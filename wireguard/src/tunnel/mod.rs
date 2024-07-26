pub mod state;

mod window;
use core::mem;
use std::net::UdpSocket;

use log::{info, warn};
use runtime::Io;
use stakker::CX;
use utils::error::*;
mod timers;
use collections::bytes::{Cursor, Slice};
use collections::map::{Index, Key, Map};
use state::*;
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret as SecretKey};

use self::timers::Timers;
use crate::mac::{CookieMac, Mac1};
use crate::noise::{Hash, InitiatorHandshake, ResponderHandshake, A32};
use crate::packet::{Cookie, Data, Initiation, Response, Tag, Timestamp};
use crate::Wireguard;

pub struct Interface {
	pub mac: CookieMac,
	pub key: SecretKey,
	pub pubkey: PublicKey,
	pub hash: Hash,
	pub link: Io<UdpSocket>,
}

impl Interface {
	pub fn new(s_key: [u8; 32], link: Io<UdpSocket>) -> Self {
		let key = SecretKey::from(s_key);
		let pubkey = PublicKey::from(&key);

		let mut hash = Hash::default();
		hash.update(pubkey.as_bytes());

		let mac = CookieMac::new(pubkey.as_bytes());

		Self { key, pubkey, hash, mac, link }
	}

	pub fn handle_initiation(&mut self, cx: CX![Wireguard], peers: &mut Map<Peer, 1>, msg: &mut Initiation) -> Result {
		info!("Recieved initiation packet");

		let idx = msg.idx;

		let (state, peer) = ResponderHandshake::consume_initiation(peers, self, msg)?;
		peer.create_response(cx, self, idx, state)
	}
}

struct SentHandshake {
	state: InitiatorHandshake,
	idx: u32,
	mac: Mac1,
}

#[derive(Default)]
struct Wheel {
	prev: Option<(u32, Simplex)>,
	pair: Option<(u32, Tunnel)>,
	next: Option<(u32, Next)>,
	sent: Option<SentHandshake>,
}

pub struct Peer {
	wheel: Wheel,
	queue: Vec<Box<dyn FnOnce(Cursor)>>,
	pub timers: Timers,
	pub hs: Noise,
}

impl Key for Peer {
	type Type = PublicKey;

	fn key(&self) -> &Self::Type {
		&self.hs.key
	}
}

impl Peer {
	pub fn init(i: &Interface, idx: Index<1>, key: PublicKey, preshared: [u8; 32]) -> Self {
		let hs = Noise::new(&i, key, preshared);

		let this = Self {
			wheel: Wheel::default(),
			timers: Timers::new(idx),
			queue: Vec::new(),
			hs,
		};

		this
	}

	pub fn write(&mut self, cx: CX![Wireguard], wg: &Interface, f: impl FnOnce(Cursor) + 'static, is_keepalive: bool) -> Result {
		let rekey = match &mut self.wheel.pair {
			Some((_, ref mut tun)) if !tun.is_send_expired(cx) => {
				let cx1 = &mut *cx;
				let rekey = wg.link.write(move |buf| tun.send(cx1, buf, f))?;
				self.timers.send_data(cx, is_keepalive);
				rekey
			}
			_ if !is_keepalive => {
				self.wheel.pair = None;
				self.queue.push(Box::new(f));
				true
			}
			_ => {
				log::error!("Failed to send keepalive packet");
				return Err(());
			}
		};

		if rekey {
			self.rekey(cx, wg)?;
		};

		Ok(())
	}

	fn rekey(&mut self, cx: CX![Wireguard], wg: &Interface) -> Result {
		if !self.timers.is_rekeying() {
			// Only send an initiation packet if there is not one queued already.
			self.create_initiation(cx, wg)
		} else {
			Ok(())
		}
	}

	pub fn create_initiation(&mut self, cx: CX![Wireguard], wg: &Interface) -> Result {
		self.wheel.sent = Some(self.hs.create_initiation(cx, wg)?);
		self.timers.send_init(cx);
		Ok(())
	}

	pub fn create_response(&mut self, cx: CX![Wireguard], wg: &Interface, idx: u32, state: ResponderHandshake) -> Result {
		self.wheel.next = Some((idx, self.hs.create_response(cx, wg, idx, state)?));
		self.timers.send_resp(cx);
		Ok(())
	}

	pub fn handle_response(&mut self, cx: CX![Wireguard], i: &Interface, msg: &mut Response) -> Result {
		info!("Recieved response packet for connection 0x{:x}", msg.rcv_idx);

		let sent = self
			.wheel
			.sent
			.as_ref()
			.filter(|s| s.idx == msg.rcv_idx)
			.ok_or_else(|| warn!("No matching incomplete state for response"))?;

		self.wheel.prev = self.wheel.pair.take().map(|(id, p)| (id, p.recv));
		self.wheel.pair = Some((sent.idx, self.hs.handle_response(cx, &sent.state, i, msg)?));
		self.wheel.sent = None;

		self.timers.recv_resp(cx);

		for f in mem::take(&mut self.queue) {
			self.write(cx, i, f, false)?;
		}

		Ok(())
	}

	pub fn handle_data<'a>(&mut self, cx: CX![Wireguard], wg: &Interface, buf: &mut Slice) -> Result {
		let msg: &Data = buf.split();

		match &mut self.wheel {
			&mut Wheel { pair: Some((i, ref mut k)), .. } if msg.idx == i => {
				let rekey = k.open(cx, msg.ctr, buf)?;

				if rekey {
					self.rekey(cx, wg)?
				};
				// Only update the timers if the data packet was recieved on the main connection.
				self.timers.recv_data(cx, buf.len() == 0);
			}
			// Ignore rekeying requests on old connections.
			&mut Wheel { prev: Some((i, ref mut k)), .. } if msg.idx == i => k.open(cx, msg.ctr, buf)?,
			&mut Wheel { next: Some((i, ref mut k)), .. } if msg.idx == i => {
				info!("Recieved data on `next` connection 0x{:x}, rotating", i);

				let pair = k.recv(msg.ctr, buf)?;

				self.wheel.prev = self.wheel.pair.take().map(|(id, p)| (id, p.recv));
				self.wheel.pair = Some((i, pair));

				for f in mem::take(&mut self.queue) {
					self.write(cx, wg, f, false)?;
				}
			}
			_ => return Err(warn!("No applicable recieve key found for Data packet")),
		};

		Ok(())
	}

	pub fn handle_cookie(&mut self, cx: CX![Wireguard], msg: &mut Cookie) -> Result {
		let mac = match &self.wheel {
			Wheel { next: Some((_, Next { sidx: idx, mac, .. })), .. } | Wheel { sent: Some(SentHandshake { idx, mac, .. }), .. }
				if msg.idx == *idx =>
			{
				mac
			}
			_ => return Err(warn!("No sent mac found for cookie message")),
		};

		self.hs.mac.handle_cookie(cx, msg, mac)
	}
}

pub struct Noise {
	mac: CookieMac,
	timestamp: Option<Tai64N>,
	idx_cur: u32,
	pub s_agree: [u8; 32],
	pub hash: Hash,
	pub preshared: A32,
	pub key: PublicKey,
}

impl Noise {
	fn new(i: &Interface, key: PublicKey, preshared: [u8; 32]) -> Self {
		let mut hash = Hash::default();
		hash.update(&key);

		Self {
			s_agree: i.key.diffie_hellman(&key).to_bytes(),
			key: PublicKey::from(key),
			idx_cur: rand::random(),
			preshared: preshared.into(),
			hash,
			timestamp: None,
			mac: CookieMac::new(key.as_bytes()),
		}
	}

	pub fn update_timestamp(&mut self, ts: Timestamp) -> Result {
		let ts = ts.try_into().map_err(|_| warn!("Invalid timestamp on message"))?;

		if self.timestamp.is_some_and(|t| ts <= t) {
			warn!("Timestamp on initiation is expired");
			return Err(());
		}

		self.timestamp = Some(ts);

		Ok(())
	}

	fn create_initiation(&mut self, cx: CX![Wireguard], wg: &Interface) -> Result<SentHandshake> {
		wg.link.write(|mut buf| {
			let msg: &mut Initiation = buf.fork().cast();
			msg.tag = Tag::INITIATION;

			let idx = self.new_idx();
			msg.idx = idx;

			let state = InitiatorHandshake::create_initiation(cx, &wg, self, msg);
			let mac = self.mac.write(cx, buf);

			log::info!("Sent initiation packet 0x{:x}", idx);

			SentHandshake { state, idx, mac }
		})
	}

	fn create_response(&mut self, cx: CX![Wireguard], wg: &Interface, rcv_idx: u32, state: ResponderHandshake) -> Result<Next> {
		wg.link.write(|mut buf| {
			let res: &mut Response = buf.fork().cast();
			res.tag = Tag::RESPONSE;

			let idx = self.new_idx();
			res.idx = idx;

			res.rcv_idx = rcv_idx;

			log::info!("Sent response packet 0x{:x}", idx);

			let chain = state.create_response(self, res);
			let mac = self.mac.write(cx, buf);

			Next::new(cx, chain, idx, mac)
		})
	}

	fn handle_response(&self, cx: CX![Wireguard], state: &InitiatorHandshake, i: &Interface, msg: &mut Response) -> Result<Tunnel> {
		let chain = state
			.clone()
			.consume_response(i, self, msg)
			.map_err(|_| warn!("Could not consume Response"))?;
		Ok(Tunnel::new(cx, chain, msg.idx))
	}

	fn new_idx(&mut self) -> u32 {
		let idx = self.idx_cur;
		self.idx_cur += 1;
		idx
	}
}
