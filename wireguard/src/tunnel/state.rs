use std::time::{Duration, Instant};

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305 as Aead, KeyInit, Nonce, Tag};
use collections::bytes::{Cursor, Slice};
use log::warn;
use stakker::CX;
use utils::bytes;
use utils::error::*;

use super::timers::{KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT};
use super::window::Window;
use crate::mac::Mac1;
use crate::noise::Chain;
use crate::packet::{self, Data};
use crate::Wireguard;

pub const REKEY_AFTER_MESSAGES: u64 = 2u64.pow(60);
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 2u64.pow(13);

fn open(key: &Aead, ctr: u64, buf: &mut Slice) -> Result {
	let tag = *buf.rsplit();

	key.decrypt_in_place_detached(&nonce(ctr), &[], buf, &tag)
		.map_err(|_| warn!("Failed to decrypt data payload"))?;
	Ok(())
}

fn nonce(n: u64) -> Nonce {
	let mut nonce = Nonce::default();
	*bytes::cast_mut(&mut nonce[4..]) = n.to_le_bytes();
	nonce
}

#[derive(PartialEq, Eq)]
pub enum Role {
	Initiator,
	Responder,
}

pub struct Simplex {
	key: Aead,
	win: Window,
	time: Instant,
}

impl Simplex {
	fn initiator(cx: CX![Wireguard], key: Aead) -> Self {
		Self { key, win: Window::empty(), time: cx.now() }
	}

	fn responder(key: Aead, idx: u64, time: Instant) -> Self {
		Self { key, win: Window::new(idx), time }
	}

	fn open_checked(&mut self, cx: CX![Wireguard], ctr: u64, buf: &mut Slice) -> Result<Duration> {
		let elapsed = cx.now() - self.time;

		if elapsed >= REJECT_AFTER_TIME || ctr >= REJECT_AFTER_MESSAGES {
			warn!("Opening key for message has expired (elapsed: {:?}, ctr: {})", elapsed, ctr);
			return Err(());
		}

		self.win.guard(ctr, || open(&self.key, ctr, buf))?;

		Ok(elapsed)
	}

	pub fn open(&mut self, cx: CX![Wireguard], ctr: u64, buf: &mut Slice) -> Result {
		self.open_checked(cx, ctr, buf)?;
		Ok(())
	}
}

pub struct Tunnel {
	pub recv: Simplex,
	role: Role,

	send: Aead,
	sctr: u64,
	sidx: u32,
}

impl Tunnel {
	pub fn new(cx: CX![Wireguard], chain: Chain, sidx: u32) -> Self {
		let (send, recv) = chain.consume();

		Self {
			recv: Simplex::initiator(cx, Aead::new(&recv)),
			role: Role::Initiator,

			send: Aead::new(&send),
			sctr: 0,
			sidx,
		}
	}

	/// Returns whether a rekey is needed.
	pub fn open(&mut self, cx: CX![Wireguard], ctr: u64, buf: &mut Slice) -> Result<bool> {
		let elapsed = self.recv.open_checked(cx, ctr, buf)?;
		let rekey = self.role == Role::Initiator && elapsed >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
		Ok(rekey)
	}

	pub fn is_send_expired(&self, cx: CX![Wireguard]) -> bool {
		cx.now().duration_since(self.recv.time) >= REJECT_AFTER_TIME || self.sctr + 1 >= REJECT_AFTER_MESSAGES
	}

	/// Returns whether a rekey is needed. Assumes is_send_expired has been verified to be false.
	pub fn send(&mut self, cx: CX![Wireguard], buf: Cursor, f: impl FnOnce(Cursor)) -> bool {
		let elapsed = cx.now() - self.recv.time;

		let ctr = self.sctr;
		self.sctr += 1;

		let rekey = (self.role == Role::Initiator && elapsed >= REKEY_AFTER_TIME) || ctr >= REKEY_AFTER_MESSAGES;

		let mut buf = buf.push(&Data { tag: packet::Tag::DATA, idx: self.sidx, ctr });

		f(buf.rlim(16));
		buf.pad_to(16);

		let (mut data, tag): (_, &mut Tag) = buf.rsplit();

		*tag = self
			.send
			.encrypt_in_place_detached(&nonce(ctr), &[], &mut data)
			.expect("Encrypting should not fail");

		rekey
	}
}

pub struct Next {
	pub sidx: u32,
	pub skey: Aead,
	pub rkey: Aead,
	pub time: Instant,
	pub mac: Mac1,
}

impl Next {
	pub fn new(cx: CX![Wireguard], chain: Chain, s_idx: u32, mac: Mac1) -> Self {
		let (recv, send) = chain.consume();

		Self {
			sidx: s_idx,
			mac,
			skey: Aead::new(&send),
			rkey: Aead::new(&recv),
			time: cx.now(),
		}
	}

	pub fn recv(&self, ctr: u64, buf: &mut Slice) -> Result<Tunnel> {
		open(&self.rkey, ctr, buf)?;

		Ok(Tunnel {
			recv: Simplex::responder(self.rkey.clone(), ctr, self.time),
			role: Role::Responder,

			send: self.skey.clone(),
			sctr: 0,
			sidx: self.sidx,
		})
	}
}
