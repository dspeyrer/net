#![feature(try_blocks, trivial_bounds)]

mod mac;
mod noise;
mod packet;
mod tunnel;

use core::mem::size_of;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::net::UdpSocket;

use chacha20poly1305::Tag;
use collections::bytes::{Buf, Cursor, Slice};
use collections::map::{Index, Map};
use log::{error, info, warn};
use runtime::{Core, Io};
use tunnel::{Interface, Peer};
use utils::bytes;
use utils::error::*;
use x25519_dalek::PublicKey;

use crate::packet::{Cookie, Data, Initiation, Response, MAC_LEN};

pub trait App: Sized {
	fn wireguard(&mut self) -> &mut Wireguard;
	fn on_packet(&mut self, cx: &mut Core<Self>, buf: Slice);
}

/// A buffer for a WireGuard packet.
pub struct Packet {
	/// The underlying I/O packet.
	inner: Buf,
}

impl Packet {
	pub fn cursor(&mut self) -> Cursor {
		// Get a cursor to the underlying buffer.
		let cur = self.inner.cursor();
		// Split off the data header.
		let (_, cur): (&mut Data, _) = cur.split();

		// Get the capacity of the packet payload.
		let mut len = cur.len();
		// Remove unusable capacity due to tag alignment.
		len -= len % size_of::<Tag>();
		// Remove the capacity of the tag.
		len -= size_of::<Tag>();

		// Return a cursor limited to the data section of the packet.
		cur.lim(len)
	}
}

macro_rules! validate_packet_size {
	($buf:ident, $struct:ident $( $rest:tt )*) => {{
		let expected = size_of::<$struct>() $( $rest )*;
		let got = $buf.len();

		if expected != got {
			warn!(concat!("Packet size is incorrect for message of type ", stringify!($struct), ": expected {} bytes, got {} bytes"), expected, got);
			return Err(());
		}
	}};
}

pub struct Wireguard {
	interface: Interface,
	peers: Map<Peer, 1>,
}

impl Wireguard {
	pub fn init<A: App>(cx: &mut Core<A>, addr: SocketAddr, s_priv: [u8; 32], p_pub: [u8; 32], q_pre: [u8; 32]) -> Self {
		let socket: std::io::Result<UdpSocket> = try {
			let socket = UdpSocket::bind::<SocketAddr>(match addr {
				SocketAddr::V4(_) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
				SocketAddr::V6(_) => SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into(),
			})?;

			socket.set_nonblocking(true)?;
			socket.connect(addr)?;

			socket
		};

		let socket = socket.expect("Failed to create socket");

		let link = Io::new(cx, socket, Box::new(move |app, cx, buf| Self::read(app, cx, buf.unwrap())));

		let mut peers = Map::<_, 1>::default();

		let interface = Interface::new(s_priv, link);

		let p_pub = PublicKey::from(p_pub);

		let slot = peers.insert_unique(&p_pub);
		let peer = Peer::init(&interface, slot.index(), p_pub, q_pre);
		slot.insert(peer);

		Self { peers, interface }
	}

	/// Gets a packet buffer for writing.
	pub fn buf(&self) -> Packet {
		Packet { inner: self.interface.link.buf() }
	}

	pub fn write<A: App>(&mut self, cx: &mut Core<A>, buf: Packet) {
		if self.peers[Index::new(0)].write(cx, &self.interface, buf, false).is_err() {
			error!("Failed to write packet");
		}
	}

	fn read<A: App>(app: &mut A, cx: &mut Core<A>, buf: Slice) {
		let _ = match *bytes::cast(&*buf) {
			packet::Tag::INITIATION => app.wireguard().initiation(cx, buf),
			packet::Tag::RESPONSE => app.wireguard().response(cx, buf),
			packet::Tag::COOKIE => app.wireguard().cookie(cx, buf),
			packet::Tag::DATA => Self::data(app, cx, buf),
			_ => return warn!("Recieved packet with invalid message tag"),
		};
	}

	fn initiation<A: App>(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		validate_packet_size!(buf, Initiation + MAC_LEN);

		self.interface.mac.check(cx, &buf)?;
		self.interface.handle_initiation(cx, &mut self.peers, bytes::cast_mut(&mut *buf))
	}

	fn response<A: App>(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		validate_packet_size!(buf, Response + MAC_LEN);

		self.interface.mac.check(cx, &buf)?;
		self.peers[Index::new(0)].handle_response(cx, &self.interface, bytes::cast_mut(&mut *buf))
	}

	fn cookie<A: App>(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		validate_packet_size!(buf, Cookie);

		self.peers[Index::new(0)].handle_cookie(cx, bytes::cast_mut(&mut *buf))
	}

	fn data<A: App>(app: &mut A, cx: &mut Core<A>, mut buf: Slice) -> Result {
		let expected = size_of::<Data>() + size_of::<Tag>();

		let n = buf.len();

		if n < expected {
			warn!("Packet size is incorrect for message of type Data: expected a length greater than {expected} bytes, got {n} bytes");
			return Err(());
		}

		let this = app.wireguard();

		this.peers[Index::new(0)].handle_data(cx, &this.interface, &mut buf)?;

		if buf.is_empty() {
			log::info!("Recieved keepalive");
		} else {
			app.on_packet(cx, buf);
		}

		Ok(())
	}

	fn send_keepalive<A: App>(&mut self, cx: &mut Core<A>, idx: Index<1>) {
		info!("Sending keepalive packet");

		let buf = self.buf();

		if let Err(()) = &self.peers[idx].write(cx, &self.interface, buf, true) {
			error!("Encountered error sending keepalive");
		}
	}

	fn rekey<A: App>(&mut self, cx: &mut Core<A>, idx: Index<1>) {
		info!("Rekeying");

		let peer = &mut self.peers[idx];

		if peer.timers.rekey_elapsed(cx) {
			error!("REKEY_ATTEMPT_TIME reached");
		}

		if let Err(e) = peer.create_initiation(cx, &self.interface) {
			error!("Encountered error rekeying: {:#?}", e);
		}
	}
}
