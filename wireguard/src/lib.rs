#![feature(try_blocks, trivial_bounds)]

mod mac;
mod noise;
mod packet;
mod tunnel;

use core::mem::size_of;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::net::UdpSocket;

use chacha20poly1305::Tag;
use collections::bytes::{Cursor, Slice};
use collections::map::{Index, Map};
use log::{error, info, warn};
use runtime::Io;
use stakker::{fwd, fwd_to, Fwd, CX};
use tunnel::{Interface, Peer};
use utils::bytes;
use utils::error::*;
use x25519_dalek::PublicKey;

use crate::packet::{Cookie, Data, Initiation, Response, MAC_LEN};

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
	fwd: Fwd<Slice>,
}

impl Wireguard {
	pub fn init(cx: CX![], addr: SocketAddr, s_priv: [u8; 32], p_pub: [u8; 32], q_pre: [u8; 32], fwd: Fwd<Slice>) -> Option<Self> {
		let socket: std::io::Result<UdpSocket> = try {
			let socket = UdpSocket::bind::<SocketAddr>(match addr {
				SocketAddr::V4(_) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
				SocketAddr::V6(_) => SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into(),
			})?;

			socket.set_nonblocking(true)?;
			socket.connect(addr)?;

			socket
		};

		let socket = socket.ok_or(|err| error!("Failed to create socket: {err}"))?;

		let read_fwd = fwd_to!([cx], read() as (Slice));
		let link = Io::new(socket, read_fwd);

		let mut peers = Map::<_, 1>::default();

		let interface = Interface::new(s_priv, link);

		let p_pub = PublicKey::from(p_pub);

		let slot = peers.insert_unique(&p_pub);
		let peer = Peer::init(&interface, slot.index(), p_pub, q_pre);
		slot.insert(peer);

		Some(Self { peers, interface, fwd })
	}
}

impl Wireguard {
	pub fn write(&mut self, cx: CX![], f: impl FnOnce(Cursor) + 'static) {
		if self.peers[Index::new(0)].write(cx, &self.interface, f, false).is_err() {
			error!("Failed to write packet");
		}
	}

	fn read(&mut self, cx: CX![], buf: Slice) {
		let _ = match *bytes::cast(&*buf) {
			packet::Tag::INITIATION => self.initiation(cx, buf),
			packet::Tag::RESPONSE => self.response(cx, buf),
			packet::Tag::COOKIE => self.cookie(cx, buf),
			packet::Tag::DATA => self.data(cx, buf),
			_ => return warn!("Recieved packet with invalid message tag"),
		};
	}

	fn initiation(&mut self, cx: CX![], mut buf: Slice) -> Result {
		validate_packet_size!(buf, Initiation + MAC_LEN);

		self.interface.mac.check(cx, &buf)?;
		self.interface.handle_initiation(cx, &mut self.peers, bytes::cast_mut(&mut *buf))
	}

	fn response(&mut self, cx: CX![], mut buf: Slice) -> Result {
		validate_packet_size!(buf, Response + MAC_LEN);

		self.interface.mac.check(cx, &buf)?;
		self.peers[Index::new(0)].handle_response(cx, &self.interface, bytes::cast_mut(&mut *buf))
	}

	fn cookie(&mut self, cx: CX![], mut buf: Slice) -> Result {
		validate_packet_size!(buf, Cookie);

		self.peers[Index::new(0)].handle_cookie(cx, bytes::cast_mut(&mut *buf))
	}

	fn data(&mut self, cx: CX![], mut buf: Slice) -> Result {
		let expected = size_of::<Data>() + size_of::<Tag>();

		let n = buf.len();

		if n < expected {
			warn!("Packet size is incorrect for message of type Data: expected a length greater than {expected} bytes, got {n} bytes");
			return Err(());
		}

		self.peers[Index::new(0)].handle_data(cx, &self.interface, &mut buf)?;

		if buf.is_empty() {
			log::info!("Recieved keepalive");
		} else {
			fwd!([self.fwd], buf);
		}

		Ok(())
	}

	fn send_keepalive(&mut self, cx: CX![], idx: Index<1>) {
		info!("Sending keepalive packet");

		if let Err(()) = &self.peers[idx].write(cx, &self.interface, |_| (), true) {
			error!("Encountered error sending keepalive");
		}
	}

	fn rekey(&mut self, cx: CX![], idx: Index<1>) {
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
