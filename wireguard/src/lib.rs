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
use stakker::Core;
use tunnel::{Interface, Peer};
use utils::bytes;
use utils::error::*;
use x25519_dalek::PublicKey;

use crate::packet::{Cookie, Data, Initiation, Response, MAC_LEN};

pub trait App: Sized + runtime::App {
	fn wireguard(&mut self) -> &mut Wireguard<Self>;
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

pub struct Wireguard<A: 'static> {
	interface: Interface,
	peers: Map<Peer, 1>,
	cb: Box<dyn FnMut(Slice)>,
	io: runtime::State<A>,
}

impl<A: App> Wireguard<A> {
	pub fn init(
		mut io: runtime::State<A>,
		addr: SocketAddr,
		s_priv: [u8; 32],
		p_pub: [u8; 32],
		q_pre: [u8; 32],
		cb: Box<dyn FnMut(Slice)>,
	) -> Self {
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

		let link = Io::new(&mut io, socket, Box::new(move |app, cx, buf| app.wireguard().read(cx, buf)));

		let mut peers = Map::<_, 1>::default();

		let interface = Interface::new(s_priv, link);

		let p_pub = PublicKey::from(p_pub);

		let slot = peers.insert_unique(&p_pub);
		let peer = Peer::init(&interface, slot.index(), p_pub, q_pre);
		slot.insert(peer);

		Self { peers, interface, cb, io }
	}

	pub fn io(&mut self) -> &mut runtime::State<A> {
		&mut self.io
	}

	pub fn write(&mut self, cx: &mut Core<A>, f: impl FnOnce(Cursor) + 'static) {
		if self.peers[Index::new(0)].write(cx, &mut self.io, &self.interface, f, false).is_err() {
			error!("Failed to write packet");
		}
	}

	fn read(&mut self, cx: &mut Core<A>, buf: Slice) {
		let _ = match *bytes::cast(&*buf) {
			packet::Tag::INITIATION => self.initiation(cx, buf),
			packet::Tag::RESPONSE => self.response(cx, buf),
			packet::Tag::COOKIE => self.cookie(cx, buf),
			packet::Tag::DATA => self.data(cx, buf),
			_ => return warn!("Recieved packet with invalid message tag"),
		};
	}

	fn initiation(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		validate_packet_size!(buf, Initiation + MAC_LEN);

		self.interface.mac.check(cx, &buf)?;
		self.interface
			.handle_initiation(cx, &mut self.io, &mut self.peers, bytes::cast_mut(&mut *buf))
	}

	fn response(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		validate_packet_size!(buf, Response + MAC_LEN);

		self.interface.mac.check(cx, &buf)?;
		self.peers[Index::new(0)].handle_response(cx, &mut self.io, &self.interface, bytes::cast_mut(&mut *buf))
	}

	fn cookie(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		validate_packet_size!(buf, Cookie);

		self.peers[Index::new(0)].handle_cookie(cx, bytes::cast_mut(&mut *buf))
	}

	fn data(&mut self, cx: &mut Core<A>, mut buf: Slice) -> Result {
		let expected = size_of::<Data>() + size_of::<Tag>();

		let n = buf.len();

		if n < expected {
			warn!("Packet size is incorrect for message of type Data: expected a length greater than {expected} bytes, got {n} bytes");
			return Err(());
		}

		self.peers[Index::new(0)].handle_data(cx, &mut self.io, &self.interface, &mut buf)?;

		if buf.is_empty() {
			log::info!("Recieved keepalive");
		} else {
			(self.cb)(buf);
		}

		Ok(())
	}

	fn send_keepalive(&mut self, cx: &mut Core<A>, idx: Index<1>) {
		info!("Sending keepalive packet");

		if let Err(()) = &self.peers[idx].write(cx, &mut self.io, &self.interface, |_| (), true) {
			error!("Encountered error sending keepalive");
		}
	}

	fn rekey(&mut self, cx: &mut Core<A>, idx: Index<1>) {
		info!("Rekeying");

		let peer = &mut self.peers[idx];

		if peer.timers.rekey_elapsed(cx) {
			error!("REKEY_ATTEMPT_TIME reached");
		}

		if let Err(e) = peer.create_initiation(cx, &mut self.io, &self.interface) {
			error!("Encountered error rekeying: {:#?}", e);
		}
	}
}
