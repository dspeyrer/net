use core::mem::size_of;
use core::net::{IpAddr, Ipv6Addr};

use bilge::prelude::*;
use collections::bytes::{Cursor, Slice};
use log::warn;
use runtime::Core;
use utils::bytes::Cast;
use utils::endian::{u16be, BigEndian};

use super::{Interface, Protocol};
use crate::ip::ToS;
use crate::ip::Version::V6;
use crate::App;

#[bitsize(32)]
#[derive(FromBits)]
struct Meta {
	flow: u20,
	tos: super::ToS,
	ver: super::Version,
}

#[derive(Cast)]
#[repr(C)]
struct Header {
	ver: BigEndian<Meta>,
	len: u16be,
	nxt: BigEndian<Protocol>,
	ttl: u8,
	src: Ipv6Addr,
	dst: Ipv6Addr,
}

impl<A: App> crate::Interface<A> {
	pub fn recv_v6(app: &mut A, cx: &mut Core<A>, buf: Slice) {
		if buf.len() < size_of::<Header>() {
			log::warn!("recieved IP packet with insufficient length");
			return;
		}

		let header: &Header = buf.split();

		let ver = header.ver.get();

		let ip = app.net().ip.v6;

		if header.dst != ip {
			warn!("Found IP packet with destination {}, expected {}", header.dst, ip);
			return;
		}

		let payload_len = header.len.get() as usize - size_of::<Header>();

		if buf.len() < payload_len {
			log::warn!("IP packet smaller than specified length field.");
			return;
		}

		buf.truncate(payload_len);

		let proto = header.nxt.get();
		let src = IpAddr::V6(header.src);

		Self::handle(app, cx, proto, src, ver.tos(), buf, None)
	}
}

impl Interface {
	pub fn init_v6(&self, cur: Cursor, protocol: Protocol, addr: Ipv6Addr, tos: ToS) {
		let header: &mut Header = cur.cast();

		header.ver = Meta::new(u20::MIN, tos, V6).into();

		header.nxt = protocol.into();
		header.ttl = 64;

		header.src = self.v6;
		header.dst = addr;
	}

	pub fn finalise_v6(cur: Cursor, _df: bool) {
		let hlen = cur.pivot();
		let header: &mut Header = cur.cast();
		header.len = (hlen as u16).into();
	}
}
