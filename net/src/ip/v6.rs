use core::mem::size_of;
use core::net::{IpAddr, Ipv6Addr};

use bilge::prelude::*;
use collections::bytes::{Cursor, Slice};
use log::warn;
use utils::bytes::Cast;
use utils::endian::{u16be, BigEndian};
use utils::error::*;

use super::{Interface, Protocol};
use crate::ip::ToS;
use crate::ip::Version::V6;

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

impl Interface {
	pub fn recv_v6(self, interface: &mut crate::Interface, buf: Slice) -> Result {
		let header: &Header = buf.split();

		if header.dst != self.v6 {
			warn!("Found IP packet with destination {}, expected {}", header.dst, self.v6);
			return Err(());
		}

		let payload_len = header.len.get() as usize - size_of::<Header>();

		if buf.len() < payload_len {
			log::warn!("IP packet smaller than specified length field.");
			return Err(());
		}

		buf.truncate(payload_len);

		let proto = header.nxt.get();
		let src = IpAddr::V6(header.src);

		interface.handle(proto, src, buf)
	}

	pub fn write_v6(&self, buf: Cursor, protocol: Protocol, addr: Ipv6Addr, tos: ToS, f: impl FnOnce(Cursor)) {
		let (header, mut buf): (&mut Header, _) = buf.split();

		header.ver = Meta::new(u20::MIN, tos, V6).into();

		header.nxt = protocol.into();
		header.ttl = 64;

		header.src = self.v6;
		header.dst = addr;

		f(buf.fork());

		header.len = ((size_of::<Header>() + buf.pivot()) as u16).into();
	}
}
