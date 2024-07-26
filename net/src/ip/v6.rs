use core::net::Ipv6Addr;

use bilge::prelude::*;
use collections::bytes::Cursor;
use utils::bytes::Cast;
use utils::endian::{b, u16be};

use super::Protocol;

pub struct Interface {
	addr: Ipv6Addr,
}

impl From<Ipv6Addr> for Interface {
	fn from(addr: Ipv6Addr) -> Self {
		Self { addr }
	}
}

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
	ver: b<Meta>,
	len: u16be,
	nxt: b<Protocol>,
	ttl: u8,
	src: Ipv6Addr,
	dst: Ipv6Addr,
}

struct Packet<'a> {
	header: &'a mut Header,
	buf: Cursor<'a>,
}

impl<'a> From<Cursor<'a>> for Packet<'a> {
	fn from(buf: Cursor<'a>) -> Self {
		let (header, buf) = buf.split();
		Self { header, buf }
	}
}
