use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr};

use bilge::prelude::*;
use collections::bytes::{Cursor, Slice};
use log::warn;
use utils::bytes::{self, Cast};
use utils::endian::{u16be, BigEndian};
use utils::error::*;

use super::{fragment, Interface};
use crate::ip::Version::V4;
use crate::ip::{Checksum, Protocol, ToS};

impl Interface {
	pub fn recv_v4(self, interface: &mut crate::Interface, buf: Slice) -> Result {
		let header: &Header = buf.split();

		if header.dst != self.v4 {
			warn!("Found IP packet with destination {}, expected {}", header.dst, self.v4);
			return Err(());
		}

		let header_len = 4 * header.ver.ihl().value() as usize;

		let options: &[u8] = buf.split_n(header_len - size_of::<Header>());

		// TODO: Process options

		if header.csm != [0, 0] {
			let mut csum = Checksum::of(bytes::as_slice(header));
			csum.push(options);

			let o = csum.end();

			if o != [0, 0] {
				warn!("Packet has invalid checksum.");
				return Err(());
			}
		}

		let payload_len = header.len.get() as usize - header_len;

		if buf.len() < payload_len {
			log::warn!("IP packet smaller than specified length field.");
			return Err(());
		}

		buf.truncate(payload_len);

		let frag = header.frg.get();

		let start = frag.ofst().value();
		let more = frag.more();

		let proto = header.proto.get();
		let src = IpAddr::V4(header.src);

		if start == 0 && !more {
			// Process the packet regularly if it is not fragmented
			interface.handle(proto, src, buf)
		} else {
			// Construct a fragmentation key and fragment.
			let key = fragment::Key { ident: frag.idnt() as u32, proto, addr: src };
			let fragment = fragment::Fragment { start, more, buf };

			// Process them with the fragmentation handler
			interface.handle_fragment(key, fragment)
		}
	}

	pub fn write_v4(&self, buf: Cursor, protocol: Protocol, addr: Ipv4Addr, tos: ToS, f: impl FnOnce(Cursor)) {
		let (header, mut buf): (&mut Header, _) = buf.split();

		header.ver = Meta::new(u4::new(5), V4);
		header.tos = tos;

		header.ttl = 64;
		header.proto = protocol.into();

		header.src = self.v4;
		header.dst = addr;

		f(buf.fork());

		header.len = ((size_of::<Header>() + buf.pivot()) as u16).into();
		header.frg = Fragment::new(u13::new(0), false, true, 0).into();

		header.csm = Checksum::of(bytes::as_slice(header)).end();
	}
}

#[bitsize(8)]
#[derive(FromBits, Cast)]
#[repr(C)]
struct Meta {
	ihl: u4,
	ver: super::Version,
}

#[bitsize(32)]
#[derive(FromBits)]
struct Fragment {
	ofst: u13,
	more: bool,
	dont: bool,
	reserved: bool,
	idnt: u16,
}

#[derive(Cast)]
#[repr(C)]
pub(super) struct Header {
	ver: Meta,
	tos: ToS,
	len: u16be,
	frg: BigEndian<Fragment>,
	ttl: u8,
	proto: BigEndian<Protocol>,
	csm: [u8; 2],
	src: Ipv4Addr,
	dst: Ipv4Addr,
}
