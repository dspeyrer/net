use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr};

use bilge::prelude::*;
use collections::bytes::{Cursor, Slice};
use log::warn;
use utils::bytes::{self, Cast};
use utils::endian::{b, u16be};
use utils::error::*;

use crate::ip::Version::V4;
use crate::ip::{Checksum, Protocol, ToS};

fn pseudo_csum(header: &Header) -> Checksum {
	let mut csum = Checksum::with(bytes::cast(&header.src));
	csum.push_chunk(bytes::cast(&header.dst));
	csum.push_chunk(&[0, 0, 0, header.proto.0]);
	csum
}

#[derive(Clone, Copy)]
pub struct Interface {
	addr: Ipv4Addr,
}

impl super::Interface {
	pub fn test() {
		let meta: u8 = Meta::new(u4::new(5), V4).into();
		println!("{:08b}", meta.value());
	}
}

impl Interface {
	pub fn recv(&self, interface: &crate::Interface, buf: Slice) -> Result {
		let header: &Header = buf.split();

		if header.dst != self.addr {
			warn!("Found IP packet with destination {}, expected {}", header.dst, self.addr);
			return Err(());
		}

		let frag = header.frg.get();

		if frag.more() || frag.ofst().value() != 0 {
			log::info!("Recieved fragmented packet, discarding.");
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

		buf.truncate(header.len.get() as usize - header_len);

		interface.handle(header.proto.get(), IpAddr::V4(header.src), || pseudo_csum(header), &buf)?(buf);

		Ok(())
	}

	pub fn write(&self, buf: Cursor, protocol: Protocol, addr: Ipv4Addr, tos: ToS, f: impl FnOnce(Cursor, Checksum)) {
		let (header, mut buf): (&mut Header, _) = buf.split();

		header.ver = Meta::new(u4::new(5), V4);
		header.tos = tos;

		header.ttl = 64;
		header.proto = protocol.into();

		header.src = self.addr;
		header.dst = addr;

		f(buf.fork(), pseudo_csum(header));

		header.len = ((size_of::<Header>() + buf.pivot()) as u16).into();
		header.frg = Fragment::new(u13::new(0), false, true, 0).into();

		header.csm = Checksum::of(bytes::as_slice(header)).end();
	}
}

impl From<Ipv4Addr> for Interface {
	fn from(addr: Ipv4Addr) -> Self {
		Self { addr }
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
struct Header {
	ver: Meta,
	tos: ToS,
	len: u16be,
	frg: b<Fragment>,
	ttl: u8,
	proto: b<Protocol>,
	csm: [u8; 2],
	src: Ipv4Addr,
	dst: Ipv4Addr,
}
