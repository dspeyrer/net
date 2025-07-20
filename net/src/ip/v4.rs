use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr};

use bilge::prelude::*;
use collections::bytes::{Cursor, Slice};
use log::warn;
use runtime::Core;
use utils::bytes::{self, Cast};
use utils::endian::{u16be, BigEndian};

use super::{fragment, Interface};
use crate::icmp::IcmpErrorTy;
use crate::ip::Version::V4;
use crate::ip::{Checksum, Protocol, ToS};
use crate::App;

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

impl<A: App> crate::Interface<A> {
	pub fn recv_v4(app: &mut A, cx: &mut Core<A>, buf: Slice, icmp: Option<IcmpErrorTy>) {
		if buf.len() < size_of::<Header>() {
			log::warn!("recieved IP packet with insufficient length");
			return;
		}

		let header: &Header = buf.split();

		let ip = app.net().ip.v4;

		let (local, remote) = match icmp {
			None => (header.dst, header.src),
			Some(_) => (header.src, header.dst),
		};

		if local != ip {
			warn!("Found IP packet with local target {}, expected {}", local, ip);
			return;
		}

		let header_len = 4 * header.ver.ihl().value() as usize;

		let options: &[u8] = buf.split_n(header_len - size_of::<Header>());

		// TODO: Process options

		if icmp.is_none() {
			if header.csm != [0, 0] {
				let mut csum = Checksum::of(bytes::as_slice(header));
				csum.push(options);

				let o = csum.end();

				if o != [0, 0] {
					warn!("Packet has invalid checksum.");
					return;
				}
			}

			let payload_len = header.len.get() as usize - header_len;

			if buf.len() < payload_len {
				log::warn!("IP packet smaller than specified length field.");
				return;
			}

			buf.truncate(payload_len);
		}

		let frag = header.frg.get();

		let start = frag.ofst().value() * 8;
		let more = frag.more();

		let proto = header.proto.get();
		let rem = IpAddr::V4(remote);

		if (start == 0 && !more) || icmp.is_some() {
			// Process the packet regularly if it is not fragmented
			Self::handle(app, cx, proto, rem, header.tos, buf, icmp);
		} else {
			let ds = header.tos.ds();
			let ecn = header.tos.ecn();

			// Construct a fragmentation key and fragment.
			let key = fragment::Key { ident: frag.idnt() as u32, proto, addr: rem, ds };

			let fragment = fragment::Fragment { start, more, buf };

			// Process them with the fragmentation handler
			Self::handle_fragment(app, cx, key, fragment, ecn);
		}
	}
}

impl Interface {
	pub fn init_v4(&self, cur: Cursor, protocol: Protocol, addr: Ipv4Addr, tos: ToS) {
		let header: &mut Header = cur.cast();

		header.ver = Meta::new(u4::new(5), V4);
		header.tos = tos;

		header.ttl = 64;
		header.proto = protocol.into();

		header.src = self.v4;
		header.dst = addr;
	}

	pub fn finalise_v4(mut cur: Cursor, df: bool) {
		let hlen = cur.pivot();

		let header: &mut Header = bytes::cast_mut(&mut *cur);

		header.len = (hlen as u16).into();
		header.frg = Fragment::new(u13::new(0), false, df, 0).into();

		header.csm = Checksum::of(bytes::as_slice(header)).end();
	}
}
