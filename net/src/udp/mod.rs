use core::mem::size_of;
use core::net::IpAddr;

use collections::bytes::{Cursor, Slice};
use runtime::Core;
use utils::bytes::{self, Cast};
use utils::endian::u16be;
use utils::error::*;

use crate::icmp::IcmpErrorTy;
use crate::ip::Protocol::Udp;
use crate::ip::{self, Checksum, SocketAddr, ToS};
use crate::{dns, App, Interface};

pub struct Packet {
	inner: ip::Packet,
	csum: Checksum,
}

impl Packet {
	pub fn cursor(&mut self) -> Cursor<'_> {
		// Get a cursor to the underlying buffer.
		let cur = self.inner.cursor();
		// Split off the packet header.
		let (_, cur): (&mut Header, _) = cur.split();
		// Return the cursor to the payload section of the packet.
		cur
	}
}

#[derive(Cast)]
#[repr(C)]
struct Header {
	src: u16be,
	dst: u16be,
	len: u16be,
	csum: [u8; 2],
}

impl<A: App> Interface<A> {
	pub fn recv_udp(app: &mut A, cx: &mut Core<A>, addr: IpAddr, _: ToS, buf: Slice, icmp: Option<IcmpErrorTy>) {
		let this = app.net();

		let Ok(len): Result<u32, _> = buf.len().try_into() else {
			log::warn!("UDP packet too big ({} bytes)", buf.len());
			return;
		};

		if buf.len() < size_of::<Header>() {
			log::warn!("UDP header too short (got {} bytes)", buf.len());
			return;
		}

		if icmp.is_none() && (addr.is_ipv6() || bytes::cast::<Header, _>(&*buf).csum != [0, 0]) {
			let mut csum = this.ip.pseudo_checksum(Udp, addr);

			csum.push(&len.to_be_bytes());
			csum.push(&buf);

			let v = csum.end();

			if v != [0, 0] {
				log::warn!("Packet with invalid UDP checksum");
				return;
			}
		}

		let header: &Header = buf.split();

		if icmp.is_none() && header.len.get() as u32 != len {
			log::warn!("UDP header length ({len}) does not match actual packet length ({})", len);
			return;
		}

		let (local, remote) = match icmp {
			None => (header.dst, header.src),
			Some(_) => (header.src, header.dst),
		};

		let rem = SocketAddr { addr, port: remote.get() };

		match local.get() {
			n if n == A::DNS_PORT => dns::Resolver::process(app, cx, rem, buf),
			n => app.on_udp(cx, n, rem, buf, icmp),
		}
	}

	pub fn buf_udp(&mut self, src: u16, SocketAddr { addr, port }: SocketAddr) -> Packet {
		let tos = ToS::new(ip::ECN::NotECT, ip::DiffServ::Default);

		let csum = self.ip.pseudo_checksum(Udp, addr);

		let mut buf = self.buf(Udp, addr, tos);
		let cur = buf.cursor();

		let header: &mut Header = cur.cast();

		header.src = src.into();
		header.dst = port.into();
		header.csum = [0, 0];

		Packet { inner: buf, csum }
	}

	pub fn write_udp(&mut self, cx: &mut Core<A>, mut buf: Packet, df: bool) {
		let mut cur = buf.inner.cursor();

		let pivot = cur.pivot();

		let len: u16 = pivot.try_into().unwrap_or(0);
		bytes::cast_mut::<Header, _>(&mut *cur).len = len.into();

		buf.csum.push(&len.to_be_bytes());
		buf.csum.push(&cur[..pivot]);

		bytes::cast_mut::<Header, _>(&mut *cur).csum = buf.csum.end();

		self.write(cx, buf.inner, df);
	}
}
