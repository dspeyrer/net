use core::mem::size_of;
use core::net::IpAddr;

use collections::bytes::{Cursor, Slice};
use log::warn;
use runtime::Core;
use utils::bytes::{self, Cast};
use utils::endian::u16be;
use utils::error::*;

use crate::ip::Protocol::Udp;
use crate::ip::{self, SocketAddr, ToS};
use crate::{dns, App, Interface};

#[derive(Cast)]
#[repr(C)]
struct Header {
	src: u16be,
	dst: u16be,
	len: u16be,
	csum: [u8; 2],
}

impl<A: App> Interface<A> {
	pub fn recv_udp(app: &mut A, cx: &mut Core<A>, addr: IpAddr, _: ToS, buf: Slice) {
		let this = app.net();

		let Ok(len): Result<u32, _> = buf.len().try_into() else {
			log::warn!("UDP packet too big ({} bytes)", buf.len());
			return;
		};

		if buf.len() < size_of::<Header>() {
			log::warn!("UDP header too short (got {} bytes)", buf.len());
			return;
		}

		if addr.is_ipv6() || bytes::cast::<Header, _>(&*buf).csum != [0, 0] {
			let mut csum = this.ip.pseudo_checksum(Udp, addr);

			csum.push(&len.to_be_bytes());
			csum.push(&buf);

			let v = csum.end();

			if v != [0, 0] {
				warn!("Packet with invalid UDP checksum");
				return;
			}
		}

		let header: &Header = buf.split();

		if header.len.get() as u32 != len {
			log::warn!("UDP header length ({len}) does not match actual packet length ({})", len);
			return;
		}

		let src = SocketAddr { addr, port: header.src.get() };

		match header.dst.get() {
			n if n == A::DNS_PORT => dns::Resolver::process(app, cx, src, buf),
			n => app.on_udp(cx, n, src, buf),
		}
	}

	pub fn write_udp(&mut self, cx: &mut Core<A>, src: u16, SocketAddr { addr, port }: SocketAddr, f: impl FnOnce(Cursor)) {
		let tos = ToS::new(ip::ECN::NotECT, ip::DiffServ::Default);

		let mut csum = self.ip.pseudo_checksum(Udp, addr);

		self.write(cx, Udp, addr, tos, move |mut buf| {
			{
				let (header, buf): (&mut Header, _) = buf.fork().split();

				header.src = src.into();
				header.dst = port.into();
				header.csum = [0, 0];

				f(buf);
			}

			let pivot = buf.pivot();

			let len: u16 = pivot.try_into().unwrap_or(0);
			bytes::cast_mut::<Header, _>(&mut *buf).len = len.into();

			csum.push(&len.to_be_bytes());
			csum.push(&buf[..pivot]);

			bytes::cast_mut::<Header, _>(&mut *buf).csum = csum.end();
		});
	}
}
