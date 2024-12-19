use core::mem::size_of;
use core::net::IpAddr;

use collections::bytes::{Cursor, Slice};
use collections::map::{self, Key, Map};
use log::{debug, info, warn};
use stakker::{Core, Deferrer};
use utils::bytes::{self, Cast};
use utils::endian::u16be;
use utils::error::*;

use crate::ip::Protocol::Udp;
use crate::ip::{self, SocketAddr, ToS};
use crate::App;

const EPHEMERAL: u16 = 49152;

#[derive(Cast)]
#[repr(C)]
struct Header {
	src: u16be,
	dst: u16be,
	len: u16be,
	csum: [u8; 2],
}

pub struct Socket<A: App + 'static> {
	port: u16,
	deferrer: Deferrer<A>,
}

impl<A: App + 'static> Socket<A> {
	pub fn bind(deferrer: Deferrer<A>, port: u16, callback: Box<dyn FnMut(SocketAddr, Slice)>) -> Self {
		deferrer.defer(move |s| {
			let this = s.app_mut().net();

			match this.udp.map.find_entry(&port) {
				map::Entry::Empty(entry) => entry.insert(Entry { port, callback }),
				// Instead of panicking, this should call an error handler.
				_ => panic!("Address already in use"),
			};
		});

		Self { port, deferrer }
	}

	pub fn bind_eph(this: &mut super::Interface<A>, cx: &mut Core<A>, callback: Box<dyn FnMut(SocketAddr, Slice)>) -> Self {
		this.udp.bind_eph(cx, callback)
	}

	pub fn write(&self, SocketAddr { addr, port }: SocketAddr, f: impl FnOnce(Cursor) + 'static) {
		let tos = ToS::new(ip::ECN::NotECT, ip::DiffServ::Default);

		let src = self.port;

		self.deferrer.defer(move |s| {
			let (this, cx) = s.split();
			let this = this.net();

			let mut csum = this.ip.pseudo_checksum(Udp, addr);

			this.write(cx, Udp, addr, tos, move |mut buf| {
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
		});
	}
}

impl<A: App + 'static> Drop for Socket<A> {
	fn drop(&mut self) {
		let port = self.port;

		self.deferrer.defer(move |s| {
			s.app_mut().net().udp.map.find_entry(&port).remove();
		});
	}
}

pub struct Connected<A: App + 'static> {
	inner: Socket<A>,
	addr: SocketAddr,
}

impl<A: App> Connected<A> {
	pub fn bind(this: &mut super::Interface<A>, cx: &mut Core<A>, addr: SocketAddr, callback: impl Fn(Slice) + 'static) -> Self {
		let callback = Box::new(move |src, buf| {
			if src == addr {
				// The packet source matches the bound address
				callback(buf);
			} else {
				info!("Recieved unexpected packet from {}", src);
			}
		});

		let inner = Socket::bind_eph(this, cx, callback);

		Connected { inner, addr }
	}

	pub fn addr(&self) -> &SocketAddr {
		&self.addr
	}

	pub fn write(&self, f: impl FnOnce(Cursor) + 'static) {
		self.inner.write(self.addr, f);
	}
}

pub(crate) struct Interface {
	/// The port number of the last created ephemeral socket
	nxt: u16,
	map: Map<Entry, 1024>,
}

impl Interface {
	pub fn bind_eph<A: App>(&mut self, cx: &mut Core<A>, callback: Box<dyn FnMut(SocketAddr, Slice)>) -> Socket<A> {
		// Note: if all ports in the ephemeral range are full, this will loop forever.
		let entry = loop {
			// Increment, wrapping to the ephemeral port starting index
			self.nxt = self.nxt.checked_add(1).unwrap_or(EPHEMERAL);

			match self.map.find_entry(&self.nxt) {
				map::Entry::Empty(entry) => break entry,
				// If the port is already taken, continue
				_ => {}
			}
		};

		entry.insert(Entry { port: self.nxt, callback });

		Socket { port: self.nxt, deferrer: cx.deferrer() }
	}

	pub fn recv<'a>(&'a mut self, interface: &ip::Interface, addr: IpAddr, buf: Slice) -> Result {
		let len: u32 = buf.len().try_into().map_err(|_| log::warn!("UDP packet too big ({} bytes)", buf.len()))?;

		if buf.len() < size_of::<Header>() {
			log::warn!("UDP header too short (got {} bytes)", buf.len());
			return Err(());
		}

		if addr.is_ipv6() || bytes::cast::<Header, _>(&*buf).csum != [0, 0] {
			let mut csum = interface.pseudo_checksum(Udp, addr);

			csum.push(&len.to_be_bytes());
			csum.push(&buf);

			let v = csum.end();

			if v != [0, 0] {
				warn!("Packet with invalid UDP checksum");
				return Err(());
			}
		}

		let header: &Header = buf.split();

		let dst = header.dst.get();

		let e = self.map.find_entry(&dst).filled().ok_or_else(|| debug!("Socket at port {dst} not found"))?.into_ref();

		if header.len.get() as u32 != len {
			log::warn!("UDP header length ({len}) does not match actual packet length ({})", len);
			return Err(());
		}

		let port = header.src.get();

		(e.callback)(SocketAddr { addr, port }, buf);

		Ok(())
	}
}

impl Default for Interface {
	fn default() -> Self {
		Self { nxt: EPHEMERAL, map: Default::default() }
	}
}

pub(crate) struct Entry {
	port: u16,
	callback: Box<dyn FnMut(SocketAddr, Slice)>,
}

impl Key for Entry {
	type Type = u16;

	fn key(&self) -> &Self::Type {
		&self.port
	}
}
