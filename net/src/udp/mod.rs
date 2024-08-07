use core::mem::size_of;
use core::net::IpAddr;

use collections::bytes::{Cursor, Slice};
use collections::map::{self, Key, Map};
use log::{debug, error, info, warn};
use stakker::{Actor, Fwd, CX};
use utils::bytes::{self, Cast};
use utils::endian::u16be;
use utils::error::*;

use crate::ip::Protocol::Udp;
use crate::ip::{self, SocketAddr, ToS};

const EPHEMERAL: u16 = 49152;

#[derive(Cast)]
#[repr(C)]
struct Header {
	src: u16be,
	dst: u16be,
	len: u16be,
	csum: [u8; 2],
}

#[derive(Clone)]
pub struct Socket {
	port: u16,
	interface: Actor<super::Interface>,
}

impl Socket {
	pub fn bind(this: &mut super::Interface, cx: CX![super::Interface], port: u16, callback: Fwd<(SocketAddr, Slice)>) -> Result<Self> {
		let udp = &mut this.udp;

		let entry = match udp.map.find_entry(&port) {
			map::Entry::Empty(entry) => entry,
			_ => {
				error!("Address already in use");
				return Err(());
			}
		};

		entry.insert(Entry { port, callback });

		Ok(Socket { port, interface: cx.access_actor().clone() })
	}

	pub fn bind_eph(this: &mut super::Interface, cx: CX![super::Interface], callback: Fwd<(SocketAddr, Slice)>) -> Self {
		let udp = &mut this.udp;

		// Note: if all ports in the ephemeral range are full, this will loop forever.
		let entry = loop {
			// Increment, wrapping to the ephemeral port starting index
			udp.nxt = udp.nxt.checked_add(1).unwrap_or(EPHEMERAL);

			match udp.map.find_entry(&udp.nxt) {
				map::Entry::Empty(entry) => break entry,
				// If the port is already taken, continue
				_ => {}
			}
		};

		entry.insert(Entry { port: udp.nxt, callback });

		Socket {
			port: udp.nxt,
			interface: cx.access_actor().clone(),
		}
	}

	pub fn write(&self, SocketAddr { addr, port }: SocketAddr, f: impl FnOnce(Cursor) + 'static) {
		let tos = ToS::new(ip::ECN::NotECT, ip::DiffServ::Default);

		let src = self.port;

		let actor = self.interface.access_actor().clone();

		self.interface.defer(move |s| {
			actor.apply(s, move |this, cx| {
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
			})
		});
	}
}

impl Drop for Socket {
	fn drop(&mut self) {
		let port = self.port;
		let i = self.interface.clone();

		self.interface
			.defer(move |s| i.apply(s, move |this, _| assert!(this.udp.map.find_entry(&port).remove().is_some())));
	}
}

pub struct Connected {
	inner: Socket,
	addr: SocketAddr,
}

impl Connected {
	pub fn bind(this: &mut super::Interface, cx: CX![super::Interface], addr: SocketAddr, callback: impl Fn(Slice) + 'static) -> Self {
		let udp = &mut this.udp;

		let callback = Fwd::new(move |(src, buf)| {
			if src == addr {
				// The packet source matches the bound address
				callback(buf);
			} else {
				info!("Recieved unexpected packet from {}", src);
			}
		});

		// Note: if all ports in the ephemeral range are full, this will loop forever.
		let entry = loop {
			// Increment, wrapping to the ephemeral port starting index
			udp.nxt = udp.nxt.checked_add(1).unwrap_or(EPHEMERAL);

			match udp.map.find_entry(&udp.nxt) {
				map::Entry::Empty(entry) => break entry,
				// If the port is already taken, continue
				_ => {}
			}
		};

		entry.insert(Entry { port: udp.nxt, callback });

		Connected {
			inner: Socket {
				port: udp.nxt,
				interface: cx.access_actor().clone(),
			},
			addr,
		}
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
	pub fn recv<'a>(&'a self, interface: &ip::Interface, addr: IpAddr, buf: Slice) -> Result {
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

		let e = self.map.find(&dst).ok_or_else(|| debug!("Socket at port {dst} not found"))?;

		if header.len.get() as u32 != len {
			log::warn!("UDP header length ({len}) does not match actual packet length ({})", len);
			return Err(());
		}

		let port = header.src.get();

		e.callback.fwd((SocketAddr { addr, port }, buf));

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
	callback: Fwd<(SocketAddr, Slice)>,
}

impl Key for Entry {
	type Type = u16;

	fn key(&self) -> &Self::Type {
		&self.port
	}
}
