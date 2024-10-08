use core::fmt::{Debug, Display};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::SocketAddrV4;

use bilge::prelude::*;
use collections::bytes::{Cursor, Slice};
use log::warn;
use stakker::{call, CX};
use utils::bytes::{self, Cast};
use utils::error::*;

mod checksum;

pub mod v4;
pub mod v6;

pub mod fragment;

pub use checksum::Checksum;

#[derive(Clone, Copy)]
pub struct Interface {
	v4: Ipv4Addr,
	v6: Ipv6Addr,
}

impl Interface {
	pub fn new(v4: Ipv4Addr, v6: Ipv6Addr) -> Self {
		Self { v4, v6 }
	}

	#[inline]
	pub(crate) fn pseudo_checksum(&self, proto: Protocol, addr: IpAddr) -> Checksum {
		match addr {
			IpAddr::V4(addr) => {
				let mut csum = Checksum::with(bytes::cast(&addr));
				csum.push_chunk(bytes::cast(&self.v4));
				csum.push_chunk(&[0, 0, 0, proto.into()]);
				csum
			}
			IpAddr::V6(addr) => {
				let mut csum = Checksum::with(bytes::cast(&addr));
				csum.push_chunk(bytes::cast(&self.v6));
				csum.push_chunk(&[0, 0, 0, proto.into()]);
				csum
			}
		}
	}
}

impl crate::Interface {
	pub fn recv(&mut self, _: CX![], buf: Slice) {
		#[cfg(feature = "pcap")]
		let _ = self.pcap.log(&buf);

		let ver = bytes::cast::<Prefix, _>(&*buf).ver();

		let _ = match ver {
			Version::V4 => self.ip.recv_v4(self, buf),
			Version::V6 => self.ip.recv_v6(self, buf),
			Version::Unknown => return warn!("Invalid IP packet version"),
		};
	}

	pub(crate) fn write(&mut self, _: CX![], protocol: Protocol, addr: IpAddr, tos: ToS, f: impl FnOnce(Cursor) + 'static) {
		let ip = self.ip;
		#[cfg(feature = "pcap")]
		let pcap = self.pcap.clone();

		call!(
			[self.link],
			write(move |mut buf: Cursor<'_>| {
				match addr {
					IpAddr::V4(addr) => ip.write_v4(buf.fork(), protocol, addr, tos, f),
					IpAddr::V6(addr) => ip.write_v6(buf.fork(), protocol, addr, tos, f),
				}

				#[cfg(feature = "pcap")]
				let _ = pcap.log(&buf[..buf.pivot()]);
			})
		)
	}

	pub(crate) fn handle<'a>(&'a mut self, proto: Protocol, addr: IpAddr, buf: Slice) -> Result {
		match proto {
			Protocol::Udp => self.udp.recv(&self.ip, addr, buf),
			Protocol::Tcp => self.tcp.recv(&self.ip, addr, buf),
			Protocol::Unknown => Err(log::debug!("Unimplemented IP protocol")),
		}
	}
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SocketAddr {
	pub addr: IpAddr,
	pub port: u16,
}

impl From<std::net::SocketAddr> for SocketAddr {
	fn from(sock: std::net::SocketAddr) -> Self {
		Self { addr: sock.ip(), port: sock.port() }
	}
}

impl From<SocketAddrV4> for SocketAddr {
	fn from(sock: SocketAddrV4) -> Self {
		std::net::SocketAddr::into(sock.into())
	}
}

impl TryFrom<SocketAddr> for std::net::SocketAddrV4 {
	type Error = ();

	fn try_from(value: SocketAddr) -> std::result::Result<Self, ()> {
		match value.addr {
			IpAddr::V4(addr) => Ok(SocketAddrV4::new(addr, value.port)),
			_ => Err(()),
		}
	}
}

impl Debug for SocketAddr {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		<Self as Display>::fmt(self, f)
	}
}

impl Display for SocketAddr {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.addr {
			IpAddr::V4(addr) => f.write_fmt(format_args!("{}:{}", addr, self.port)),
			IpAddr::V6(addr) => f.write_fmt(format_args!("[{}]:{}", addr, self.port)),
		}
	}
}

#[bitsize(4)]
#[derive(FromBits)]
pub enum Version {
	V4 = 4,
	V6 = 6,
	#[fallback]
	Unknown,
}

#[bitsize(8)]
#[derive(FromBits, Cast)]
#[repr(C)]
pub struct Prefix {
	__0: u4,
	ver: Version,
}

#[bitsize(8)]
#[derive(Clone, Copy, FromBits, Cast)]
#[repr(C)]
pub struct ToS {
	ecn: ECN,
	ds: DiffServ,
}

#[bitsize(6)]
#[derive(FromBits)]
pub enum DiffServ {
	Default = 0,
	#[fallback]
	Unknown,
}

#[bitsize(2)]
#[derive(FromBits)]
pub enum ECN {
	NotECT = 0b00,
	ECT1 = 0b01,
	ECT0 = 0b10,
	CE = 0b11,
}

#[repr(u8)]
#[bitsize(8)]
#[derive(Hash, PartialEq, Eq, Clone, Copy, FromBits)]
pub enum Protocol {
	Tcp = 6,
	Udp = 17,
	#[fallback]
	Unknown,
}
