#![feature(write_all_vectored, trivial_bounds)]

use core::net::{Ipv4Addr, Ipv6Addr};
use std::net::IpAddr;

use collections::bytes::Slice;
use runtime::Core;
use wireguard::Wireguard;

extern crate alloc;

mod dns;
mod icmp;
mod ip;

pub mod pcap;
pub mod tcp;
pub mod udp;

pub use icmp::IcmpErrorTy;
pub use ip::SocketAddr;

pub struct Interface<A> {
	link: Wireguard,

	#[cfg(feature = "pcap")]
	pcap: pcap::Writer,

	ip: ip::Interface,

	fragment: ip::fragment::Store,

	tcp: tcp::Interface,
	dns: dns::Resolver<A>,
}

pub trait App: wireguard::App + Sized {
	const DNS_PORT: u16;

	/// The UDP read callback.
	fn on_udp(&mut self, cx: &mut Core<Self>, port: u16, src: SocketAddr, buf: Slice, icmp: Option<IcmpErrorTy>);

	fn net(&mut self) -> &mut Interface<Self>;
}

impl<A: App> Interface<A> {
	pub fn init(link: Wireguard, v4: Ipv4Addr, v6: Ipv6Addr, dns: IpAddr) -> Self {
		Self {
			link,

			#[cfg(feature = "pcap")]
			pcap: pcap::Writer::new(&format!("./{}.pcap",
				std::time::SystemTime::now()
				.duration_since(std::time::SystemTime::UNIX_EPOCH)
				.unwrap()
				.as_secs()
			)).unwrap(),

			ip: ip::Interface::new(v4, v6),

			fragment: ip::fragment::Store::default(),

			dns: dns::Resolver::init(dns),

			tcp: tcp::Interface::default(),
		}
	}

	pub fn wireguard(&mut self) -> &mut Wireguard {
		&mut self.link
	}
}
