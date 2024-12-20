#![feature(slice_as_chunks, write_all_vectored, trivial_bounds)]

use core::net::{Ipv4Addr, Ipv6Addr};
use std::net::IpAddr;

use collections::bytes::Slice;
use stakker::Core;
use wireguard::Wireguard;

extern crate alloc;

mod dns;
mod ip;
pub mod pcap;
pub mod tcp;
pub mod udp;

pub use ip::SocketAddr;

pub struct Interface<A: App + 'static> {
	link: Wireguard,

	#[cfg(feature = "pcap")]
	pcap: pcap::Writer,

	ip: ip::Interface,

	fragment: ip::fragment::Store,

	udp: udp::Interface,
	tcp: tcp::Interface,

	dns: dns::Resolver<A>,
}

pub trait App: wireguard::App + Sized {
	fn net(&mut self) -> &mut Interface<Self>;
}

impl<A: App> Interface<A> {
	pub fn init(
		cx: &mut Core<A>,
		link: impl FnOnce(&mut stakker::Core<A>, Box<dyn FnMut(Slice)>) -> Wireguard,
		v4: Ipv4Addr,
		v6: Ipv6Addr,
		dns: IpAddr,
	) -> Self {
		let mut udp = udp::Interface::default();

		let d = cx.deferrer();
		let write = Box::new(move |buf| d.defer(|app, _| app.net().recv(buf)));

		Self {
			link: link(cx, write),

			#[cfg(feature = "pcap")]
			pcap: pcap::Writer::new("./log.pcap").unwrap(),

			ip: ip::Interface::new(v4, v6),

			fragment: ip::fragment::Store::default(),

			dns: dns::Resolver::init(cx, &mut udp, dns),

			udp,
			tcp: tcp::Interface::default(),
		}
	}

	pub fn wireguard(&mut self) -> &mut Wireguard {
		&mut self.link
	}
}
