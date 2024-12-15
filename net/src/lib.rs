#![feature(slice_as_chunks, write_all_vectored, trivial_bounds)]

use core::net::{Ipv4Addr, Ipv6Addr};
use std::net::IpAddr;

use stakker::{Actor, ActorOwn, CX};
use wireguard::Wireguard;

extern crate alloc;

mod dns;
mod ip;
pub mod pcap;
pub mod tcp;
pub mod udp;

pub use ip::SocketAddr;

pub struct Interface<A: App + 'static> {
	link: ActorOwn<Wireguard, A>,

	#[cfg(feature = "pcap")]
	pcap: pcap::Writer,

	ip: ip::Interface,

	fragment: ip::fragment::Store,

	udp: udp::Interface,
	tcp: tcp::Interface,

	dns: dns::Resolver<A>,
}

pub trait App: Sized {
	fn net(&self) -> &Actor<Interface<Self>, Self>;
}

impl<A: App> Interface<A> {
	pub fn init(
		cx: CX![A],
		link: impl FnOnce(&mut stakker::Core<A>, Actor<Self, A>) -> ActorOwn<Wireguard, A>,
		v4: Ipv4Addr,
		v6: Ipv6Addr,
		dns: IpAddr,
	) -> Self {
		let actor = cx.access_actor().clone();

		let mut udp = udp::Interface::default();

		Self {
			link: link(cx, actor),

			#[cfg(feature = "pcap")]
			pcap: pcap::Writer::new("./log.pcap").unwrap(),

			ip: ip::Interface::new(v4, v6),

			fragment: ip::fragment::Store::default(),

			dns: dns::Resolver::init(cx, &mut udp, dns),

			udp,
			tcp: tcp::Interface::default(),
		}
	}
}
