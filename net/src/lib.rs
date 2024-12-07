#![feature(slice_as_chunks, write_all_vectored, trivial_bounds)]

use core::net::{Ipv4Addr, Ipv6Addr};

use stakker::{Actor, ActorOwn, CX};
use wireguard::Wireguard;

extern crate alloc;

pub mod dns;
mod ip;
pub mod pcap;
pub mod tcp;
pub mod udp;

pub use ip::SocketAddr;

pub struct Interface {
	link: ActorOwn<Wireguard>,

	#[cfg(feature = "pcap")]
	pcap: pcap::Writer,

	ip: ip::Interface,

	fragment: ip::fragment::Store,

	udp: udp::Interface,
	tcp: tcp::Interface,
}

impl Interface {
	pub fn init(cx: CX![], link: impl FnOnce(&mut stakker::Core, Actor<Self>) -> ActorOwn<Wireguard>, v4: Ipv4Addr, v6: Ipv6Addr) -> Option<Self> {
		let actor = cx.access_actor().clone();

		Some(Self {
			link: link(cx, actor),

			#[cfg(feature = "pcap")]
			pcap: pcap::Writer::new("./log.pcap").unwrap(),

			ip: ip::Interface::new(v4, v6),

			fragment: ip::fragment::Store::default(),

			udp: udp::Interface::default(),
			tcp: tcp::Interface::default(),
		})
	}
}
