#![feature(slice_as_chunks, write_all_vectored, trivial_bounds)]

use core::net::{Ipv4Addr, Ipv6Addr};

use stakker::{ActorOwn, CX};
use wireguard::Wireguard;

extern crate alloc;

pub mod dns;
mod ip;
#[cfg(feature = "pcap")]
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
	pub fn init(_: CX![], link: ActorOwn<Wireguard>, v4: Ipv4Addr, v6: Ipv6Addr) -> Option<Self> {
		Some(Self {
			link,

			#[cfg(feature = "pcap")]
			pcap: pcap::Writer::new("./log.pcap").unwrap(),

			ip: ip::Interface::new(v4, v6),

			fragment: ip::fragment::Store::default(),

			udp: udp::Interface::default(),
			tcp: tcp::Interface::default(),
		})
	}
}
