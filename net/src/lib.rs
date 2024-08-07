#![feature(slice_as_chunks, write_all_vectored, trivial_bounds)]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use stakker::{ActorOwn, CX};
use wireguard::Wireguard;

extern crate alloc;

pub mod dns;
mod ip;
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod tcp;
pub mod udp;

pub struct Interface {
	link: ActorOwn<Wireguard>,

	#[cfg(feature = "pcap")]
	pcap: pcap::Writer,

	ip: ip::Interface,

	fragment: ip::fragment::Store,

	dns: dns::Interface,

	udp: udp::Interface,
	tcp: tcp::Interface,
}

impl Interface {
	pub fn init(cx: CX![], link: ActorOwn<Wireguard>, v4: Ipv4Addr, v6: Ipv6Addr, dns: IpAddr) -> Option<Self> {
		let mut udp = udp::Interface::default();
		let tcp = tcp::Interface::default();

		let dns = dns::Interface::new(cx, &mut udp, dns);

		Some(Self {
			link,

			#[cfg(feature = "pcap")]
			pcap: pcap::Writer::new("./log.pcap").unwrap(),

			ip: ip::Interface::new(v4, v6),

			fragment: ip::fragment::Store::default(),

			dns,

			udp,
			tcp,
		})
	}
}
