use std::net::IpAddr;

use bilge::prelude::*;
use collections::bytes::Slice;
use runtime::Core;
use utils::bytes::Cast;
use utils::endian::BigEndian;

use crate::ip::{Checksum, ToS};
use crate::{App, Interface};

pub enum IcmpErrorTy {
	DestinationUnreachable,
	FragmentationNeeded { next_hop_mtu: u16 },
}

#[bitsize(8)]
#[derive(FromBits)]
enum Type {
	DestinationUnreachable = 3,
	#[fallback]
	Unknown,
}

#[bitsize(8)]
#[derive(FromBits, PartialEq, Eq)]
enum DestinationUnreachableCode {
	FragmentationRequired = 4,
	#[fallback]
	Unknown,
}

use DestinationUnreachableCode::*;

#[repr(C)]
#[derive(Cast)]
struct DestinationUnreachableHeader {
	/// Unused, must be set to zero. If Length or Next-hop MTU are not used, they are considered part of this field.
	unused: u8,
	/// Optional. The Length field indicates the length of the original datagram data, in 32-bit words. This allows this ICMP message to be extended with extra information. If used, the original datagram data must be padded with zeroes to the nearest 32-bit boundary.
	length: u8,
	/// Optional. Contains the MTU of the next-hop network if a code 4 error occurs.
	mtu: BigEndian<u16>,
}

#[repr(C)]
#[derive(Cast)]
struct Header {
	/// ICMP type.
	icty: BigEndian<Type>,
	/// ICMP subtype.
	code: u8,
	/// Internet checksum for error checking, calculated from the ICMP header and data with value 0 substituted for this field.
	csum: [u8; 2],
}

impl<A: App> Interface<A> {
	pub fn recv_icmp(app: &mut A, cx: &mut Core<A>, _: IpAddr, _: ToS, buf: Slice) {
		if buf.len() < size_of::<Header>() {
			log::info!("received ICMPv4 packet that is too short");
			return;
		}

		// Validate the checksum.
		if Checksum::of(&buf).end() != [0, 0] {
			log::warn!("ICMPv4 checksum does not match");
			return;
		}

		// Split off the ICMP header.
		let &Header { icty, code, .. } = buf.split();

		match icty.get() {
			Type::DestinationUnreachable => {
				if buf.len() < size_of::<DestinationUnreachableHeader>() {
					log::info!("received ICMPv4 packet that is too short");
					return;
				}

				// Extract the specific subtype of the packet.
				let code = DestinationUnreachableCode::from(code);
				// Get the type-specific header data.
				let &DestinationUnreachableHeader { unused, length, mtu } = buf.split();

				let next_hop_mtu = mtu.get();
				let skip = length as usize * 4;

				// Ensure we support the packet.
				if unused != 0 || (code != FragmentationRequired && next_hop_mtu != 0) {
					log::warn!("received destination unreachable packet with nonzero unused bytes");
					return;
				}

				if buf.len() < skip {
					log::warn!("received ICMPv4 packet that is too short");
					return;
				}

				// Skip any extension bytes.
				buf.split_bytes(skip);

				let errty = match code {
					FragmentationRequired => IcmpErrorTy::DestinationUnreachable,
					Unknown => IcmpErrorTy::FragmentationNeeded { next_hop_mtu },
				};

				// Forward the packet header for processing.
				Self::recv_v4(app, cx, buf, Some(errty));
			}
			Type::Unknown => log::debug!("received unknown ICMPv4 packet type"),
		}
	}
}
