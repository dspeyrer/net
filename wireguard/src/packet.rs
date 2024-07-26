use tai64::Tai64N;
use utils::bytes::Cast;
use x25519_dalek::PublicKey;

use crate::noise::aead::Sealed;

pub const MAC_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Cast)]
#[repr(C)]
pub struct Tag(u32);

impl Tag {
	pub const COOKIE: Self = Tag(3);
	pub const DATA: Self = Tag(4);
	pub const INITIATION: Self = Tag(1);
	pub const RESPONSE: Self = Tag(2);
}

#[derive(Clone, Copy, Cast)]
#[repr(C)]
pub struct Timestamp {
	bytes: [u8; 12],
}

impl From<Tai64N> for Timestamp {
	fn from(value: Tai64N) -> Self {
		Self { bytes: value.to_bytes() }
	}
}

impl TryFrom<Timestamp> for Tai64N {
	type Error = tai64::Error;

	fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
		Tai64N::try_from(value.bytes)
	}
}

#[derive(Cast)]
#[repr(C)]
pub struct Initiation {
	pub tag: Tag,
	pub idx: u32,
	pub ephemeral: PublicKey,
	pub pubkey: Sealed<PublicKey>,
	pub timestamp: Sealed<Timestamp>,
}

#[derive(Cast)]
#[repr(C)]
pub struct Response {
	pub tag: Tag,
	pub idx: u32,
	pub rcv_idx: u32,
	pub ephemeral: PublicKey,
	pub empty: Sealed<()>,
}

#[derive(Cast)]
#[repr(C)]
pub struct Cookie {
	pub tag: Tag,
	pub idx: u32,
	pub nonce: [u8; 24],
	pub cookie: [u8; 32],
}

#[derive(Cast)]
#[repr(C)]
pub struct Data {
	pub tag: Tag,
	pub idx: u32,
	pub ctr: u64,
}
