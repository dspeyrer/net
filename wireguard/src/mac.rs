use std::time::{Duration, Instant};

use blake2::digest::generic_array::sequence::Split;
use blake2::digest::generic_array::GenericArray;
use blake2::digest::typenum::U16;
use blake2::digest::{FixedOutput, FixedOutputReset, KeyInit, Update};
use blake2::{Blake2s256 as Hasher, Blake2sMac};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Tag, XChaCha20Poly1305 as XAead};
use collections::bytes::Cursor;
use log::warn;
use stakker::CX;
use utils::error::*;

use crate::noise::A32;
use crate::packet::Cookie;
use crate::Wireguard;

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

type A16 = GenericArray<u8, U16>;
type Mac = Blake2sMac<U16>;

pub struct Mac1(A16);

pub struct CookieMac {
	mac1: A32,
	mac2: Option<Tau>,
	aead: XAead,
}

#[derive(Clone, Copy)]
struct Tau {
	value: A16,
	time: Instant,
}

impl CookieMac {
	pub fn new(key: &[u8; 32]) -> Self {
		let mut hasher = Hasher::default();

		hasher.update(LABEL_MAC1);
		hasher.update(key);

		let mac1 = hasher.finalize_fixed_reset();

		hasher.update(LABEL_COOKIE);
		hasher.update(key);

		let aead = XAead::new(&hasher.finalize_fixed());

		Self { mac1, mac2: None, aead }
	}

	pub fn check(&mut self, cx: CX![Wireguard], bytes: &[u8]) -> Result {
		let m1 = bytes.len() - 32;
		let m2 = bytes.len() - 16;

		let mac1 = Mac::new(&self.mac1).chain(&bytes[..m1]).finalize_fixed();

		if mac1.as_slice() != &bytes[m1..m2] {
			warn!("Packet contains invalid mac1");
			return Err(());
		}

		let mac2 = if self.tau(cx).is_some() {
			unimplemented!("Cookie sending is not supported")
		} else {
			[0u8; 16]
		};

		if mac2.as_slice() != &bytes[m2..] {
			warn!("Packet contains invalid mac2");
			return Err(());
		}

		Ok(())
	}

	#[must_use]
	pub fn write(&mut self, cx: CX![Wireguard], mut buf: Cursor) -> Mac1 {
		let (data, mac1) = buf.fork().rsplit();

		Mac::new(&self.mac1).chain(&*data).finalize_into(mac1);
		let m1 = Mac1(*mac1);

		let (data, mac2) = buf.fork().rsplit();

		if let Some(mut core) = self.tau(cx) {
			core.update(&data);
			core.finalize_into(mac2);
		} else {
			mac2.fill(0);
		};

		m1
	}

	pub fn handle_cookie(&mut self, cx: CX![Wireguard], msg: &mut Cookie, last_mac: &Mac1) -> Result {
		let (tau, tag): (&mut GenericArray<u8, U16>, &mut Tag) = <&mut GenericArray<_, _>>::from(&mut msg.cookie).split();
		self.aead
			.decrypt_in_place_detached((&msg.nonce).into(), &last_mac.0, tau, tag)
			.map_err(|_| warn!("Failed to decrypt cookie value"))?;

		self.mac2 = Tau { value: *tau, time: cx.now() }.into();

		Ok(())
	}

	fn tau(&mut self, cx: CX![Wireguard]) -> Option<Mac> {
		let tau = &self.mac2?;

		if cx.now() - tau.time >= Duration::from_secs(120) {
			self.mac2 = None;
			return None;
		}

		Some(Mac::new_from_slice(&tau.value).expect("Key size is valid"))
	}
}
