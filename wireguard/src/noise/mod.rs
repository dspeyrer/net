pub mod aead;
mod chain;
mod hash;

use blake2::digest::consts::U32;
use blake2::digest::generic_array::GenericArray;
use collections::map::Map;
pub use hash::Hash;
use log::warn;
use runtime::time;
use stakker::CX;
use tai64::Tai64N;
use utils::error::*;
use x25519_dalek::{PublicKey, StaticSecret as SecretKey};

pub use self::chain::Chain;
use crate::packet::{Initiation, Response};
use crate::tunnel::{Interface, Noise, Peer};
use crate::Wireguard;

pub type A32 = GenericArray<u8, U32>;

#[derive(Clone)]
pub struct InitiatorHandshake {
	hash: Hash,
	chain: Chain,
	iek: SecretKey,
}

pub struct ResponderHandshake<'a> {
	hash: Hash,
	chain: Chain,
	iek: &'a PublicKey,
}

impl InitiatorHandshake {
	pub fn create_initiation(cx: CX![Wireguard], i: &Interface, r: &Noise, msg: &mut Initiation) -> Self {
		let mut hash = r.hash.clone();
		let mut chain = Chain::default();

		let iek = SecretKey::random();
		msg.ephemeral = PublicKey::from(&iek);

		hash.update(&msg.ephemeral);
		chain.write(&msg.ephemeral);

		let [k] = chain.kdf(&iek.diffie_hellman(&r.key));

		msg.pubkey.seal(i.pubkey, &k, &mut hash);

		let [k] = chain.kdf(&r.s_agree);

		let now = time::system(cx);

		msg.timestamp.seal(Tai64N::from_system_time(&now).into(), &k, &mut hash);

		Self { hash, chain, iek }
	}

	pub fn consume_response(self, i: &Interface, r: &Noise, msg: &mut Response) -> Result<Chain> {
		let Self { mut hash, mut chain, iek } = self;

		hash.update(&msg.ephemeral);
		chain.write(&msg.ephemeral);

		chain.write(&iek.diffie_hellman(&msg.ephemeral));
		chain.write(&i.key.diffie_hellman(&msg.ephemeral));

		let [t, k] = chain.kdf(&r.preshared);

		hash.update(&t);
		msg.empty.open(&k, &mut hash)?;

		// fs::write(
		// 	"./WIREGUARD_KEYS",
		// 	format!(
		// 		"LOCAL_STATIC_PRIVATE_KEY={}\nREMOTE_STATIC_PUBLIC_KEY={}\nLOCAL_EPHEMERAL_PRIVATE_KEY={}\nPRESHARED_KEY={}",
		// 		STANDARD.encode(i.key.as_bytes()),
		// 		STANDARD.encode(r.key.as_bytes()),
		// 		STANDARD.encode(iek.as_bytes()),
		// 		STANDARD.encode(r.preshared),
		// 	),
		// )
		// .unwrap();

		Ok(chain)
	}
}

impl<'a> ResponderHandshake<'a> {
	pub fn consume_initiation<'b>(initiators: &'b mut Map<Peer, 1>, r: &Interface, msg: &'a mut Initiation) -> Result<(Self, &'b mut Peer)> {
		let mut hash = r.hash.clone();
		let mut chain = Chain::default();

		hash.update(&msg.ephemeral);
		chain.write(&msg.ephemeral);

		let [k] = chain.kdf(&r.key.diffie_hellman(&msg.ephemeral));
		let s_pub = msg.pubkey.open(&k, &mut hash)?;

		let i = initiators
			.find_entry(s_pub)
			.filled()
			.ok_or_else(|| warn!("Unable to find peer"))?
			.into_ref();

		let [k] = chain.kdf(&i.hs.s_agree);
		let timestamp = msg.timestamp.open(&k, &mut hash)?;
		i.hs.update_timestamp(*timestamp)?;

		Ok((Self { hash, chain, iek: &msg.ephemeral }, i))
	}

	pub fn create_response(self, i: &Noise, msg: &mut Response) -> Chain {
		let Self { mut hash, mut chain, iek } = self;

		let re = SecretKey::random();
		msg.ephemeral = PublicKey::from(&re);

		hash.update(&msg.ephemeral);
		chain.write(&msg.ephemeral);

		chain.write(&re.diffie_hellman(&iek));
		chain.write(&re.diffie_hellman(&i.key));

		let [t, k] = chain.kdf(&i.preshared);

		hash.update(&t);
		msg.empty.seal((), &k, &mut hash);

		chain
	}
}
