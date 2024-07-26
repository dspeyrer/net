use std::time::{Duration, Instant};

use collections::map::Index;
use log::{debug, info, trace};
use rand::Rng;
use stakker::{timer_max, Cx, FixedTimerKey, MaxTimerKey, CX};

use crate::Wireguard;

pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// The timer state for a peer.
pub struct Timers {
	/// When the rekey timer elapses, a new initiation message is sent to the peer. This is used both for the rekey cycle and for keepalive expirations.
	rekey: MaxTimerKey,
	/// When the keepalive timer elapses, an empty data packet (keepalive) is sent to the peer. If this field is equal to FixedTimerKey::default(), then there is no keepalive timer set.
	keepalive: FixedTimerKey,
	/// The timestamp when rekeying started. When the elapsed time since this timestamp exceeds `REKEY_ATTEMPT_TIME`, give up on rekeying.
	rekey_start: Option<Instant>,
	/// The index in the map of the peer this timer state belongs to.
	idx: Index<1>,
}

impl Timers {
	pub fn new(idx: Index<1>) -> Self {
		Self {
			rekey: MaxTimerKey::default(),
			keepalive: FixedTimerKey::default(),
			rekey_start: None,
			idx,
		}
	}

	/// Call when a rekey is requested. The caller must send an initiation message if this method returns true.
	pub fn is_rekeying(&self) -> bool {
		self.rekey_start.is_some()
	}

	/// Returns whether REKEY_ATTEMPT_TIME has already elapsed.
	pub fn rekey_elapsed(&self, cx: CX![Wireguard]) -> bool {
		let Some(t) = self.rekey_start.as_ref() else { return false };
		cx.now() - *t >= REKEY_ATTEMPT_TIME
	}

	/// Call when a data packet is sent.
	pub fn send_data(&mut self, cx: &mut Cx<Wireguard>, is_keepalive: bool) {
		if !is_keepalive {
			// Delete the keepalive timer, since data has now been sent.
			cx.timer_del(self.keepalive);
			// Start the response timeout for rekeying.
			self.reset_rekey(cx, KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
		}

		// Clear the keepalive timer
		self.keepalive = FixedTimerKey::default();
	}

	/// Call when a data packet is recieved.
	pub fn recv_data(&mut self, cx: &mut Cx<Wireguard>, is_keepalive: bool) {
		// Cancel the timeout rekey timer, since a packet has been recieved
		cx.timer_max_del(self.rekey);

		if !is_keepalive {
			// Defer the sending of a keepalive packet if the recieved packet is not a keepalive packet
			self.reset_keepalive(cx, KEEPALIVE_TIMEOUT);
		} else {
			info!("Recieved keepalive packet");
		}
	}

	/// Call when an initiation packet is sent.
	pub fn send_init(&mut self, cx: &mut Cx<Wireguard>) {
		if self.rekey_start.is_none() {
			// Start the rekeying timer
			self.rekey_start = cx.now().into();
		};

		// Defer another rekey
		self.reset_rekey(cx, REKEY_TIMEOUT + Self::jitter());
	}

	/// Call when a response packet is recieved.
	pub fn recv_resp(&mut self, cx: &mut Cx<Wireguard>) {
		// Rekeying is over
		self.rekey_start = None;
		// Delete the rekey timer
		cx.timer_max_del(self.rekey);
		// Defer sending a keepalive packet immediately if no other data is sent
		self.reset_keepalive(cx, Duration::ZERO);
	}

	/// Call when a response packet is sent.
	pub fn send_resp(&mut self, _: &mut Cx<Wireguard>) {
		// No-op
	}

	/// Defer sending a keepalive packet until `duration` elapses.
	fn reset_keepalive(&mut self, cx: &mut Cx<Wireguard>, duration: Duration) {
		if self.keepalive == FixedTimerKey::default() {
			debug!("Setting keepalive timeout for {:?}", duration);

			let actor = cx.access_actor().clone();
			let idx = self.idx;

			self.keepalive = cx.after(duration, move |s| actor.apply(s, move |this, cx| this.send_keepalive(cx, idx)));
		}
	}

	/// Defer rekeying until `duration` elapses.
	fn reset_rekey(&mut self, cx: &mut Cx<Wireguard>, duration: Duration) {
		trace!("Setting rekey timeout for {:?}", duration);
		timer_max!(&mut self.rekey, cx.now() + duration, [cx], rekey(self.idx));
	}

	/// Return random jitter for timeouts. This should be applied to the next rekey timer each time it elapses.
	fn jitter() -> Duration {
		Duration::from_millis(rand::thread_rng().gen_range(0..333))
	}
}
