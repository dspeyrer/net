use std::time::{Duration, Instant};

use collections::map::Index;
use log::{info, trace};
use rand::Rng;
use runtime::{Core, FixedTimerKey, MaxTimerKey};

use crate::App;

pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// The timer state for a peer.
pub struct Timers {
	/// When the rekey timer elapses, a new initiation message is sent to the peer. This is used both for the rekey cycle and for keepalive expirations.
	rekey: MaxTimerKey,
	/// When the keepalive timer elapses, an empty data packet (keepalive) is sent to the peer.
	keepalive: FixedTimerKey,
	/// The time that the next keepalive has been queued for.
	next_keepalive: Option<Instant>,
	/// The persistent keepalive interval, if any.
	persistent_keepalive: Option<Duration>,
	/// The timestamp when rekeying started. When the elapsed time since this timestamp exceeds `REKEY_ATTEMPT_TIME`, give up on rekeying.
	rekey_start: Option<Instant>,
	/// The index in the map of the peer this timer state belongs to.
	idx: Index<1>,
}

impl Timers {
	pub fn new(idx: Index<1>, persistent_keepalive: Option<Duration>) -> Self {
		Self {
			rekey: MaxTimerKey::default(),
			keepalive: FixedTimerKey::default(),
			next_keepalive: None,
			persistent_keepalive,
			rekey_start: None,
			idx,
		}
	}

	/// Call when a rekey is requested. The caller must send an initiation message if this method returns true.
	pub fn is_rekeying(&self) -> bool {
		self.rekey_start.is_some()
	}

	/// Returns whether REKEY_ATTEMPT_TIME has already elapsed.
	pub fn rekey_elapsed<A>(&self, cx: &mut Core<A>) -> bool {
		let Some(t) = self.rekey_start.as_ref() else { return false };
		cx.now() - *t >= REKEY_ATTEMPT_TIME
	}

	/// Call when a data packet is sent.
	pub fn send_data<A: App>(&mut self, cx: &mut Core<A>, is_keepalive: bool) {
		// Cancel the keepalive timer, since we just sent a packet instead.
		cx.timer_del(self.keepalive);

		if let Some(delay) = self.persistent_keepalive {
			let next_keepalive = cx.now() + delay;
			// If there is a persistent keepalive, then send a keepalive after its timeout.
			self.keepalive = cx.after(delay, self.keepalive_fn());
			self.next_keepalive = Some(next_keepalive);
		} else {
			self.next_keepalive = None;
		}

		if !is_keepalive {
			// Start the response timeout for rekeying if we don't get a response to a data packet.
			self.reset_rekey(cx, KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
		}
	}

	/// Call when a data packet is recieved.
	pub fn recv_data<A: App>(&mut self, cx: &mut Core<A>, is_keepalive: bool) {
		if !self.is_rekeying() {
			// Cancel the timeout rekey timer, since a packet has been recieved.
			cx.timer_max_del(self.rekey);
		}

		if !is_keepalive {
			// If the recieved packet is not a keepalive packet, the peer expects a response.
			// Calculate the time we should send a keepalive.
			let next_keepalive = cx.now() + KEEPALIVE_TIMEOUT;

			// If there isn't a keepalive queued already, or it's queued for after we need it,
			// then we need to set this keepalive.
			if self.next_keepalive.is_none_or(|t| t > next_keepalive) {
				// If there already is a keepalive timer set, clear it.
				if self.next_keepalive.is_some() {
					cx.timer_del(self.keepalive);
				}
				// Set the keepalive timer.
				cx.timer_add(next_keepalive, self.keepalive_fn());
				self.next_keepalive = Some(next_keepalive);
			}
		} else {
			info!("Recieved keepalive packet");
		}
	}

	/// Call when an initiation packet is sent.
	pub fn send_init<A: App>(&mut self, cx: &mut Core<A>) {
		if self.rekey_start.is_none() {
			// Start the rekeying timer
			self.rekey_start = cx.now().into();
		};

		// Defer another rekey
		self.reset_rekey(cx, REKEY_TIMEOUT + Self::jitter());
	}

	/// Call when a response packet is recieved.
	pub fn recv_resp<A: App>(&mut self, cx: &mut Core<A>) {
		// Rekeying is over
		self.rekey_start = None;
		// Delete the rekey timer
		cx.timer_max_del(self.rekey);
		// Defer sending a keepalive packet immediately if no other data is sent to activate the connection.
		self.keepalive = cx.timer_add(cx.now(), self.keepalive_fn());
	}

	/// Call when a response packet is sent.
	pub fn send_resp<A>(&mut self, _: &mut Core<A>) {
		// No-op
	}

	/// Defer sending a keepalive packet until `duration` elapses.
	fn keepalive_fn<A: App>(&self) -> impl FnOnce(&mut A, &mut Core<A>) + Send + 'static {
		let idx = self.idx;
		move |app, cx| app.wireguard().send_keepalive(cx, idx)
	}

	/// Defer rekeying until `duration` elapses.
	fn reset_rekey<A: App>(&mut self, cx: &mut Core<A>, duration: Duration) {
		trace!("Setting rekey timeout for {:?}", duration);
		let idx = self.idx;
		cx.timer_max(&mut self.rekey, cx.now() + duration, move |app, cx| app.wireguard().rekey(cx, idx));
	}

	/// Return random jitter for timeouts. This should be applied to the next rekey timer each time it elapses.
	fn jitter() -> Duration {
		Duration::from_millis(rand::thread_rng().gen_range(0..333))
	}
}
