use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use stakker::Stakker;
use utils::error::Result;

use crate::GLOBAL;

static EXIT: AtomicBool = AtomicBool::new(false);

pub fn init() -> Stakker {
	// Get both a monotonic and an absolute representation of the time.
	let now = Instant::now();
	let now_sys = SystemTime::now();
	// Initialise Stakker with the monotonic time.
	let mut s = Stakker::new(now);
	// Set the Stakker systime to the start time.
	s.set_systime(Some(now_sys));
	s
}

pub fn exec(stakker: &mut Stakker, exit_fn: impl FnOnce()) -> Result {
	ctrlc::set_handler(|| EXIT.store(true, Ordering::Relaxed)).map_err(|err| log::error!("Error occurred while setting Ctrl+C handler: {err}"))?;

	GLOBAL.with(|this| {
		let mut t = Instant::now();
		let mut idle_pending = stakker.run(t, false);

		while stakker.not_shutdown() {
			// Break out of the loop if an exit is requested.
			if EXIT.load(Ordering::Relaxed) {
				// Call the exit function, which should defer the cleanup of remaining objects.
				exit_fn();
				// Execute the deferral queue to cleanup the application state.
				stakker.run(t, false);
				// Log collected poll statistics.
				this.borrow().log_stats();
				// Exit.
				break;
			};

			let timeout = if idle_pending {
				// Poll the file descriptors without a timeout if there are items in the idle queue.
				Some(Duration::from_secs(0))
			} else {
				// Otherwise, get the timeout for the next timer.
				stakker.next_wait(t)
			};

			// If there is no timeout and no more sockets to poll, there is no more work to do. Exit.
			if timeout.is_none() && !this.borrow().is_io() {
				break;
			}

			log::trace!("idle_pending: {}, timeout: {:?}", idle_pending, timeout);

			// Poll the file descriptors.
			let Ok(is_io) = this.borrow_mut().poll(timeout) else {
				// If polling fails, run the exit processor on the next iteration of the loop.
				EXIT.store(true, Ordering::Relaxed);
				continue;
			};

			t = Instant::now();
			// If there is still no I/O ready after a non-blocking poll, run the idle queue.
			idle_pending = stakker.run(t, idle_pending && !is_io);
		}

		Ok(())
	})
}
