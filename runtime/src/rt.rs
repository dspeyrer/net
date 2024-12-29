use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use stakker::{Core, Stakker};
use utils::error::Result;

use crate::State;

static EXIT: AtomicBool = AtomicBool::new(false);

pub trait App {
	fn io(&mut self) -> &mut State;
}

pub fn exec<A: App + 'static>(f: impl FnOnce(&mut Core<A>, State) -> A) -> Result {
	// Set the global logger.
	crate::log_init();
	// Get both a monotonic and an absolute representation of the time.
	let now = Instant::now();
	let now_sys = SystemTime::now();
	// Create an I/O runner.
	let io = State::new();
	// Initialise Stakker with the monotonic time.
	let mut stakker = Stakker::new(now, |core| f(core, io));
	// Set the Stakker systime to the start time.
	stakker.set_systime(Some(now_sys));

	ctrlc::set_handler(|| EXIT.store(true, Ordering::Relaxed)).map_err(|err| log::error!("Error occurred while setting Ctrl+C handler: {err}"))?;

	let mut idle = false;

	loop {
		let t = Instant::now();

		let idle_pending = stakker.run(t, idle);

		// Break out of the loop if an exit is requested.
		if EXIT.load(Ordering::Relaxed) {
			// Execute the deferral queue to cleanup the application state.
			stakker.run(t, false);
			// Log collected poll statistics.
			stakker.app().io().log_stats();
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
		if timeout.is_none() && !stakker.app().io().is_io() {
			break;
		}

		log::trace!("idle_pending: {}, timeout: {:?}", idle_pending, timeout);

		// Poll the file descriptors.
		let Ok(is_io) = stakker.app().io().poll(timeout) else {
			// If polling fails, run the exit processor on the next iteration of the loop.
			EXIT.store(true, Ordering::Relaxed);
			continue;
		};

		// Only process the idle queue if there are items in it, and if no I/O occurred.
		idle = idle_pending && !is_io;
	}

	Ok(())
}
