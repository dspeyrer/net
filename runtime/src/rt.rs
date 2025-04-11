use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};

use utils::error::Result;

use crate::{Core, State};

static EXIT: AtomicBool = AtomicBool::new(false);

pub fn exec<A>(f: impl FnOnce(&mut Core<A>) -> A) -> Result {
	// Set the global logger.
	crate::log_init();

	// Get both a monotonic and an absolute representation of the time.
	let now = Instant::now();
	let sys = SystemTime::now();

	// Initialise the runtime core with the monotonic time.
	let mut cx = Core::new(now, sys);
	let mut app = f(&mut cx);

	if let Err(err) = ctrlc::set_handler(|| EXIT.store(true, Ordering::Relaxed)) {
		log::error!("Error occurred while setting Ctrl+C handler: {err}");
	}

	// Run while the exit flag has not been set.
	while !EXIT.load(Ordering::Relaxed) {
		// Update the time.
		let elapsed = cx.update_time();
		cx.io().exec += elapsed;
		// Get the timeout for the next query.
		let timeout = cx.next_wait();
		// If there is no timeout and no more sockets to poll, there is no more work to do. Exit.
		if timeout.is_none() && !cx.io().is_io() {
			break;
		}
		// Poll I/O.
		let pending = cx.io().poll(timeout)?;
		// Update the time.
		let elapsed = cx.update_time();
		cx.io().wait += elapsed;
		// Execute I/O callbacks.
		let io_occurred = State::execute(&mut app, &mut cx, pending)?;
		// Execute expired timers, running the idle queue if no I/O occurred.
		cx.run(&mut app, !io_occurred);
	}

	Ok(())
}
