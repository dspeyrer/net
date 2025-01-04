use std::time::{Duration, SystemTime};

pub fn elapsed<A>(core: &stakker::Core<A>) -> Duration {
	// Get the duration that has passed since the runtime was initialised.
	core.now() - core.start_instant()
}

/// Get the current system time.
pub fn system<A>(core: &stakker::Core<A>) -> SystemTime {
	// Get the system time of initialisation of the runtime.
	let time = core.systime();
	// Simulate the current system time using the monotonic clock.
	time + elapsed(core)
}

/// Get the UNIX time in seconds.
pub fn unix<A>(core: &stakker::Core<A>) -> u32 {
	// Get the system time.
	let time = system(core);

	// Calculate the amount of time since the UNIX epoch.
	let unix = time
		.duration_since(SystemTime::UNIX_EPOCH)
		.expect("The current time should be after the UNIX epoch");

	// Return the duration in seconds.
	unix.as_secs().try_into().expect("32-bit UNIX time should not overflow")
}
