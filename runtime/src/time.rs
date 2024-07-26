use std::time::SystemTime;

/// Get the current system time.
pub fn system(core: &stakker::Core) -> SystemTime {
	// Get the system time of initialisation of the runtime.
	let time = core.systime();
	// Get the duration that has passed since the runtime was initialised.
	let dur = core.now() - core.start_instant();
	// Simulate the current system time using the monotonic clock.
	time + dur
}

/// Get the UNIX time in seconds.
pub fn unix(core: &stakker::Core) -> u32 {
	// Get the system time.
	let time = system(core);

	// Calculate the amount of time since the UNIX epoch.
	let unix = time
		.duration_since(SystemTime::UNIX_EPOCH)
		.expect("The current time should be after the UNIX epoch");

	// Return the duration in seconds.
	unix.as_secs().try_into().expect("32-bit UNIX time should not overflow")
}
