// Copyright (c) 2019-2020 Jim Peters
// Copyright (c) 2020 `stakker` crate contributors

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use timers::Timers;
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

pub use timers::{FixedTimerKey, MaxTimerKey};

mod timers;

/// Core operations available from both [`Stakker`] and [`Cx`] objects
///
/// Both [`Stakker`] and [`Cx`] references auto-dereference to a
/// [`Core`] reference, so typically either of those can be used
/// wherever a [`Core`] reference is required.
///
/// [`Core`]: struct.Core.html
/// [`Cx`]: struct.Cx.html
/// [`Stakker`]: struct.Stakker.html
pub struct Core<A> {
    now: Instant,
    idle_queue: VecDeque<Box<dyn FnOnce(&mut A, &mut Core<A>)>>,
    timers: Timers<A>,
    systime: SystemTime,
}

impl<A> Core<A> {
    pub fn new(now: Instant, systime: SystemTime) -> Self {
        Self {
            now,
            idle_queue: VecDeque::new(),
            timers: Timers::new(now),
            systime,
        }
    }

    /// Return how long we need to wait for the next timer, or None if
    /// there are no timers to wait for
    pub fn next_wait(&mut self) -> Option<Duration> {
		if self.idle_queue.is_empty() {
			self.timers
				.next_expiry()
				.map(|t| t.saturating_duration_since(self.now))
        } else {
			Some(Duration::from_secs(0))
		}
    }

    /// Move time forward, expire any timers onto the main
    /// [`Deferrer`] queue, then run main and lazy queues until there
    /// is nothing outstanding.  Returns `true` if there are idle
    /// items still to run.
    ///
    /// If `idle` is true, then runs an item from the idle queue as
    /// well.  This should be set only if we've already run the queues
    /// and just polled I/O (without waiting) and still there's
    /// nothing to do.
    ///
    /// Note: All actors should use `cx.now()` to get the time, which
    /// allows the entire system to be run in virtual time (unrelated
    /// to real time) if necessary.
    ///
    /// [`Deferrer`]: struct.Deferrer.html
    pub fn run(&mut self, app: &mut A, idle: bool) {
        if idle {
            if let Some(cb) = self.idle_queue.pop_front() {
                cb(app, self);
            }
        }

		Timers::advance(self, app, self.now);
    }

	pub fn update_time(&mut self) -> Duration {
		let now = Instant::now();

		if let Some(elapsed) = now.checked_duration_since(self.now) {
			self.now = now;
			elapsed
		} else {
			Duration::ZERO
		}
	}

    /// Our view of the current time.  Actors should use this in
    /// preference to `Instant::now()` for speed and in order to work
    /// in virtual time.
    #[inline]
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Get the current `SystemTime`.  Normally this returns the same
    /// as `SystemTime::now()`, but if running in virtual time, it
    /// would return the virtual `SystemTime` instead (as provided to
    /// [`Stakker::set_systime`] by the virtual time main loop).  Note
    /// that this time is not suitable for timing things, as it may go
    /// backwards if the user or a system process adjusts the clock.
    /// It is just useful for showing or recording "human time" for
    /// the user, and for recording times that are meaningful on a
    /// longer scale, e.g. from one run of a process to the next.
    ///
    /// [`Stakker::set_systime`]: struct.Stakker.html#method.set_systime
    #[inline]
    pub fn systime(&self) -> SystemTime {
        self.systime
    }

    /// Get the `Instant` which was passed to `Stakker::new` when this
    /// runtime was started.
    #[inline]
    pub fn start_instant(&self) -> Instant {
        self.timers.t0
    }

    /// Defer an operation to be executed when this process next
    /// becomes idle, i.e. when all other queues are empty and there
    /// is no I/O to process.  This can be used to implement
    /// backpressure on incoming streams, i.e. only fetch more data
    /// once there is nothing else left to do.  See also the [`idle!`]
    /// macro.
    ///
    /// [`idle!`]: macro.idle.html
    #[inline]
    pub fn idle(&mut self, f: impl FnOnce(&mut A, &mut Core<A>) + 'static) {
        self.idle_queue.push_back(Box::new(f));
    }

    /// Delay an operation to be executed after a duration has passed.
    /// This is the same as adding it as a fixed timer.  Returns a key
    /// that can be used to delete the timer.  See also the [`after!`]
    /// macro.
    ///
    /// [`after!`]: macro.after.html
    #[inline]
    pub fn after(
        &mut self,
        dur: Duration,
        f: impl FnOnce(&mut A, &mut Core<A>) + 'static,
    ) -> FixedTimerKey {
        self.timers.add(self.now + dur, Box::new(f))
    }

    /// Add a fixed timer that expires at the given time.  Returns a
    /// key that can be used to delete the timer.  See also the
    /// [`at!`] macro.
    ///
    /// [`at!`]: macro.at.html
    #[inline]
    pub fn timer_add(
        &mut self,
        expiry: Instant,
        f: impl FnOnce(&mut A, &mut Core<A>) + 'static,
    ) -> FixedTimerKey {
        self.timers.add(expiry, Box::new(f))
    }

    /// Delete a fixed timer.  Returns `true` on success, `false` if
    /// timer no longer exists (i.e. it expired or was deleted)
    #[inline]
    pub fn timer_del(&mut self, key: FixedTimerKey) -> bool {
        self.timers.del(key)
    }

    /// Add a "Max" timer, which expires at the greatest (latest)
    /// expiry time provided.  See [`MaxTimerKey`] for the
    /// characteristics of this timer.  Returns a key that can be used
    /// to delete or modify the timer.
    ///
    /// See also the [`timer_max!`] macro, which may be more
    /// convenient as it combines [`Core::timer_max_add`] and
    /// [`Core::timer_max_upd`].
    ///
    /// [`Core::timer_max_add`]: struct.Core.html#method.timer_max_add
    /// [`Core::timer_max_upd`]: struct.Core.html#method.timer_max_upd
    /// [`MaxTimerKey`]: struct.MaxTimerKey.html
    /// [`timer_max!`]: macro.timer_max.html
    #[inline]
    pub fn timer_max_add(
        &mut self,
        expiry: Instant,
        f: impl FnOnce(&mut A, &mut Core<A>) + 'static,
    ) -> MaxTimerKey {
        self.timers.add_max(expiry, Box::new(f))
    }

    /// Update a "Max" timer with a new expiry time.  It will be used
    /// as the new expiry time only if it is greater than the current
    /// expiry time.  This call is designed to be very cheap to call
    /// frequently.
    ///
    /// Returns `true` on success, `false` if timer no longer exists
    /// (i.e. it expired or was deleted)
    ///
    /// See also the [`timer_max!`] macro, which may be more
    /// convenient as it combines [`Core::timer_max_add`] and
    /// [`Core::timer_max_upd`].
    ///
    /// [`Core::timer_max_add`]: struct.Core.html#method.timer_max_add
    /// [`Core::timer_max_upd`]: struct.Core.html#method.timer_max_upd
    /// [`timer_max!`]: macro.timer_max.html
    #[inline]
    pub fn timer_max_upd(&mut self, key: MaxTimerKey, expiry: Instant) -> bool {
        self.timers.mod_max(key, expiry)
    }

    /// Delete a "Max" timer.  Returns `true` on success, `false` if
    /// timer no longer exists (i.e. it expired or was deleted)
    #[inline]
    pub fn timer_max_del(&mut self, key: MaxTimerKey) -> bool {
        self.timers.del_max(key)
    }

    /// Check whether a "Max" timer is active.  Returns `true` if it
    /// exists and is active, `false` if it expired or was deleted or
    /// never existed
    #[inline]
    pub fn timer_max_active(&mut self, key: MaxTimerKey) -> bool {
        self.timers.max_is_active(key)
    }

	#[inline]
	pub fn timer_max(
		&mut self,
		key: &mut MaxTimerKey,
		expiry: Instant,
		f: impl FnOnce(&mut A, &mut Core<A>) + 'static
	) {
		if !self.timer_max_upd(*key, expiry) {
            *key = self.timer_max_add(expiry, f);
        }
	}
}
