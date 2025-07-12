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

use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::Core;

// TODO: Switch to N-ary Heap for storing (WrapTime, slot-index),
// e.g. Octonary heap, and use slots for normal timers as well as
// min/max.  Octonary heap because that means each level is a cache
// line.  So to pick the next, you have to scan 8 items, but they're
// all in one cache line so that's okay.  So reorganization of the
// tree is much cheaper.  Code for a heap should be a lot cheaper than
// BTreeMap, which generates a huge amount of assembler.

/// Timer key for a fixed timer
///
/// Returned by [`Core::timer_add`] or [`Core::after`].  It can be
/// used to delete a timer with [`Core::timer_del`].  It is plain
/// `Copy` data, 8 bytes long.  Note that the key should only be used
/// on this same **Stakker** instance.  If it is used on another then
/// it might cause a panic.
///
/// [`Core::after`]: struct.Core.html#method.after
/// [`Core::timer_add`]: struct.Core.html#method.timer_add
/// [`Core::timer_del`]: struct.Core.html#method.timer_del
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug)]
pub struct FixedTimerKey {
	slot: u32,
	// Generation for slot < 0x8000_0000, or WrapTime otherwise
	gen_or_time: u32,
}

/// Timer key for a Max timer
///
/// Used by the [`timer_max!`] macro and the `timer_max_*` methods in
/// [`Core`].  It can be used to delete a timer or change its expiry
/// time.  It is plain `Copy` data, 8 bytes long.  Note that the key
/// should only be used on this same **Stakker** instance.  If it is
/// used on another then it might cause a panic.
///
/// A "max" timer sets a timer at the first-provided timeout time,
/// then just records the largest of the timeout values provided until
/// that original timer expires, at which point it sets a new timer.
/// So this naturally absorbs a lot of changes without having to
/// delete any timers.  A typical use might be to take some action in
/// a gap in activity, for example to do an expensive background check
/// in a gap in the user's typing into a UI field.  To implement this,
/// the timer expiry time might be set to 'now' + 300ms by each
/// keypress, for example:
///
/// ```ignore
/// fn handle_keypress(&mut self, cx: CX![], ...) {
///     :::
///     timer_max!(&mut self.timer,
///                cx.now() + Duration::from_millis(300),
///                [cx], check_focus_field());
/// }
/// ```
///
/// [`Core`]: struct.Core.html
/// [`timer_max!`]: macro.timer_max.html
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug)]
pub struct MaxTimerKey {
	slot: u32, // Slot number
	gen: u32,  // Generation
}

// `Instant` converted cheaply into a `u64` by reducing the accuracy.
// This is `(secs << 16) + (nanos >> 14)`.  Nanos take values 0..61036
// in the low 16 bits, giving resolution of ~0.016ms.  This means
// quick conversion but adding/subtracting is not straightforward.
// Range is 8 million years, but more important is that low 32 bits
// cover 18 hours.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Time(u64);

impl Time {
	// Rounding up, used for timer expiry times, to make sure they
	// don't expire early
	pub fn new_ceil(inst: Instant, t0: Instant) -> Self {
		let dur = inst.saturating_duration_since(t0);
		Self((dur.as_secs() << 16) | u64::from((dur.subsec_nanos() + (1 << 14) - 1) >> 14))
	}

	// Rounding down, used for current time, to make sure we don't
	// accidentally expire something before its actual time.
	pub fn new_floor(inst: Instant, t0: Instant) -> Self {
		let dur = inst.saturating_duration_since(t0);
		Self((dur.as_secs() << 16) | u64::from(dur.subsec_nanos() >> 14))
	}

	pub fn add_secs(self, secs: u32) -> Time {
		Self(self.0 + (u64::from(secs) << 16))
	}

	pub fn inc(self) -> Time {
		Self(self.0 + 1)
	}

	pub fn instant(self, t0: Instant) -> Instant {
		t0 + Duration::new(self.0 >> 16, ((self.0 & 0xFFFF) as u32) << 14)
	}

	pub fn wt(self) -> WrapTime {
		WrapTime(self.0 as u32)
	}
}

// Cyclic (wrapping) time representation.  This can represent ~18
// hours cyclic range with resolution of ~0.016ms.  The difference
// between any two times is taken to be the smallest wrapped distance
// between them.  So to maintain a total order, no two timers can be
// more than ~9 hours apart.  So longer timers use a `VarSlot` and set
// the longest possible time there, and the actual time in the
// `VarSlot`.  They will be reinserted into the list about every 9
// hours until they expire.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct WrapTime(u32);

impl WrapTime {
	// Convert back to a Time, given the base value
	fn time(self, base: Time) -> Time {
		let val = (base.0 & !0xFFFF_FFFF) | u64::from(self.0);
		if val < base.0 {
			Time(val + 0x1_0000_0000)
		} else {
			Time(val)
		}
	}
}

impl Ord for WrapTime {
	fn cmp(&self, other: &Self) -> Ordering {
		(self.0.wrapping_sub(other.0) as i32).cmp(&0)
	}
}

impl PartialOrd for WrapTime {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

// Internal timer key for queue
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct TimerKey {
	time: WrapTime,
	// Has a `VarSlot` for slot < 0x8000_0000, else this is just a
	// number to make the key unique
	slot: u32,
}

impl TimerKey {
	fn new(time: WrapTime, slot: u32) -> Self {
		assert_eq!(8, std::mem::size_of::<TimerKey>());
		Self { time, slot }
	}
}

impl Ord for TimerKey {
	fn cmp(&self, other: &Self) -> Ordering {
		self.time.cmp(&other.time).then_with(|| self.slot.cmp(&other.slot))
	}
}

impl PartialOrd for TimerKey {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

// Variable-expiry timer: either min or max timer
struct VarTimer {
	// Target expiry time
	expiry: Time,
	// Current timer expiry
	curr: Time,
}

enum VarItem {
	Max(VarTimer),
	Free(Option<u32>), // Free slot with link to next
}

struct VarSlot {
	gen: u32, // Generation, incremented on delete
	item: VarItem,
}

pub(crate) type BoxedFnOnce<A> = Box<dyn FnOnce(&mut A, &mut Core<A>) + Send + 'static>;

// Timers
pub(crate) struct Timers<A> {
	// Base time against which all other times are measured
	pub t0: Instant,
	// The last `now` value we were given, relative to `t0`.  All
	// times in the `queue` will be within ~9 hours of this time.
	now: Time,
	// Stores all timers waiting to run, in order
	queue: BTreeMap<TimerKey, BoxedFnOnce<A>>,
	// Fixed timers don't use a slot, but max/min timers do
	var: Vec<VarSlot>,
	// First free slot in `var`, or None
	var_free: Option<u32>,
	// Sequential number used for `slot` values >= 0x8000_0000
	seq: u32,
}

impl<S> Timers<S> {
	pub(crate) fn new(now: Instant) -> Self {
		Self {
			t0: now,
			now: Time(0),
			queue: BTreeMap::new(),
			var: Vec::new(),
			var_free: None,
			seq: 0,
		}
	}

	/// Get the time that the next timer will expire, if there is one
	pub(crate) fn next_expiry(&self) -> Option<Instant> {
		self.queue.iter().next().map(|(tk, _)| tk.time.time(self.now).instant(self.t0))
	}

	/// Advance 'now' to a new value, expiring timers to the provided
	/// queue
	pub(crate) fn advance(cx: &mut Core<S>, app: &mut S, now: Instant) {
		let target_now = Time::new_floor(now, cx.timers.t0);
		while cx.timers.now < target_now {
			// Advance in steps of max 0x7FFF seconds to avoid
			// skipping timers in the queue
			cx.timers.now = cx.timers.now.add_secs(0x7FFF).min(target_now);
			let key = cx.timers.now.wt();

			while let Some(next) = cx.timers.queue.first_entry() {
				if next.key().time > key {
					break;
				}

				let (key, bfn) = next.remove_entry();

				if key.slot >= 0x8000_0000 {
					// Fixed timer
					bfn(app, cx);
					continue;
				}
				let slot = &mut cx.timers.var[key.slot as usize];
				match slot.item {
					VarItem::Max(ref mut vt) => {
						if vt.expiry <= target_now {
							cx.timers.free_slot(key.slot);
							bfn(app, cx);
						} else {
							// Set time to current expiry time
							vt.curr = vt.expiry.min(cx.timers.now.add_secs(0x7FFF));
							cx.timers.queue.insert(TimerKey::new(vt.curr.wt(), key.slot), bfn);
						}
					}
					VarItem::Free(_) => panic!("TimerKey points to a free slot"),
				}
			}
		}
	}

	fn alloc_slot(&mut self, item: VarItem) -> (u32, u32) {
		if let Some(i) = self.var_free {
			let slot = &mut self.var[i as usize];
			match slot.item {
				VarItem::Free(next) => self.var_free = next,
				_ => panic!("Timers: var_free pointed to slot that wasn't free"),
			};
			slot.item = item;
			(i, slot.gen)
		} else {
			let i = self.var.len();
			if i >= 0x8000_0000 {
				panic!("Exceeded 2^31 variable timers at the same time");
			}
			// Start at gen==1 so that `Default` on keys doesn't match
			// anything
			self.var.push(VarSlot { gen: 1, item });
			(i as u32, 1)
		}
	}

	fn free_slot(&mut self, i: u32) {
		let slot = &mut self.var[i as usize];
		slot.gen = slot.gen.wrapping_add(1).max(1); // Avoid gen==0, reserved for Default
		if let VarItem::Free(_) = slot.item {
			panic!("Timers: deleting slot that was already free");
		}
		slot.item = VarItem::Free(self.var_free);
		self.var_free = Some(i);
	}

	// Add a fixed timer.  A fixed timer can only expire or be
	// deleted.
	pub(crate) fn add(&mut self, expiry_time: Instant, bfn: BoxedFnOnce<S>) -> FixedTimerKey {
		// We must never add a timer with exactly self.now, because
		// code won't run to advance time unless the time changes
		let expiry = Time::new_ceil(expiry_time, self.t0).max(self.now.inc());
		if expiry >= self.now.add_secs(0x7FFF) {
			// Add it as a var-timer, so it will keep rescheduling
			// itself until it reaches the target time
			let mk = self.add_max(expiry_time, bfn);
			return FixedTimerKey { slot: mk.slot, gen_or_time: mk.gen };
		}

		// Collision should be very unlikely in actual use, since we
		// have 2^31 unique values per 15us instant, and we cycle
		// constantly, so the next caller will get a different unique
		// value.  Almost always the first attempt will succeed.
		// Otherwise we try all the 2^31 slots for this instant, then
		// try the next instant and so on.  This must succeed, because
		// the address space is not big enough to contain 2^63 active
		// timers, so there will always be a slot free somewhere.
		let mut wt = expiry.wt();
		loop {
			for _ in 0..0x8000_0000u32 {
				self.seq = self.seq.wrapping_add(1);
				let slot = self.seq | 0x8000_0000;
				if let Entry::Vacant(ent) = self.queue.entry(TimerKey::new(wt, slot)) {
					ent.insert(bfn);
					return FixedTimerKey { slot, gen_or_time: wt.0 };
				}
			}
			wt.0 = wt.0.wrapping_add(1);
		}
	}

	/// Returns whether a timer exists.
	pub(crate) fn is_active(&self, fk: FixedTimerKey) -> bool {
		if fk.slot < 0x8000_0000 {
			self.max_is_active(MaxTimerKey { slot: fk.slot, gen: fk.gen_or_time })
		} else {
			self.queue.contains_key(&TimerKey::new(WrapTime(fk.gen_or_time), fk.slot))
		}
	}

	// Delete a fixed timer.  Returns: true: success, false: timer no
	// longer exists (i.e. it expired or was deleted)
	pub(crate) fn del(&mut self, fk: FixedTimerKey) -> bool {
		if fk.slot < 0x8000_0000 {
			self.del_max(MaxTimerKey { slot: fk.slot, gen: fk.gen_or_time })
		} else {
			self.queue.remove(&TimerKey::new(WrapTime(fk.gen_or_time), fk.slot)).is_some()
		}
	}

	// Add a Max timer, which expires at the greatest (latest) expiry
	// time it has been given.  A Max timer allows its expiry time to
	// be modified efficiently after creation, without having to
	// insert or delete timers from the queue, so the `mod_max` method
	// can be called frequently.
	//
	// When the expiry time is changed to be further in the future,
	// the new value is stored but the old timer remains active in the
	// queue.  A new timer is set only when the old timer expires.
	pub(crate) fn add_max(&mut self, expiry_time: Instant, bfn: BoxedFnOnce<S>) -> MaxTimerKey {
		let expiry = Time::new_ceil(expiry_time, self.t0);
		let curr = expiry.max(self.now.inc()).min(self.now.add_secs(0x7FFF));
		let (slot, gen) = self.alloc_slot(VarItem::Max(VarTimer { expiry, curr }));
		self.queue.insert(TimerKey::new(curr.wt(), slot), bfn);
		MaxTimerKey { slot, gen }
	}

	/// Modify a Max timer.  This is a quick operation.  Returns:
	/// true: success, false: timer no longer exists (i.e. it expired
	/// or was deleted or never existed)
	pub(crate) fn mod_max(&mut self, mk: MaxTimerKey, expiry_time: Instant) -> bool {
		if let Some(slot) = self.var.get_mut(mk.slot as usize) {
			if slot.gen == mk.gen {
				if let VarItem::Max(ref mut vt) = slot.item {
					let expiry = Time::new_ceil(expiry_time, self.t0);
					vt.expiry = vt.expiry.max(expiry);
					return true;
				}
			}
		}
		false
	}

	/// Delete a Max timer.  Returns: true: success, false: timer no
	/// longer exists (i.e. it expired or was deleted)
	pub(crate) fn del_max(&mut self, mk: MaxTimerKey) -> bool {
		if let Some(slot) = self.var.get_mut(mk.slot as usize) {
			if slot.gen == mk.gen {
				if let VarItem::Max(ref mut vt) = slot.item {
					self.queue.remove(&TimerKey::new(vt.curr.wt(), mk.slot));
					self.free_slot(mk.slot);
					return true;
				}
			}
		}
		false
	}

	// Check whether a max timer is still active
	pub(crate) fn max_is_active(&self, mk: MaxTimerKey) -> bool {
		if let Some(slot) = self.var.get(mk.slot as usize) {
			slot.gen == mk.gen
		} else {
			false
		}
	}

	// Clears the timers.
	pub fn clear(&mut self) {
		// Note: we do not clear the vartimers here,
		// since they may be being processed right now.
		self.queue.clear();
	}
}
