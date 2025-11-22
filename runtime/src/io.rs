use alloc::collections::VecDeque;
use core::time::Duration;
use std::io::{self, ErrorKind};
use std::mem;

use collections::bytes::{Buf, Slice};
use log::error;

use crate::Core;

#[cfg(target_family = "unix")]
mod sys {
	pub use std::os::fd::{AsRawFd, RawFd};

	pub use libc::{recv, send, c_void as BufType, poll, pollfd as Poll, ENOBUFS, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT};

	pub fn as_raw<T: AsRawFd>(t: &T) -> RawFd {
		t.as_raw_fd()
	}
}

#[cfg(target_family = "windows")]
mod sys {
	pub use std::os::windows::io::AsRawSocket as AsRawFd;

	pub use u8 as BufType;
	pub use windows_sys::Win32::Networking::WinSock::{
		recv, send, WSAPoll as poll, WSAPOLLFD as Poll, WSAENOBUFS as ENOBUFS, POLLERR, POLLHUP, POLLRDNORM as POLLIN, POLLNVAL, POLLWRNORM as POLLOUT, SOCKET as RawFd,
	};

	pub fn as_raw<T: AsRawFd>(t: &T) -> RawFd {
		t.as_raw_socket() as _
	}
}

pub use sys::AsRawFd;
use sys::*;
use utils::error::*;

fn as_timeout(t: Option<Duration>) -> i32 {
	t.and_then(|d| d.as_millis().try_into().ok()).unwrap_or(-1)
}

fn ret_to_err(val: isize) -> Result<Option<usize>> {
	match TryInto::<usize>::try_into(val) {
		Ok(n) => Ok(Some(n)),
		Err(_) => {
			let err = io::Error::last_os_error();
			let os = err.raw_os_error().unwrap();

			if matches!(err.kind(), ErrorKind::WouldBlock) || os == ENOBUFS {
				return Ok(None);
			}

			error!("I/O operation failed: {err}, kind={:?}", err.kind());
			Err(())
		}
	}
}

fn send(fd: RawFd, buf: &[u8]) -> Result<bool> {
	let r = unsafe { sys::send(fd, buf.as_ptr() as *mut BufType, buf.len() as _, 0) };

	if let Some(n) = ret_to_err(r as _)? {
		if n != buf.len() {
			error!("Only sent {}/{} bytes to socket", n, buf.len());
			return Err(());
		}

		Ok(true)
	} else {
		Ok(false)
	}
}

fn recv(fd: RawFd, buf: &mut Slice) -> Result<bool> {
	let r = unsafe { sys::recv(fd, buf.as_ptr() as *mut BufType, buf.len() as _, 0) };

	if let Some(n) = ret_to_err(r as _)? {
		buf.truncate(n);
		Ok(true)
	} else {
		Ok(false)
	}
}

pub(crate) struct State<A> {
	fds: Vec<Poll>,
	entries: Vec<Entry<A>>,
	/// The number of I/O events available in `fds` since the last `poll`.
	pending: u32,

	/// Total number of poll calls
	pub poll: u64,
	/// Total number of socket reads
	read: u64,
	/// Total poll wait time
	pub wait: Duration,
	/// Total lock acquire wait time
	pub lock: Duration,
	/// Total execution time
	pub exec: Duration,
	/// Total requested timeout duration
	pub tout: Duration,
}

impl<A> State<A> {
	pub fn new() -> Self {
		Self {
			fds: Vec::new(),
			entries: Vec::new(),
			pending: 0,

			poll: 0,
			read: 0,
			wait: Duration::ZERO,
			lock: Duration::ZERO,
			exec: Duration::ZERO,
			tout: Duration::ZERO,
		}
	}

	fn idx_of<T: AsRawFd>(&mut self, socket: &T) -> usize {
		let raw = as_raw(socket);
		self.fds.iter().position(|f| f.fd == raw).expect("Socket is present")
	}

	/// Returns whether any more I/O is waiting.
	pub fn is_io(&self) -> bool {
		!self.fds.is_empty()
	}

	/// Polls I/O, returning the number of file descriptors for which events have occurred.
	pub fn poll(&mut self, timeout: Option<Duration>) -> Result {
		self.pending = unsafe {
			poll(
				self.fds.as_mut_ptr(),
				self.fds.len().try_into().expect("Fewer than u32::MAX fds"),
				as_timeout(timeout),
			)
		}
		.try_into()
		.map_err(|_| error!("poll() failed: {}", io::Error::last_os_error()))?;

		Ok(())
	}

	/// Execute I/O callbacks, returning whether any I/O reads occurred.
	pub fn execute(app: &mut A, cx: &mut Core<A>) -> bool {
		let mut read = 0;
		let mut idx = 0;

		// Search for requests as long as we know there are any pending.
		while cx.io.pending != 0 {
			// If we've reached the end of the `fds` list while there is still pending data,
			// then a reordering must have occurred, and we should restart.
			if idx > cx.io.fds.len() {
				idx = 0;
			}

			// Get the pollfd and entry metadata.
			let &mut Poll { fd, ref mut revents, ref mut events } = &mut cx.io.fds[idx];
			let entry = &mut cx.io.entries[idx];

			// If there were no events on this socket, continue.
			if *revents == 0 {
				// Grab the next index to process.
				idx += 1;
				continue;
			}

			// Otherwise, consume all event flags.
			let revents = mem::take(revents);
			// Reduce the number of pending requests.
			cx.io.pending -= 1;

			// Check for any errors.
			let mut err = revents & (POLLNVAL | POLLERR | POLLHUP) != 0;

			// If there were errors, log them.
			if err {
				if revents & POLLNVAL != 0 {
					log::error!("{fd}: socket invalid");
				}

				if revents & POLLERR != 0 {
					log::error!("{fd}: socket error");
				}

				if revents & POLLHUP != 0 {
					log::error!("{fd}: socket hangup");
				}
			// Otherwise, flush read and write queues.
			} else if revents & POLLOUT != 0 {
				match entry.flush_write(fd) {
					Ok(true) => *events = POLLIN,
					Ok(false) => {}
					Err(_) => err = true,
				}
			}

			// Grab the read callback.
			let mut cb = entry.cb.take().unwrap();
			// Check if an error occured.
			if err
				|| (
					// If an error didn't occur, check if there's data to read.
					revents & POLLIN != 0
					// If there is, flush the read queue, checking for errors.
					&& Entry::flush_read(&mut cb, app, cx, fd, &mut read).is_err()
				) {
				// If an error occured at any point, call the error callback.
				cb(app, cx, Err(()));
			}
			// Return the callback.
			match cx.io.entries.get_mut(idx) {
				// As long as the entry still exists and its callback is missing, we can return it.
				Some(Entry { cb: ref mut slot @ None, .. }) => *slot = Some(cb),
				// Otherwise, if the entry index is out of range, at least one socket has been deleted.
				_ => {
					// In case the current socket is not the one which has been deleted,
					// search through all entries to try to find one with a missing callback.
					if let Some(x) = cx.io.entries.iter_mut().find(|x| x.cb.is_none()) {
						// Insert the callback once we find its slot.
						x.cb = Some(cb);
					}
				}
			}

			// Grab the next index to process.
			idx += 1;
		}

		cx.io.read += read;

		read == 0
	}

	/// Clears all fds and pending socket events.
	pub fn clear(&mut self) {
		self.fds.clear();
		self.entries.clear();
		self.pending = 0;
	}
}

impl<A> Drop for State<A> {
	fn drop(&mut self) {
		log::info!("runtime statistics (average per poll):");
		log::info!("socket reads:     {:>10.2}  ", self.read as f64 / self.poll as f64);
		log::info!("poll wait time:   {:>10.2}us", self.wait.as_micros() as f64 / self.poll as f64);
		log::info!("lock acquisition: {:>10.2}us", self.lock.as_micros() as f64 / self.poll as f64);
		log::info!("execution time:   {:>10.2}us", self.exec.as_micros() as f64 / self.poll as f64);
		log::info!("poll timeout:     {:>10.2}us", self.tout.as_micros() as f64 / self.poll as f64);
	}
}

struct Entry<A> {
	cb: Option<Box<dyn FnMut(&mut A, &mut Core<A>, Result<Slice>) + Send>>,
	queue: VecDeque<Buf>,
}

impl<A> Entry<A> {
	fn flush_read(cb: &mut dyn FnMut(&mut A, &mut Core<A>, Result<Slice>), app: &mut A, cx: &mut Core<A>, fd: RawFd, ctr: &mut u64) -> Result {
		let mut buf = Slice::new(1500);

		while recv(fd, &mut buf)? {
			cb(app, cx, Ok(buf));
			*ctr += 1;

			buf = Slice::new(1500);
		}

		Ok(())
	}

	fn flush_write(&mut self, fd: RawFd) -> Result<bool> {
		assert!(!self.queue.is_empty());

		loop {
			let Some(buf) = self.queue.back_mut() else { return Ok(true) };

			if !send(fd, buf.filled())? {
				return Ok(false);
			}

			self.queue.pop_back();
		}
	}
}

pub struct Io<T: AsRawFd> {
	inner: T,
}

impl<T: AsRawFd> Io<T> {
	pub fn new<A>(cx: &mut Core<A>, inner: T, cb: Box<dyn FnMut(&mut A, &mut Core<A>, Result<Slice>) + Send>) -> Self {
		cx.io.fds.push(Poll { fd: as_raw(&inner), events: POLLIN, revents: 0 });
		cx.io.entries.push(Entry { cb: Some(cb), queue: VecDeque::new() });

		Self { inner }
	}

	pub fn buf(&self) -> Buf {
		// TODO: reuse these allocations by reclaiming them after write calls.
		Buf::zeroed(1500)
	}

	pub fn write<A>(&self, cx: &mut Core<A>, buf: Buf) -> Result {
		if !send(as_raw(&self.inner), buf.filled())? {
			let idx = cx.io.idx_of(&self.inner);
			cx.io.entries[idx].queue.push_front(buf);
			cx.io.fds[idx].events |= POLLOUT;
		}

		Ok(())
	}

	pub fn unbind<A>(self, cx: &mut Core<A>) {
		let idx = cx.io.idx_of(&self.inner);
		cx.io.entries.swap_remove(idx);
		cx.io.fds.swap_remove(idx);
	}
}
