extern crate alloc;

use alloc::collections::VecDeque;
use stakker::Core;
use core::time::Duration;
use std::io::{self, ErrorKind};
use std::time::Instant;

use collections::bytes::{Cursor, Slice};
use log::error;

mod logger;
mod rt;

pub use logger::init as log_init;

pub mod time;

pub use rt::*;

#[cfg(target_family = "unix")]
mod sys {
	pub use std::os::fd::{AsRawFd, RawFd};

	pub use libc::{c_void as BufType, poll, pollfd as Poll, recv, send, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT};

	pub fn as_raw<T: AsRawFd>(t: &T) -> RawFd {
		t.as_raw_fd()
	}
}

#[cfg(target_family = "windows")]
mod sys {
	pub use std::os::windows::io::AsRawSocket as AsRawFd;

	pub use u8 as BufType;
	pub use windows_sys::Win32::Networking::WinSock::{
		recv, send, WSAPoll as poll, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM as POLLIN, POLLWRNORM as POLLOUT, SOCKET as RawFd, WSAPOLLFD as Poll,
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

			if matches!(err.kind(), ErrorKind::WouldBlock) {
				return Ok(None);
			}

			error!("I/O operation failed: {err}");
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
	let r = unsafe { sys::recv(fd, buf.as_mut_ptr() as *mut BufType, buf.len() as _, 0) };

	if let Some(n) = ret_to_err(r as _)? {
		buf.truncate(n);
		Ok(true)
	} else {
		Ok(false)
	}
}

pub struct State<A: 'static> {
	fds: Vec<Poll>,
	entries: Vec<Entry<A>>,

	/// The last poll call end timestamp
	prev: Option<Instant>,
	/// Total number of poll calls
	poll: u64,
	/// Total number of socket reads
	read: u64,
	/// Total poll wait time
	wait: Duration,
	/// Total Stakker run time
	tick: Duration,
	/// Total requested timeout duration
	tout: Duration,
}

impl<A: App + 'static> State<A> {
	fn new() -> Self {
		Self {
			fds: Vec::new(),
			entries: Vec::new(),

			prev: None,
			poll: 0,
			read: 0,
			wait: Duration::ZERO,
			tick: Duration::ZERO,
			tout: Duration::ZERO
		}
	}

	fn idx_of<T: AsRawFd>(&mut self, socket: &T) -> usize {
		let raw = as_raw(socket);
		self.fds.iter().position(|f| f.fd == raw).expect("Socket is present")
	}

	/// Returns whether any more I/O is waiting.
	fn is_io(&self) -> bool {
		!self.fds.is_empty()
	}

	/// Poll the fds. Returns whether any file descriptors are ready for I/O.
	fn poll(app: &mut A, cx: &mut Core<A>, timeout: Option<Duration>) -> Result<bool> {
		let t = Instant::now();

		let mut this = app.io();

		let ret = unsafe {
			poll(
				this.fds.as_mut_ptr(),
				this.fds.len().try_into().expect("Fewer than u32::MAX fds"),
				as_timeout(timeout),
			)
		};

		let e = Instant::now();

		let mut read = this.read;

		// Update statistics
		this.wait += e - t;

		if let Some(prev) = this.prev.replace(e) {
			this.tick += t - prev;
		}

		if let Some(timeout) = timeout {
			this.tout += timeout;
		}

		this.poll += 1;

		let mut pending: u32 = ret.try_into().map_err(|_| error!("poll() failed: {}", io::Error::last_os_error()))?;

		if pending == 0 {
			return Ok(false);
		}

		for idx in 0.. {
			let &mut Poll { fd, revents, .. } = &mut this.fds[idx];
			let mut entry = &mut this.entries[idx];

			if revents == 0 {
				continue;
			}

			if revents & POLLERR != 0 {
				panic!("Socket error while polling");
			}

			if revents & POLLHUP != 0 {
				panic!("Socket hangup");
			}

			if revents & POLLNVAL != 0 {
				panic!("Socket invalid");
			}

			if revents & POLLIN != 0 {
				let mut cb = entry.cb.take().unwrap();

				Entry::flush_read(&mut cb, app, cx, fd, &mut read)?;

				this = app.io();
				entry = &mut this.entries[idx];

				entry.cb = Some(cb);
			}

			if revents & POLLOUT != 0 {
				entry.flush_write(fd)?;
			};

			let Poll { events, revents, .. } = &mut this.fds[idx];

			*events = POLLIN;

			if !entry.queue.is_empty() {
				*events |= POLLOUT;
			}

			*revents = 0;

			pending -= 1;

			if pending == 0 {
				break;
			}
		}

		this.read = read;

		Ok(true)
	}

	pub fn log_stats(&self) {
		log::info!("Average socket reads per I/O poll: {:.2}", self.read as f64 / self.poll as f64);
		log::info!("Average poll wait time: {:.2}us", self.wait.as_micros() as f64 / self.poll as f64);
		log::info!("Average runtime tick time: {:.2}us", self.tick.as_micros() as f64 / self.poll as f64);
		log::info!("Average timeout: {:.2}us", self.tout.as_micros() as f64 / self.poll as f64);
	}
}

struct Entry<A: 'static> {
	cb: Option<Box<dyn FnMut(&mut A, &mut Core<A>, Slice)>>,
	queue: VecDeque<Box<[u8]>>,
}

impl<A> Entry<A> {
	fn flush_read(cb: &mut dyn FnMut(&mut A, &mut Core<A>, Slice), app: &mut A, cx: &mut Core<A>, fd: RawFd, ctr: &mut u64) -> Result {
		let mut buf = Slice::new(1500);

		while recv(fd, &mut buf)? {
			cb(app, cx, buf);
			*ctr += 1;

			buf = Slice::new(1500);
		}

		Ok(())
	}

	fn flush_write(&mut self, fd: RawFd) -> Result {
		assert!(!self.queue.is_empty());

		loop {
			let Some(buf) = self.queue.back_mut() else { return Ok(()) };

			if !send(fd, buf)? {
				return Ok(());
			}

			self.queue.pop_back();
		}
	}
}

pub struct Io<T: AsRawFd> {
	inner: T,
}

impl<T: AsRawFd> Io<T> {
	pub fn new<A: App>(state: &mut State<A>, inner: T, cb: Box<dyn FnMut(&mut A, &mut Core<A>, Slice)>) -> Self {
		state.fds.push(Poll { fd: as_raw(&inner), events: POLLIN, revents: 0 });
		state.entries.push(Entry { cb: Some(cb), queue: VecDeque::new() });

		Self { inner }
	}

	pub fn write<A: App, X>(&self, state: &mut State<A>, f: impl FnOnce(Cursor) -> X) -> Result<X> {
		let mut vec = vec![0; 1500];
		let res = Cursor::vec(&mut vec, f);

		if !send(as_raw(&self.inner), &mut vec)? {
			let idx = state.idx_of(&self.inner);
			state.entries[idx].queue.push_front(vec.into_boxed_slice());
			state.fds[idx].events |= POLLOUT;
		}

		Ok(res)
	}

	pub fn unbind<A: App>(self, state: &mut State<A>) {
		let idx = state.idx_of(&self.inner);
		state.entries.swap_remove(idx);
		state.fds.swap_remove(idx);
	}
}
