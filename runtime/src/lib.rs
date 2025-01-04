extern crate alloc;

use alloc::collections::VecDeque;
use core::time::Duration;
use std::io::{self, ErrorKind};

use collections::bytes::{Cursor, Slice};
use log::error;
use stakker::Core;

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
	let r = unsafe { sys::recv(fd, buf.as_ptr() as *mut BufType, buf.len() as _, 0) };

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

	/// Total number of poll calls
	poll: u64,
	/// Total number of socket reads
	read: u64,
	/// Total poll wait time
	wait: Duration,
	/// Total execution time
	exec: Duration,
	/// Total requested timeout duration
	tout: Duration,
}

impl<A: App + 'static> State<A> {
	fn new() -> Self {
		Self {
			fds: Vec::new(),
			entries: Vec::new(),

			poll: 0,
			read: 0,
			wait: Duration::ZERO,
			exec: Duration::ZERO,
			tout: Duration::ZERO,
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

	/// Polls I/O, returning the number of file descriptors for which events have occurred.
	fn poll(&mut self, timeout: Option<Duration>) -> Result<u32> {
		self.poll += 1;

		unsafe {
			poll(
				self.fds.as_mut_ptr(),
				self.fds.len().try_into().expect("Fewer than u32::MAX fds"),
				as_timeout(timeout),
			)
		}
		.try_into()
		.map_err(|_| error!("poll() failed: {}", io::Error::last_os_error()))
	}

	/// Execute I/O callbacks, returning whether any I/O reads occurred.
	fn execute(app: &mut A, cx: &mut Core<A>, mut pending: u32) -> Result<bool> {
		let mut this = app.io();
		let mut read = 0;

		for idx in 0.. {
			if pending == 0 {
				break;
			}

			let &mut Poll { fd, revents, ref mut events } = &mut this.fds[idx];
			let mut entry = &mut this.entries[idx];

			if revents == 0 {
				continue;
			}

			assert!(revents & POLLERR == 0, "socket error");
			assert!(revents & POLLHUP == 0, "socket hangup");
			assert!(revents & POLLNVAL == 0, "socket invalid");

			if revents & POLLOUT != 0 {
				if entry.flush_write(fd)? {
					*events = POLLIN;
				}
			}

			if revents & POLLIN != 0 {
				let mut cb = entry.cb.take().unwrap();

				Entry::flush_read(&mut cb, app, cx, fd, &mut read)?;

				this = app.io();
				entry = &mut this.entries[idx];

				entry.cb = Some(cb);
			}

			this.fds[idx].revents = 0;

			pending -= 1;
		}

		this.read += read;

		Ok(read == 0)
	}
}

impl<A> Drop for State<A> {
	fn drop(&mut self) {
		log::info!("Average socket reads per I/O poll: {:.2}", self.read as f64 / self.poll as f64);
		log::info!("Average poll wait time: {:.2}us", self.wait.as_micros() as f64 / self.poll as f64);
		log::info!("Average runtime tick time: {:.2}us", self.exec.as_micros() as f64 / self.poll as f64);
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

	fn flush_write(&mut self, fd: RawFd) -> Result<bool> {
		assert!(!self.queue.is_empty());

		loop {
			let Some(buf) = self.queue.back_mut() else { return Ok(true) };

			if !send(fd, buf)? {
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
