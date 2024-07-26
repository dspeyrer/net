extern crate alloc;

use alloc::collections::VecDeque;
use core::cell::RefCell;
use core::time::Duration;
use std::io::{self, ErrorKind};

use collections::bytes::{Cursor, Slice};
use log::error;
use stakker::Fwd;

mod rt;
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

thread_local! {
	static GLOBAL: RefCell<State> = const {
		RefCell::new(State {
			fds: Vec::new(),
			entries: Vec::new()
		})
	};
}

struct State {
	fds: Vec<Poll>,
	entries: Vec<Entry>,
}

impl State {
	fn with<X, F: FnOnce(&mut Self) -> X>(f: F) -> X {
		GLOBAL.with(|x| f(&mut x.borrow_mut()))
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
	fn poll(&mut self, timeout: Option<Duration>) -> Result<bool> {
		let ret = unsafe {
			poll(
				self.fds.as_mut_ptr(),
				self.fds.len().try_into().expect("Fewer than u32::MAX fds"),
				as_timeout(timeout),
			)
		};

		let mut pending: u32 = ret.try_into().map_err(|_| error!("poll() failed: {}", io::Error::last_os_error()))?;

		if pending == 0 {
			return Ok(false);
		}

		for idx in 0.. {
			let Poll { fd, events, revents } = &mut self.fds[idx];
			let entry = &mut self.entries[idx];

			if *revents == 0 {
				continue;
			}

			if *revents & POLLERR != 0 {
				panic!("Socket error while polling");
			}

			if *revents & POLLHUP != 0 {
				panic!("Socket hangup");
			}

			if *revents & POLLNVAL != 0 {
				panic!("Socket invalid");
			}

			if *revents & POLLIN != 0 {
				entry.flush_read(*fd)?;
			}

			if *revents & POLLOUT != 0 {
				entry.flush_write(*fd)?;
			};

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

		Ok(true)
	}
}

struct Entry {
	fwd: Fwd<Slice>,
	queue: VecDeque<Box<[u8]>>,
}

impl Entry {
	fn flush_read(&mut self, fd: RawFd) -> Result {
		let mut buf = Slice::new(1500);

		while recv(fd, &mut buf)? {
			self.fwd.fwd(buf);
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
	pub fn new(inner: T, fwd: Fwd<Slice>) -> Self {
		State::with(|i| {
			i.fds.push(Poll { fd: as_raw(&inner), events: POLLIN, revents: 0 });

			i.entries.push(Entry { fwd, queue: VecDeque::new() });

			Self { inner }
		})
	}

	pub fn write<X>(&self, f: impl FnOnce(Cursor) -> X) -> Result<X> {
		let mut vec = vec![0; 1500];
		let res = Cursor::vec(&mut vec, f);

		if !send(as_raw(&self.inner), &mut vec)? {
			State::with(|i| {
				let idx = i.idx_of(&self.inner);
				i.entries[idx].queue.push_front(vec.into_boxed_slice());
				i.fds[idx].events |= POLLOUT;
			});
		}

		Ok(res)
	}
}

impl<T: AsRawFd> Drop for Io<T> {
	fn drop(&mut self) {
		State::with(|i| {
			let idx = i.idx_of(&self.inner);
			i.entries.swap_remove(idx);
			i.fds.swap_remove(idx);
		})
	}
}
