extern crate alloc;

use alloc::collections::VecDeque;
use core::time::Duration;
use std::io::ErrorKind;

use collections::bytes::{Buf, Slice};
use log::error;

mod cx;
mod io;
mod logger;
mod rt;

pub use logger::init as log_init;

pub mod time;

pub use cx::*;
pub use io::*;
pub use rt::*;
