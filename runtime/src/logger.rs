use std::time::SystemTime;

use log::Level;
use nu_ansi_term::ansi::RESET;
use nu_ansi_term::{Color, Style};

pub struct Logger;

impl log::Log for Logger {
	fn enabled(&self, _: &log::Metadata) -> bool {
		true
	}

	fn log(&self, record: &log::Record) {
		let time = humantime::format_rfc3339_nanos(SystemTime::now());

		let dim = Style::new().dimmed().prefix();

		eprintln!(
			"{dim}{time}{RESET} {}{:5}{RESET} {}{}{RESET}{dim}:{RESET} {}",
			match record.level() {
				Level::Trace => Color::Purple,
				Level::Debug => Color::Blue,
				Level::Info => Color::Green,
				Level::Warn => Color::Yellow,
				Level::Error => Color::Red,
			}
			.bold()
			.prefix(),
			record.level(),
			Style::new().bold().prefix(),
			record.target(),
			record.args()
		);
	}

	fn flush(&self) {}
}
