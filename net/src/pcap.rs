//! https://wiki.wireshark.org/Development/LibpcapFileFormat

use alloc::rc::Rc;
use std::fs::File;
use std::io::{IoSlice, Read, Write};
use std::mem::size_of;
use std::time::{Duration, SystemTime};

use log::warn;
use runtime::time;
use stakker::CX;
use utils::bytes;
use utils::bytes::Cast;
use utils::error::*;

const SNAPLEN: u32 = u32::MAX;

#[derive(Clone)]
pub struct Writer {
	file: Rc<File>,
}

impl Writer {
	pub fn new(path: &str) -> Result<Self> {
		let file = File::create(path).map_err(|_| warn!("Unable to create pcap file"))?;
		let file = Rc::new(file);

		let header = Header {
			// 0xa1b23c4d for nanosecond-resolution files, 0xa1b2c3d4 for microsecond
			magic_number: 0xa1b23c4d,
			version_major: 2,
			version_minor: 4,
			thiszone: 0,
			sigfigs: 0,
			snaplen: SNAPLEN,
			network: Linktype::RAW,
		};

		(&*file)
			.write_all(bytes::as_slice(&header))
			.map_err(|_| warn!("Could not write header to file"))?;

		Ok(Self { file })
	}

	pub fn log(&self, cx: CX![super::Interface], packet: &[u8]) -> Result {
		let timestamp = time::system(cx)
			.duration_since(SystemTime::UNIX_EPOCH)
			.map_err(|_| warn!("Elapsed time since UNIX_EPOCH overflows"))?;

		let packet_len: u32 = packet.len().try_into().map_err(|_| warn!("Packet length is too large"))?;
		let incl_len: u32 = packet_len.min(SNAPLEN);

		let packet_header = PacketHeader {
			ts_sec: timestamp.as_secs().try_into().map_err(|_| warn!("Timestamp seconds overflows"))?,
			ts_usec: timestamp.subsec_nanos(),
			incl_len: packet_len.min(SNAPLEN),
			orig_len: packet_len,
		};

		(&*self.file)
			.write_all_vectored(&mut [IoSlice::new(bytes::as_slice(&packet_header)), IoSlice::new(&packet[..incl_len as usize])])
			.map_err(|err| warn!("Unable to write header to file: {err}"))?;

		Ok(())
	}
}

/// A PCAP consumer.
pub struct Reader {
	file: File,
	/// Whether the capture is nanosecond-resolution.
	nano: bool,
}

impl Reader {
	/// Construct a new reader and parse the header from a packet capture file.
	pub fn new(path: &str) -> Result<(Self, Linktype)> {
		let mut file = File::open(path).map_err(|_| warn!("Unable to open pcap file"))?;

		// Create a buffer for the header.
		let mut buf = [0; size_of::<Header>()];

		file.read_exact(&mut buf)
			.map_err(|e| log::error!("Could not read header from PCAP file: {e}"))?;

		let header: &Header = bytes::cast(&buf);

		let nano = match header.magic_number {
			// Microsecond little-endian
			0xa1b2c3d4 => false,
			// Nanosecond little-endian
			0xa1b23c4d => true,
			// Other
			n => {
				log::error!("Unsupported PCAP magic number: 0x{n:08X}");
				return Err(());
			}
		};

		if header.version_major != 2 || header.version_minor != 4 {
			log::error!(
				"Unsupported PCAP version: {}.{}, expected 2.4",
				header.version_major,
				header.version_minor
			);
			return Err(());
		}

		Ok((Self { file, nano }, header.network))
	}

	pub fn visit(mut self, mut f: impl FnMut(SystemTime, &[u8])) -> Result {
		let mut hdr_buf = [0; size_of::<PacketHeader>()];
		let mut buf = Vec::new();

		while self.file.read_exact(&mut hdr_buf).is_ok() {
			let header: &PacketHeader = bytes::cast(&hdr_buf);

			let time = SystemTime::UNIX_EPOCH
				+ Duration::from_secs(header.ts_sec as u64)
				+ if self.nano {
					Duration::from_nanos(header.ts_usec as u64)
				} else {
					Duration::from_micros(header.ts_usec as u64)
				};

			buf.resize(header.incl_len as usize, 0);

			self.file
				.read_exact(&mut buf)
				.map_err(|e| log::error!("Failed to read packet data from PCAP: {e}"))?;

			f(time, &buf)
		}

		Ok(())
	}
}

/// Data link type. See <https://www.tcpdump.org/linktypes.html>
#[derive(Cast, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Linktype(u32);

impl Linktype {
	/// Raw IP; the packet begins with an IPv4 or IPv6 header, with the version field of the header indicating whether it's an IPv4 or IPv6 header.
	pub const RAW: Self = Self(101);
}

#[derive(Cast)]
#[repr(C)]
struct Header {
	/// Used to detect the file format itself and the byte ordering. The writing application writes 0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the swapped 0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too.
	magic_number: u32,
	/// Major version number
	version_major: u16,
	/// Minor version number
	version_minor: u16,
	/// The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
	thiszone: i32,
	/// In theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0.
	sigfigs: u32,
	/// Max length of captured packets, in octets.
	snaplen: u32,
	/// Data link type. See <https://www.tcpdump.org/linktypes.html>
	network: Linktype,
}

#[derive(Cast)]
#[repr(C)]
struct PacketHeader {
	/// The date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from time.h to get this value, but you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.
	ts_sec: u32,
	/// ts_usec: in regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec. In nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as an offset to ts_sec This value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); in this case ts_sec must be increased instead!
	ts_usec: u32,
	// The number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.
	incl_len: u32,
	/// The length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.
	orig_len: u32,
}
