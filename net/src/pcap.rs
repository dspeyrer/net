//! https://wiki.wireshark.org/Development/LibpcapFileFormat

use alloc::rc::Rc;
use std::fs::File;
use std::io::{IoSlice, Write};
use std::time::SystemTime;

use log::warn;
use utils::error::*;
use utils::{bytes, time};

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
			// Raw IP; the packet begins with an IPv4 or IPv6 header, with the version field of the header indicating whether it's an IPv4 or IPv6 header.
			network: 101,
		};

		(&*file)
			.write_all(bytes::as_slice(&header))
			.map_err(|_| warn!("Could not write header to file"))?;

		Ok(Self { file })
	}

	pub fn log(&self, packet: &[u8]) -> Result {
		let timestamp = time::system()
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

#[derive(Cast)]
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
	network: u32,
}

#[derive(Cast)]
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
