use utils::{bytes::Cast, endian::{BigEndian, u16be, u32be, u64be}};
use bilge::prelude::*;


#[bitsize(16)]
struct Control {
	/// No more data from sender.
	fin: bool,
	/// Synchronize sequence numbers.
	syn: bool,
	/// Reset the connection.
	rst: bool,
	/// Push function (see the Send Call description in Section 3.9.1).
	psh: bool,
	/// Acknowledgment field is significant.
	ack: bool,
	/// Urgent pointer field is significant.
	urg: bool,
	/// ECN-Echo.
	ece: bool,
	/// Congestion Window Reduced.
	cwr: bool,
	/// A set of control bits reserved for future use. Must be zero in generated segments and must be ignored in received segments if the corresponding future features are not implemented by the sending or receiving host.
	reserved: u4,
	/// The number of 32-bit words in the TCP header. This indicates where the data begins. The TCP header (even one including options) is an integer multiple of 32 bits long.
	off: u4,
}

#[derive(Cast)]
#[repr(C)]
struct Header {
	/// The source port number.
	src: u16be,
	/// The destination port number.
	dst: u16be,
	/// The sequence number of the first data octet in this segment (except when the SYN flag is set). If SYN is set, the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1.
	seq: u32be,
	/// If the ACK control bit is set, this field contains the value of the next sequence number the sender of the segment is expecting to receive. Once a connection is established, this is always sent.
	ack: u32be,
	/// The control bits, also known as "flags".
	ctl: BigEndian<Control>,
	/// The number of data octets beginning with the one indicated in the acknowledgment field that the sender of this segment is willing to accept. The value is shifted when the window scaling extension is used [47]. The window size MUST be treated as an unsigned number, or else large window sizes will appear like negative windows and TCP will not work (MUST-1). It is RECOMMENDED that implementations will reserve 32-bit fields for the send and receive window sizes in the connection record and do all window computations with 32 bits (REC-1).
	win: u64be,
// The checksum field is the 16-bit ones' complement of the ones' complement sum of all 16-bit words in the header and text.
	csm: u16be,
	/// This field communicates the current value of the urgent pointer as a positive offset from the sequence number in this segment. The urgent pointer points to the sequence number of the octet following the urgent data. This field is only to be interpreted in segments with the URG control bit set.
	urg: u16be
}

pub(crate) struct Interface {}

impl Default for Interface {
	fn default() -> Self {
		Self {}
	}
}
