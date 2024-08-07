use core::net::IpAddr;
use std::collections::{HashMap, VecDeque};
use std::ptr::NonNull;

use bilge::prelude::*;
use collections::bytes::Slice;
use utils::bytes::Cast;
use utils::endian::{u16be, u32be, u64be, BigEndian};
use utils::error::*;

use crate::ip::{SocketAddr, IP};

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
	urg: u16be,
}

enum OptKind {
	/// End of Option List Option. This option code indicates the end of the option list. This might not coincide with the end of the TCP header according to the Data Offset field. This is used at the end of all options, not the end of each option, and need only be used if the end of the options would not otherwise coincide with the end of the TCP header.
	EOL = 0,
	/// No-Operation. This option code can be used between options, for example, to align the beginning of a subsequent option on a word boundary.
	NOP = 1,
	/// Maximum Segment Size. If this option is present, then it communicates the maximum receive segment size at the TCP endpoint that sends this segment. This value is limited by the IP reassembly limit. This field may be sent in the initial connection request (i.e., in segments with the SYN control bit set) and must not be sent in other segments. If this option is not used, any segment size is allowed.
	MSS = 2,
}

/// The send sequence variables.
///
///          1         2          3          4
///     ----------|----------|----------|----------
///            SND.UNA    SND.NXT    SND.UNA
///                                 +SND.WND
///
/// 1. old sequence numbers that have been acknowledged
/// 2. sequence numbers of unacknowledged data
/// 3. sequence numbers allowed for new data transmission
/// 4. future sequence numbers that are not yet allowed
struct SndSeq {
	/// unacknowledged
	una: u32,
	/// next
	nxt: u32,
	/// window
	wnd: u32,
	/// urgent pointer
	up: u32,
	/// segment sequence number used for last window update
	wl1: u32,
	/// segment acknowledgment number used for last window update
	wl2: u32,
}

/// The recieve sequence variables.
///
///         1          2          3
///     ----------|----------|----------
///            RCV.NXT    RCV.NXT
///                      +RCV.WND
///
/// 1. old sequence numbers that have been acknowledged
/// 2. sequence numbers allowed for new reception
/// 3. future sequence numbers that are not yet allowed
struct RcvSeq {
	/// next
	nxt: u32,
	/// window
	wnd: u32,
	/// urgent pointer
	up: u32,
}

enum State {
	/// Represents waiting for a connection request from any remote TCP peer and port.
	Listen,
	/// Represents waiting for a matching connection request after having sent a connection request.
	SynSent,
	/// Represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.
	SynReceived,
	/// Represents an open connection, data received can be delivered to the user. The normal state for the data transfer phase of the connection.
	Established,
	/// Represents waiting for a connection termination request from the remote TCP peer, or an acknowledgment of the connection termination request previously sent.
	FinWait1,
	/// Represents waiting for a connection termination request from the remote TCP peer.
	FinWait2,
	/// Represents waiting for a connection termination request from the local user.
	CloseWait,
	/// Represents waiting for a connection termination request acknowledgment from the remote TCP peer.
	Closing,
	/// Represents waiting for an acknowledgment of the connection termination request previously sent to the remote TCP peer (this termination request sent to the remote TCP peer already included an acknowledgment of the termination request sent from the remote TCP peer).
	LastAck,
	/// Represents waiting for enough time to pass to be sure the remote TCP peer received the acknowledgment of its connection termination request and to avoid new connections being impacted by delayed segments from previous connections.
	TimeWait,
	/// Represents no connection state at all.
	Closed,
}

/// The identifying key for a TCB.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
	/// The local port of the connection, if any.
	port: Option<NonNull<u16>>,
	/// The remote IP address of the connection.
	addr: SocketAddr,
}

/// The Transmission Control Block, which holds state for a TCP connection.
struct TCB {
	/// The send buffer.
	send: VecDeque<Slice>,
	/// The retransmit queue.
	rexmit: (),
	/// The current segment.
	current: (),

	/// Send sequence variables.
	snd: SndSeq,
	/// initial send sequence number
	iss: u32,

	/// Recieve sequence variables.
	rcv: RcvSeq,
	/// initial receive sequence number
	irs: u32,
}

#[derive(Default)]
pub(crate) struct Interface {
	map: HashMap<Key, TCB>,
}

impl Interface {
	pub fn recv<'a>(&'a mut self, interface: &IP, addr: IpAddr, buf: Slice) -> Result {
		Err(())
	}
}
