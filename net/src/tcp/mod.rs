use core::net::IpAddr;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::num::NonZero;
use std::ops::{Add, Sub};

use bilge::prelude::*;
use collections::bytes::Slice;
use runtime::Core;
use utils::bytes::{self, Cast};
use utils::endian::{u16be, u32be, u64be, BigEndian};

use crate::ip::Protocol::Tcp;
use crate::ip::{SocketAddr, ToS};
use crate::{App, IcmpErrorTy};

/// A fundamental notion in the design is that every octet of data sent over a TCP connection has a sequence number. Since every octet is sequenced, each of them can be acknowledged. The acknowledgment mechanism employed is cumulative so that an acknowledgment of sequence number X indicates that all octets up to but not including X have been received. This mechanism allows for straightforward duplicate detection in the presence of retransmission. The numbering scheme of octets within a segment is as follows: the first data octet immediately following the header is the lowest numbered, and the following octets are numbered consecutively.
///
/// It is essential to remember that the actual sequence number space is finite, though large. This space ranges from 0 to 232 - 1. Since the space is finite, all arithmetic dealing with sequence numbers must be performed modulo 232. This unsigned arithmetic preserves the relationship of sequence numbers as they cycle from 232 - 1 to 0 again. There are some subtleties to computer modulo arithmetic, so great care should be taken in programming the comparison of such values. The symbol "=<" means "less than or equal" (modulo 2^32).
#[derive(PartialEq, Eq, Clone, Copy)]
struct Seq(u32);

impl From<u32> for Seq {
	fn from(value: u32) -> Self {
		Self(value)
	}
}

impl Add<u32> for Seq {
	type Output = Self;

	fn add(self, rhs: u32) -> Self::Output {
		Self(self.0.wrapping_add(rhs))
	}
}

impl Sub<u32> for Seq {
	type Output = Self;

	fn sub(self, rhs: u32) -> Self::Output {
		Self(self.0.wrapping_sub(rhs))
	}
}

impl PartialOrd for Seq {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for Seq {
	fn cmp(&self, other: &Self) -> Ordering {
		// Find the wrapping difference between the two sequence numbers.
		match other.0.wrapping_sub(self.0) {
			// If the difference between the sequence numbers is more than half
			// the sequence space, then `self` must be greater than `other`.
			n if n > u32::MAX / 2 => Ordering::Greater,
			// If the difference is zero, then the sequence numbers are equal.
			0 => Ordering::Equal,
			// Otherwise, the sequence number is greater.
			_ => Ordering::Less,
		}
	}
}

#[bitsize(16)]
#[derive(FromBits)]
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
	csm: [u8; 2],
	/// This field communicates the current value of the urgent pointer as a positive offset from the sequence number in this segment. The urgent pointer points to the sequence number of the octet following the urgent data. This field is only to be interpreted in segments with the URG control bit set.
	urg: u16be,
}

const HEADER_BASE_OFF: u4 = u4::new((size_of::<Header>() / size_of::<u32>()) as u8);

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
	una: Seq,
	/// next
	nxt: Seq,
	/// window
	wnd: u32,
	/// urgent pointer
	up: Seq,
	/// segment sequence number used for last window update
	wl1: Seq,
	/// segment acknowledgment number used for last window update
	wl2: Seq,
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
	nxt: Seq,
	/// window
	wnd: u32,
	/// urgent pointer
	up: Seq,
}

#[derive(Clone, Copy)]
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
	port: Option<NonZero<u16>>,
	/// The remote IP address of the connection.
	addr: SocketAddr,
}

/// The Transmission Control Block, which holds state for a TCP connection.
struct TCB {
	/// The state of the TCB.
	state: State,
	/// The send buffer.
	send: VecDeque<Slice>,
	/// The retransmit queue.
	rexmit: (),
	/// The current segment.
	current: (),

	/// Send sequence variables.
	snd: SndSeq,
	/// initial send sequence number
	iss: Seq,

	/// Recieve sequence variables.
	rcv: RcvSeq,
	/// initial receive sequence number
	irs: Seq,
}

impl TCB {
	/// A new acknowledgment (called an "acceptable ack") is one for which the inequality holds: SND.UNA < SEG.ACK =< SND.NXT
	fn is_acceptable_ack(&self, seg_ack: Seq) -> bool {
		self.snd.una < seg_ack && seg_ack <= self.snd.nxt
	}

	/// Test the acceptability of a recieved segment.
	fn is_acceptable_seg(&self, seg_seq: Seq, seg_len: u32) -> bool {
		match (seg_len, self.rcv.wnd) {
			(0, 0) => seg_seq == self.rcv.nxt,
			(0, _) => self.rcv.nxt <= seg_seq && seg_seq < self.rcv.nxt + self.rcv.wnd,
			(_, 0) => false,
			(_, _) => {
				(self.rcv.nxt <= seg_seq && seg_seq < self.rcv.nxt + self.rcv.wnd)
					|| (self.rcv.nxt <= seg_seq + seg_len - 1 && seg_seq + seg_len - 1 < self.rcv.nxt + self.rcv.wnd)
			}
		}
	}

	/// Generate an initial sequence number.
	fn gen_isn<A>(&self, c: &mut Core<A>) -> Seq {
		todo!()
	}
}

#[derive(Default)]
pub(crate) struct Interface {
	map: HashMap<Key, TCB>,
}

impl<A: App> crate::Interface<A> {
	pub fn recv_tcp(app: &mut A, cx: &mut Core<A>, addr: IpAddr, tos: ToS, buf: Slice, icmp: Option<IcmpErrorTy>) {
		let net = app.net();

		if icmp.is_some() {
			return;
		}

		if buf.len() < size_of::<Header>() {
			return;
		}

		let packet = buf.split::<Header>();

		let src = SocketAddr { addr, port: packet.src.get() };

		let Some(dst) = NonZero::new(packet.dst.get()) else {
			log::warn!("Recieved packet addressed to TCP port 0");
			return;
		};

		let tcb = net.tcp.map.entry(Key { addr: src, port: Some(dst) });

		let state = match &tcb {
			Entry::Occupied(occupied) => occupied.get().state,
			Entry::Vacant(_) => State::Closed,
		};

		let ctl = packet.ctl.get();

		let data_len = buf.len() - ctl.off().value() as usize;

		match state {
			State::Closed => {
				// If the state is CLOSED (i.e., TCB does not exist), then all
				// data in the incoming segment is discarded.

				// An incoming segment containing a RST is discarded.
				if ctl.rst() {
					return;
				}

				let mut res = net.buf(Tcp, addr, tos);
				let mut cur = res.cursor();

				let hdr = cur.fork().cast::<Header>();

				hdr.src = packet.dst;
				hdr.dst = packet.src;

				hdr.win = 0.into();
				hdr.urg = 0.into();
				hdr.csm = [0; 2];

				let ack;

				// An incoming segment not containing a RST causes a RST to be
				// sent in response. The acknowledgment and sequence field
				// values are selected to make the reset sequence acceptable to
				// the TCP endpoint that sent the offending segment.
				if ctl.ack() {
					// If the ACK bit is on,
					// <SEQ=SEG.ACK><CTL=RST>
					hdr.seq = packet.ack;
					hdr.ack = 0.into();

					ack = false;
				} else {
					// If the ACK bit is off, sequence number zero is used,
					// <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
					hdr.seq = 0.into();
					hdr.ack = (packet.seq.get() + data_len as u32).into();

					ack = true;
				}

				hdr.ctl = Control::new(false, false, true, false, ack, false, false, false, HEADER_BASE_OFF).into();

				// Evaluate the checksum.
				let mut csm = net.ip.pseudo_checksum(Tcp, addr);

				let tcp_len = cur.pivot();

				csm.push(&tcp_len.to_be_bytes());
				csm.push(&cur[..tcp_len]);

				bytes::cast_mut::<Header, _>(&mut *cur).csm = csm.end();

				// Send the packet.
				net.write(cx, res);
			}
			_ => todo!(),
		}
	}
}
