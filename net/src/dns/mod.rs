use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use std::collections::{hash_map, HashMap};

use bilge::prelude::*;
use collections::bytes::Slice;
use log::{info, warn};
use rand::Rng;
use stakker::{fwd_to, Actor, FixedTimerKey, Ret, CX};
use utils::bytes::Cast;
use utils::endian::{u16be, u32be, BigEndian};

use crate::ip::SocketAddr;
use crate::udp;

const TIMEOUT: Duration = Duration::from_secs(10);

const TY_A: u16 = 1;
const CLASS_IN: u16 = 1;

struct Entry {
	/// The callback for the resolved IP address
	ret: Ret<Ipv4Addr>,
	/// The timer key of the retry callback for this request
	retry: FixedTimerKey,
	/// The DNS server that was queried
	server: IpAddr,
}

pub struct Resolver {
	/// The UDP socket for DNS
	socket: udp::Socket,
	/// The address of the primary DNS server
	primary: IpAddr,
	/// In-flight DNS requests and their corresponding callbacks
	in_flight: HashMap<u16, Entry>,
}

impl Resolver {
	pub fn init(cx: CX![], net: Actor<super::Interface>, addr: IpAddr) -> Option<Self> {
		let actor = cx.access_actor().clone();

		cx.defer(move |s| {
			net.apply(s, move |n, c| {
				let socket = udp::Socket::bind_eph(n, c, fwd_to!([actor], process() as (SocketAddr, Slice)));

				c.defer(move |s| actor.apply_prep(s, move |_| Some(Self { socket, primary: addr, in_flight: HashMap::new() })))
			})
		});

		None
	}

	pub fn v4(&mut self, cx: CX![], name: impl Into<String>, ret: Ret<Ipv4Addr>) {
		self.v4_with(cx, name, self.primary, ret)
	}

	pub fn v4_with(&mut self, cx: CX![], name: impl Into<String>, server: IpAddr, ret: Ret<Ipv4Addr>) {
		let id = self.gen_id();
		let retry = self.query(cx, id, server, name.into());
		self.in_flight.insert(id, Entry { ret, server, retry });
	}

	fn gen_id(&mut self) -> u16 {
		let mut rng = rand::thread_rng();
		let mut id = rng.gen();

		while self.in_flight.contains_key(&id) {
			id = rng.gen();
		}

		id
	}

	fn query(&mut self, cx: CX![], id: u16, server: IpAddr, name: String) -> FixedTimerKey {
		info!("Querying DNS server {} for {} (0x{:x})", server, name, id);

		let n = name.clone();

		// Query port 53 of the server
		self.socket.write(SocketAddr { addr: server, port: 53 }, move |buf| {
			let (header, mut buf): (&mut Header, _) = buf.split();

			// ID from parameters so that it can be duplicated between requests
			header.id = id;

			// Generic query flags
			header.flags = Flags::new(Rcode::Ok, u3::new(0), false, true, false, false, Opcode::Query, false).into();

			// Asking one question, with no resource records
			header.qdcount = 1.into();
			header.ancount = 0.into();
			header.nscount = 0.into();
			header.arcount = 0.into();

			for name in n.split(".") {
				let bytes = name.as_bytes();

				assert!(bytes.len() <= 63);

				let len: u8 = bytes.len() as _;

				// Append a length octet
				buf = buf.push(&len);
				// Push the name bytes
				buf = buf.push(bytes);
			}

			// Zero-length root label for name
			buf = buf.push(&0u8);

			// Domain names must be less than or equal to 255 octets
			assert!(buf.pivot() <= 255);

			// QTYPE
			buf = buf.push(&BigEndian::from(TY_A));

			// QCLASS
			buf.push(&BigEndian::from(CLASS_IN));
		});

		let actor = cx.access_actor().clone();

		cx.after(TIMEOUT, move |s| {
			actor.apply(s, move |dns, cx| {
				warn!("DNS resolution for {name} timed out. Retrying...");

				let server = dns.in_flight[&id].server;

				// Retry the query
				let retry = dns.query(cx, id, server, name);
				// Set the new retry timer key
				dns.in_flight.get_mut(&id).unwrap().retry = retry;
			})
		})
	}

	fn process(&mut self, cx: CX![], src: SocketAddr, buf: Slice) {
		let header: &Header = buf.split();

		info!("Recieved DNS response for 0x{:x}", header.id);

		let entry = match self.in_flight.entry(header.id) {
			hash_map::Entry::Occupied(entry) if entry.get().server == src.addr => entry,
			_ => {
				warn!("No in-flight request corresponding to DNS request");
				return;
			}
		};

		let flags = header.flags.get();

		assert!(flags.qr());

		// Expect there to be one resource record, which corresponds to an answer
		assert!(header.qdcount.get() == 1);
		assert!(header.ancount.get() == 1);
		assert!(header.nscount.get() == 0);
		assert!(header.arcount.get() == 0);

		macro_rules! skip_name {
			() => {
				loop {
					let len: u8 = *buf.split();

					match len >> 6 {
						// The octet is a length. Skip the number of bytes of its value.
						0b00 => {}
						// The octet is a pointer. Skip the second byte of the pointer.
						0b11 => {
							let _: &u8 = buf.split();
							break;
						}
						_ => unimplemented!(),
					}

					if len == 0 {
						break;
					}

					buf.split_bytes(len as _);
				}
			};
		}

		// Skip QD
		skip_name!();
		buf.split_bytes(4);

		// Skip RNAME
		skip_name!();

		let rr: &RR = buf.split();

		assert!(rr.ty.get() == TY_A);
		assert!(rr.class.get() == CLASS_IN);
		assert!(rr.rdlength.get() == 4);

		let addr: &Ipv4Addr = buf.split();

		log::info!("Resolved to {}", addr);

		let Entry { ret, retry, .. } = entry.remove();

		// Call the callback
		ret.ret(*addr);
		// Cancel the retry timer, since the request has been resolved
		cx.timer_del(retry);
	}
}

#[bitsize(4)]
#[derive(FromBits)]
enum Opcode {
	/// a standard query
	Query = 0,
	/// an inverse query
	IQuery = 1,
	/// a server status request
	Status = 2,
	/// reserved
	#[fallback]
	Reserved,
}

#[bitsize(4)]
#[derive(FromBits)]
enum Rcode {
	/// No error condition
	Ok = 0,
	/// Format error - The name server was unable to interpret the query.
	FormatErr = 1,
	/// Server failure - The name server was unable to process this query due to a problem with the name server.
	ServerFailure = 2,
	/// Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	NameErr = 3,
	/// Not Implemented - The name server does not support the requested kind of query.
	NotImplemented = 4,
	/// Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
	Refused = 5,
	/// Reserved
	#[fallback]
	Reserved,
}

#[bitsize(16)]
#[derive(FromBits)]
struct Flags {
	/// Response code - this 4 bit field is set as part of responses.
	rcode: Rcode,
	/// Reserved for future use.  Must be zero in all queries and responses.
	z: u3,
	/// Recursion Available - this bit is set or cleared in a response, and denotes whether recursive query support is available in the name server.
	ra: bool,
	/// Recursion Desired - this bit may be set in a query and is copied into the response. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
	rd: bool,
	/// TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
	tc: bool,
	///  Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.
	/// Note that the contents of the answer section may have multiple owner names because of aliases.  The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
	aa: bool,
	/// A four bit field that specifies kind of query in this message.  This value is set by the originator of a query and copied into the response.
	opcode: Opcode,
	/// A one bit field that specifies whether this message is a query (0), or a response (1).
	qr: bool,
}

/// The header section is always present.  The header includes fields that specify which of the remaining sections are present, and also specify whether the message is a query or a response, a standard query or some other opcode, etc.
#[derive(Cast)]
#[repr(C)]
struct Header {
	/// A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester  to match up replies to outstanding queries.
	id: u16,
	/// The bitfields of the next two bytes
	flags: BigEndian<Flags>,
	/// an unsigned 16 bit integer specifying the number of entries in the question section.
	qdcount: u16be,
	/// an unsigned 16 bit integer specifying the number of resource records in the answer section.
	ancount: u16be,
	/// an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
	nscount: u16be,
	/// an unsigned 16 bit integer specifying the number of resource records in the additional records section.
	arcount: u16be,
}

#[derive(Cast)]
#[repr(C)]
struct RR {
	/// two octets containing one of the RR type codes. This field specifies the meaning of the data in the RDATA field.
	ty: u16be,
	// two octets which specify the class of the data in the RDATA field.
	class: u16be,
	/// a 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.  Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
	ttl: u32be,
	/// an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
	rdlength: u16be,
}
