//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

#![cfg_attr(feature = "benchmark", feature(test))]

pub mod packet;

use bytes::{Bytes, BytesMut};
use log::{debug, error, info, trace, warn};
use packet::*;
use pnet::packet::{Packet, tcp};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tun::Tun;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB
const DEFAULT_KEEPALIVE_INTERVAL: time::Duration = time::Duration::from_secs(15);
const DEFAULT_KEEPALIVE_MISSES: usize = 3;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, Connection>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<Tun>>,
    ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
    started: time::Instant,
    keepalive: KeepaliveConfig,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    ready: mpsc::Receiver<Socket>,
}

#[derive(Clone, Copy)]
pub struct KeepaliveConfig {
    pub interval: time::Duration,
    pub max_missed: usize,
}

impl KeepaliveConfig {
    pub fn disabled() -> KeepaliveConfig {
        KeepaliveConfig {
            interval: time::Duration::ZERO,
            max_missed: 0,
        }
    }

    fn is_enabled(self) -> bool {
        !self.interval.is_zero() && self.max_missed > 0
    }
}

impl Default for KeepaliveConfig {
    fn default() -> KeepaliveConfig {
        KeepaliveConfig {
            interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_missed: DEFAULT_KEEPALIVE_MISSES,
        }
    }
}

#[derive(Clone)]
struct Connection {
    incoming: flume::Sender<Bytes>,
    health: Arc<SocketHealth>,
}

struct SocketHealth {
    last_rx_ms: AtomicU64,
    closed: AtomicBool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<Tun>,
    incoming: flume::Receiver<Bytes>,
    health: Arc<SocketHealth>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: Arc<AtomicU32>,
    ack: Arc<AtomicU32>,
    last_ack: Arc<AtomicU32>,
    state: State,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn remove_tuple(&self, tuple: &AddrTuple) -> bool {
        let removed = self.tuples.write().unwrap().remove(tuple).is_some();
        let _ = self.tuples_purge.send(tuple.clone());
        removed
    }
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    fn new(
        shared: Arc<Shared>,
        tun: Arc<Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, Connection) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);
        let health = Arc::new(SocketHealth {
            last_rx_ms: AtomicU64::new(shared.now_ms()),
            closed: AtomicBool::new(false),
        });

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                health: health.clone(),
                local_addr,
                remote_addr,
                seq: Arc::new(AtomicU32::new(0)),
                ack: Arc::new(AtomicU32::new(ack.unwrap_or(0))),
                last_ack: Arc::new(AtomicU32::new(ack.unwrap_or(0))),
                state,
            },
            Connection {
                incoming: incoming_tx,
                health,
            },
        )
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        match self.state {
            State::Established => {
                if self.health.closed.load(Ordering::Relaxed) {
                    return None;
                }

                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                self.tun.send(&buf).await.ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        match self.state {
            State::Established => loop {
                let raw_buf = self.incoming.recv_async().await.ok()?;
                let res = {
                    let (_v4_packet, tcp_packet) = parse_ip_packet(&raw_buf).unwrap();

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        self.close();
                        return None;
                    }

                    self.health
                        .last_rx_ms
                        .store(self.shared.now_ms(), Ordering::Relaxed);

                    let payload = tcp_packet.payload();

                    if payload.is_empty() {
                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_sequence()
                                == self.ack.load(Ordering::Relaxed).wrapping_sub(1)
                        {
                            self.send_ack();
                        }

                        None
                    } else {
                        let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                        let last_ask = self.last_ack.load(Ordering::Relaxed);
                        self.ack.store(new_ack, Ordering::Relaxed);

                        if new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN {
                            let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                            if let Err(e) = self.tun.try_send(&buf) {
                                // This should not really happen as we have not sent anything for
                                // quite some time...
                                info!("Connection {} unable to send idling ACK back: {}", self, e)
                            }
                        }

                        buf[..payload.len()].copy_from_slice(payload);

                        Some(payload.len())
                    }
                };

                if let Some(size) = res {
                    return Some(size);
                }
            },
            _ => unreachable!(),
        }
    }

    fn send_ack(&self) {
        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
        if let Err(e) = self.tun.try_send(&buf) {
            debug!("Unable to send ACK to remote end: {}", e);
        }
    }

    fn send_keepalive_probe(
        tun: &Tun,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        seq: u32,
        ack: u32,
    ) -> Option<()> {
        let buf = build_tcp_packet(
            local_addr,
            remote_addr,
            seq.wrapping_sub(1),
            ack,
            tcp::TcpFlags::ACK,
            None,
        );

        tun.try_send(&buf).ok().and(Some(()))
    }

    fn start_keepalive(&self) {
        if !self.shared.keepalive.is_enabled() {
            return;
        }

        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        let shared = self.shared.clone();
        let tun = self.tun.clone();
        let health = self.health.clone();
        let seq = self.seq.clone();
        let ack = self.ack.clone();
        let local_addr = self.local_addr;
        let remote_addr = self.remote_addr;
        let keepalive = shared.keepalive;

        tokio::spawn(async move {
            let mut last_seen = health.last_rx_ms.load(Ordering::Relaxed);
            let mut missed = 0usize;

            loop {
                time::sleep(keepalive.interval).await;

                if health.closed.load(Ordering::Relaxed) {
                    return;
                }

                let current_seen = health.last_rx_ms.load(Ordering::Relaxed);
                if current_seen != last_seen {
                    last_seen = current_seen;
                    missed = 0;
                    continue;
                }

                if missed >= keepalive.max_missed {
                    info!(
                        "Connection from {} to {} timed out after {} missed keepalive probes",
                        local_addr, remote_addr, missed
                    );
                    health.closed.store(true, Ordering::Relaxed);
                    shared.remove_tuple(&tuple);
                    return;
                }

                missed += 1;
                if Socket::send_keepalive_probe(
                    &tun,
                    local_addr,
                    remote_addr,
                    seq.load(Ordering::Relaxed),
                    ack.load(Ordering::Relaxed),
                )
                .is_none()
                {
                    warn!(
                        "Unable to send keepalive probe from {} to {}",
                        local_addr, remote_addr
                    );
                    health.closed.store(true, Ordering::Relaxed);
                    shared.remove_tuple(&tuple);
                    return;
                }
            }
        });
    }

    fn close(&self) {
        self.health.closed.store(true, Ordering::Relaxed);
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        self.shared.remove_tuple(&tuple);
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
                    if let Ok(buf) = res {
                        let buf = buf.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.seq.load(Ordering::Relaxed) + 1
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
                            self.state = State::Established;
                            self.start_keepalive();

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            if let Err(e) = ready.send(self).await {
                                error!("Unable to send accepted socket to ready queue: {}", e);
                            }
                            return;
                        }
                    } else {
                        info!("Waiting for client ACK timed out");
                        self.state = State::Idle;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) -> Option<()> {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return None;
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK
                                && tcp_packet.get_acknowledgement()
                                    == self.seq.load(Ordering::Relaxed) + 1
                            {
                                // found our SYN + ACK
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack
                                    .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                self.tun.send(&buf).await.unwrap();

                                self.state = State::Established;
                                self.start_keepalive();

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        let removed = self.shared.remove_tuple(&tuple);

        if !self.health.closed.swap(true, Ordering::Relaxed) && removed {
            let buf = build_tcp_packet(
                self.local_addr,
                self.remote_addr,
                self.seq.load(Ordering::Relaxed),
                0,
                tcp::TcpFlags::RST,
                None,
            );
            if let Err(e) = self.tun.try_send(&buf) {
                warn!("Unable to send RST to remote end: {}", e);
            }
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(tun: Vec<Tun>, local_ip: Ipv4Addr, local_ip6: Option<Ipv6Addr>) -> Stack {
        Stack::new_with_keepalive(tun, local_ip, local_ip6, KeepaliveConfig::default())
    }

    pub fn new_with_keepalive(
        tun: Vec<Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        keepalive: KeepaliveConfig,
    ) -> Stack {
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
            started: time::Instant::now(),
            keepalive,
        });

        for t in tun {
            tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            local_ip6,
            ready: ready_rx,
        }
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    /// Accepts an incoming connection.
    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    /// Connects to the remote end. `None` returned means
    /// the connection attempt failed.
    pub async fn connect(&mut self, addr: SocketAddr) -> Option<Socket> {
        let mut rng = SmallRng::from_os_rng();
        for local_port in rng.random_range(32768..=60999)..=60999 {
            let local_addr = SocketAddr::new(
                if addr.is_ipv4() {
                    IpAddr::V4(self.local_ip)
                } else {
                    IpAddr::V6(self.local_ip6.expect("IPv6 local address undefined"))
                },
                local_port,
            );
            let tuple = AddrTuple::new(local_addr, addr);
            let mut sock;

            {
                let mut tuples = self.shared.tuples.write().unwrap();
                if tuples.contains_key(&tuple) {
                    trace!(
                        "Fake TCP connection to {}, local port number {} already in use, trying another one",
                        addr, local_port
                    );
                    continue;
                }

                let incoming;
                (sock, incoming) = Socket::new(
                    self.shared.clone(),
                    self.shared.tun.choose(&mut rng).unwrap().clone(),
                    local_addr,
                    addr,
                    None,
                    State::Idle,
                );

                assert!(tuples.insert(tuple, incoming).is_none());
            }

            return sock.connect().await.map(|_| sock);
        }

        error!(
            "Fake TCP connection to {} failed, emphemeral port number exhausted",
            addr
        );
        None
    }

    async fn reader_task(
        tun: Arc<Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, Connection> = HashMap::new();

        loop {
            let mut buf = BytesMut::zeroed(MAX_PACKET_LEN);

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = size.unwrap();
                    buf.truncate(size);
                    let buf = buf.freeze();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                c.health.last_rx_ms.store(shared.now_ms(), Ordering::Relaxed);
                                if c.incoming.send_async(buf).await.is_err() {
                                    trace!("Cache hit, but receiver already closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    c.health.last_rx_ms.store(shared.now_ms(), Ordering::Relaxed);
                                    if c.incoming.send_async(buf).await.is_err() {
                                        trace!("Receiver already closed, dropping packet");
                                    }
                                    continue;
                                }
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                // SYN seen on listening socket
                                if tcp_packet.get_sequence() == 0 {
                                    let (sock, incoming) = Socket::new(
                                        shared.clone(),
                                        tun.clone(),
                                        local_addr,
                                        remote_addr,
                                        Some(tcp_packet.get_sequence() + 1),
                                        State::Idle,
                                    );
                                    assert!(shared
                                        .tuples
                                        .write()
                                        .unwrap()
                                        .insert(tuple, incoming)
                                        .is_none());
                                    tokio::spawn(sock.accept());
                                } else {
                                    trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                                    let buf = build_tcp_packet(
                                        local_addr,
                                        remote_addr,
                                        0,
                                        tcp_packet.get_sequence() + tcp_packet.payload().len() as u32 + 1, // +1 because of SYN flag set
                                        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                        None,
                                    );
                                    shared.tun[0].try_send(&buf).unwrap();
                                }
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    tcp_packet.get_acknowledgement(),
                                    tcp_packet.get_sequence() + tcp_packet.payload().len() as u32,
                                    tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                    None,
                                );
                                shared.tun[0].try_send(&buf).unwrap();
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    let tuple = tuple.unwrap();
                    tuples.remove(&tuple);
                    trace!("Removed cached tuple: {:?}", tuple);
                }
            }
        }
    }
}
