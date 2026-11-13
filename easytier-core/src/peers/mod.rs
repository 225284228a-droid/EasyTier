pub(crate) mod acl;
pub(crate) mod admission;
pub(crate) mod attached;
pub(crate) mod conn;
pub mod context;
pub mod credential_manager;
pub mod error;
pub mod foreign_network;
pub mod peer_center;
pub mod peer_manager;
pub(crate) mod peer_rpc;
pub mod public_ipv6;
pub(crate) mod relay_peer_map;
pub(crate) mod route;
pub(crate) mod traffic_metrics;
mod util;
pub(crate) mod whitelist;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

use crate::packet::ZCPacket;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::error::{SendError, TryRecvError, TrySendError};

use self::conn::peer_conn::PeerConnId;
use crate::config::PeerId;

/// Capacity of the channel feeding the main peer manager. Every own-network
/// connection and every foreign network that hands packets back to the parent
/// shares this one queue, so it gets more headroom than per-network queues.
pub(crate) const MAIN_PEER_PACKET_CHAN_CAPACITY: usize = 2048;

/// Packets dropped instead of blocking a producer on a full peer packet queue.
///
/// Blocking used to stall the per-connection receive loop (no ping/pong or RPC
/// processing for that connection) and the per-foreign-network router whenever
/// the peer manager fell behind. Relay data is dropped instead; control traffic
/// still waits. Totals are logged at most every `LOG_INTERVAL_SECS`.
pub(crate) struct PeerChanDropStats {
    conn_data_queue_full: AtomicU64,
    foreign_forward_queue_full: AtomicU64,
    foreign_forward_no_route: AtomicU64,
    last_log_secs: AtomicU64,
}

impl PeerChanDropStats {
    const LOG_INTERVAL_SECS: u64 = 10;

    const fn new() -> Self {
        Self {
            conn_data_queue_full: AtomicU64::new(0),
            foreign_forward_queue_full: AtomicU64::new(0),
            foreign_forward_no_route: AtomicU64::new(0),
            last_log_secs: AtomicU64::new(0),
        }
    }

    pub(crate) fn inc_conn_data_queue_full(&self) {
        self.conn_data_queue_full.fetch_add(1, Ordering::Relaxed);
        self.maybe_log();
    }

    pub(crate) fn inc_foreign_forward_queue_full(&self) {
        self.foreign_forward_queue_full
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_log();
    }

    pub(crate) fn inc_foreign_forward_no_route(&self) {
        self.foreign_forward_no_route
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_log();
    }

    fn maybe_log(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_log_secs.load(Ordering::Relaxed);
        if now < last + Self::LOG_INTERVAL_SECS
            || self
                .last_log_secs
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        tracing::warn!(
            conn_data_queue_full = self.conn_data_queue_full.load(Ordering::Relaxed),
            foreign_forward_queue_full = self.foreign_forward_queue_full.load(Ordering::Relaxed),
            foreign_forward_no_route = self.foreign_forward_no_route.load(Ordering::Relaxed),
            "peer packet queue drops (cumulative)"
        );
    }
}

pub(crate) static PEER_CHAN_DROP_STATS: PeerChanDropStats = PeerChanDropStats::new();

/// The local entry point that created a peer connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerConnectionOrigin {
    Manual,
    Direct,
    Listener,
    TcpHolePunch,
    UdpHolePunch,
    Attached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerPacketIngress {
    Local,
    Peer {
        peer_id: PeerId,
        conn_id: PeerConnId,
        origin: PeerConnectionOrigin,
    },
}

impl PeerPacketIngress {
    pub(crate) fn is_attached(self) -> bool {
        matches!(
            self,
            Self::Peer {
                origin: PeerConnectionOrigin::Attached,
                ..
            }
        )
    }

    pub(crate) fn peer_connection(self) -> Option<(PeerId, PeerConnId)> {
        match self {
            Self::Local => None,
            Self::Peer {
                peer_id, conn_id, ..
            } => Some((peer_id, conn_id)),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PeerPacketEnvelope {
    packet: ZCPacket,
    ingress: PeerPacketIngress,
}

impl PeerPacketEnvelope {
    fn local(packet: ZCPacket) -> Self {
        Self {
            packet,
            ingress: PeerPacketIngress::Local,
        }
    }

    fn from_peer(packet: ZCPacket, ingress: PeerPacketIngress) -> Self {
        debug_assert!(matches!(ingress, PeerPacketIngress::Peer { .. }));
        Self { packet, ingress }
    }

    pub(crate) fn into_parts(self) -> (ZCPacket, PeerPacketIngress) {
        (self.packet, self.ingress)
    }
}

#[derive(Clone)]
pub struct PacketRecvChan(tokio::sync::mpsc::Sender<PeerPacketEnvelope>);

impl PacketRecvChan {
    /// Injects a packet produced by a local subsystem. Local injection never carries
    /// the privileges of an attached peer connection.
    pub async fn send(&self, packet: ZCPacket) -> Result<(), SendError<ZCPacket>> {
        self.0
            .send(PeerPacketEnvelope::local(packet))
            .await
            .map_err(|error| SendError(error.0.packet))
    }

    /// Non-blocking variant of [`Self::send`] for producers that must never be
    /// held up by a slow consumer.
    pub(crate) fn try_send(&self, packet: ZCPacket) -> Result<(), TrySendError<ZCPacket>> {
        self.0
            .try_send(PeerPacketEnvelope::local(packet))
            .map_err(|error| match error {
                TrySendError::Full(envelope) => TrySendError::Full(envelope.packet),
                TrySendError::Closed(envelope) => TrySendError::Closed(envelope.packet),
            })
    }
}

pub struct PacketRecvChanReceiver(tokio::sync::mpsc::Receiver<PeerPacketEnvelope>);

impl PacketRecvChanReceiver {
    pub async fn recv(&mut self) -> Option<ZCPacket> {
        self.0.recv().await.map(|envelope| envelope.packet)
    }
}

pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
    create_packet_recv_chan_with_capacity(128)
}

pub(crate) fn create_packet_recv_chan_with_capacity(
    capacity: usize,
) -> (PacketRecvChan, PacketRecvChanReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
    (PacketRecvChan(sender), PacketRecvChanReceiver(receiver))
}

/// Hands a packet received on a peer connection to its peer manager.
///
/// When the queue is full, relay data is dropped (the tunnelled protocols
/// recover from loss) so the connection's receive loop keeps running and keeps
/// answering pings and RPCs. Control packets still wait for room; waiting
/// senders get freed slots before `try_send` callers, so they are not starved
/// by data traffic.
pub(crate) async fn send_peer_packet_to_chan(
    sender: &PacketRecvChan,
    packet: ZCPacket,
    ingress: PeerPacketIngress,
) -> Result<(), SendError<ZCPacket>> {
    let envelope = PeerPacketEnvelope::from_peer(packet, ingress);
    match sender.0.try_send(envelope) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(envelope)) => {
            if peer_manager::is_relay_data_zc_packet(&envelope.packet) {
                PEER_CHAN_DROP_STATS.inc_conn_data_queue_full();
                return Ok(());
            }
            sender
                .0
                .send(envelope)
                .await
                .map_err(|error| SendError(error.0.packet))
        }
        Err(TrySendError::Closed(envelope)) => Err(SendError(envelope.packet)),
    }
}

pub(crate) async fn recv_packet_envelope_from_chan(
    packet_recv_chan_receiver: &mut PacketRecvChanReceiver,
) -> Result<PeerPacketEnvelope, anyhow::Error> {
    match packet_recv_chan_receiver.0.try_recv() {
        Ok(packet) => Ok(packet),
        Err(TryRecvError::Empty) => packet_recv_chan_receiver
            .0
            .recv()
            .await
            .ok_or(anyhow::anyhow!("recv_packet_from_chan failed")),
        Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!("recv_packet_from_chan failed")),
    }
}

pub async fn recv_packet_from_chan(
    packet_recv_chan_receiver: &mut PacketRecvChanReceiver,
) -> Result<ZCPacket, anyhow::Error> {
    recv_packet_envelope_from_chan(packet_recv_chan_receiver)
        .await
        .map(|envelope| envelope.packet)
}

/// Returned packets continue at the next peer-packet filter.
#[derive(Debug)]
pub enum PeerPacketFilterResult {
    Consumed,
    Pass(ZCPacket),
    PassBatch(Vec<ZCPacket>),
}

impl From<Option<ZCPacket>> for PeerPacketFilterResult {
    fn from(packet: Option<ZCPacket>) -> Self {
        match packet {
            Some(packet) => Self::Pass(packet),
            None => Self::Consumed,
        }
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(&self, zc_packet: ZCPacket) -> PeerPacketFilterResult {
        PeerPacketFilterResult::Pass(zc_packet)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket) -> bool;

    fn id(&self) -> String {
        format!("{:p}", self)
    }
}

pub type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
pub type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;
