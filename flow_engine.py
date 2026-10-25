"""
Network Flow Engine module for AI-NIDS/IPS.
Aggregates captured packets into bidirectional network flows using normalized 5-tuples.
Computes flow duration, packet/byte statistics, TCP flag counts, inter-arrival times (IAT),
handles timeouts, and extracts ML-ready feature vectors without fabricating data.
"""

import threading
import time
import math
import logging
from typing import Dict, Any, List, Optional, Tuple, Callable

logger = logging.getLogger(__name__)


def make_canonical_flow_key(
    src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], protocol: str
) -> Tuple[str, bool]:
    """
    Generate a canonical bidirectional flow key and determine direction relative to initiator.
    Returns (flow_key, is_forward).
    """
    sport = src_port or 0
    dport = dst_port or 0
    ep1 = (src_ip, sport)
    ep2 = (dst_ip, dport)

    proto = protocol.upper()
    if ep1 <= ep2:
        flow_key = f"{src_ip}:{sport}<->{dst_ip}:{dport}/{proto}"
        is_forward = True
    else:
        flow_key = f"{dst_ip}:{dport}<->{src_ip}:{sport}/{proto}"
        is_forward = False

    return flow_key, is_forward


class NetworkFlow:
    """Represents a single bidirectional network conversation."""

    def __init__(
        self,
        flow_key: str,
        initiator_ip: str,
        responder_ip: str,
        initiator_port: Optional[int],
        responder_port: Optional[int],
        protocol: str,
        start_time: float
    ):
        self.flow_key = flow_key
        self.src_ip = initiator_ip
        self.dst_ip = responder_ip
        self.src_port = initiator_port
        self.dst_port = responder_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_time = start_time

        # Packet and byte counters
        self.fwd_pkts: int = 0
        self.bwd_pkts: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0

        # Packet lengths and arrival times for statistical features
        self.packet_lengths: List[int] = []
        self.packet_timestamps: List[float] = []

        # TCP flag tracking
        self.syn_cnt: int = 0
        self.ack_cnt: int = 0
        self.fin_cnt: int = 0
        self.rst_cnt: int = 0
        self.psh_cnt: int = 0
        self.urg_cnt: int = 0

        self.state: str = "ACTIVE"
        self.is_anomalous: bool = False
        self.anomaly_score: float = 0.0

    def add_packet(self, pkt: Dict[str, Any], is_forward: bool) -> None:
        """Update flow metrics with a new observed packet."""
        ts = pkt.get("timestamp", time.time())
        length = int(pkt.get("length", 0))

        self.last_time = max(self.last_time, ts)
        self.packet_lengths.append(length)
        self.packet_timestamps.append(ts)

        # Cap retained lists to prevent unbounded memory on elephant flows
        if len(self.packet_lengths) > 500:
            self.packet_lengths = self.packet_lengths[-500:]
            self.packet_timestamps = self.packet_timestamps[-500:]

        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += length
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += length

        # Parse TCP flags
        flags_str = pkt.get("tcp_flags") or ""
        if flags_str and flags_str != "NONE":
            flags = set(flags_str.split(","))
            if "SYN" in flags: self.syn_cnt += 1
            if "ACK" in flags: self.ack_cnt += 1
            if "FIN" in flags:
                self.fin_cnt += 1
                self.state = "CLOSING"
            if "RST" in flags:
                self.rst_cnt += 1
                self.state = "RESET"
            if "PSH" in flags: self.psh_cnt += 1
            if "URG" in flags: self.urg_cnt += 1

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.fwd_pkts + self.bwd_pkts

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    def get_statistics(self) -> Dict[str, Any]:
        """Compute summary statistics for the flow."""
        dur = self.duration
        total_p = self.total_packets
        total_b = self.total_bytes

        # Packet rate and byte rate
        pkt_rate = (total_p / dur) if dur > 0.0001 else float(total_p)
        byte_rate = (total_b / dur) if dur > 0.0001 else float(total_b)

        # Packet length statistics
        if self.packet_lengths:
            pkt_len_mean = sum(self.packet_lengths) / len(self.packet_lengths)
            pkt_len_max = max(self.packet_lengths)
            pkt_len_min = min(self.packet_lengths)
            variance = sum((x - pkt_len_mean) ** 2 for x in self.packet_lengths) / len(self.packet_lengths)
            pkt_len_std = math.sqrt(variance)
        else:
            pkt_len_mean = 0.0
            pkt_len_max = 0
            pkt_len_min = 0
            pkt_len_std = 0.0

        # Inter-arrival time (IAT) statistics
        iats = []
        if len(self.packet_timestamps) > 1:
            for i in range(1, len(self.packet_timestamps)):
                diff = self.packet_timestamps[i] - self.packet_timestamps[i - 1]
                if diff >= 0:
                    iats.append(diff)

        if iats:
            iat_mean = sum(iats) / len(iats)
            iat_max = max(iats)
            iat_min = min(iats)
            iat_variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
            iat_std = math.sqrt(iat_variance)
        else:
            iat_mean = 0.0
            iat_max = 0.0
            iat_min = 0.0
            iat_std = 0.0

        return {
            "flow_key": self.flow_key,
            "start_time": self.start_time,
            "last_time": self.last_time,
            "duration": round(dur, 4),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "fwd_pkts": self.fwd_pkts,
            "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "total_packets": total_p,
            "total_bytes": total_b,
            "pkt_rate": round(pkt_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "pkt_len_mean": round(pkt_len_mean, 2),
            "pkt_len_std": round(pkt_len_std, 2),
            "pkt_len_max": pkt_len_max,
            "pkt_len_min": pkt_len_min,
            "flow_iat_mean": round(iat_mean, 6),
            "flow_iat_std": round(iat_std, 6),
            "flow_iat_max": round(iat_max, 6),
            "flow_iat_min": round(iat_min, 6),
            "syn_cnt": self.syn_cnt,
            "ack_cnt": self.ack_cnt,
            "fin_cnt": self.fin_cnt,
            "rst_cnt": self.rst_cnt,
            "psh_cnt": self.psh_cnt,
            "urg_cnt": self.urg_cnt,
            "state": self.state,
            "is_anomalous": self.is_anomalous,
            "anomaly_score": self.anomaly_score
        }

    def to_feature_vector(self) -> Dict[str, float]:
        """
        Extract standardized feature dictionary for Machine Learning pipeline.
        Compatible with documented CICIDS2017 / UNSW-NB15 flow features schema.
        """
        stats = self.get_statistics()
        return {
            "flow_duration": stats["duration"],
            "total_fwd_pkts": float(stats["fwd_pkts"]),
            "total_bwd_pkts": float(stats["bwd_pkts"]),
            "total_fwd_bytes": float(stats["fwd_bytes"]),
            "total_bwd_bytes": float(stats["bwd_bytes"]),
            "pkt_len_mean": stats["pkt_len_mean"],
            "pkt_len_std": stats["pkt_len_std"],
            "pkt_len_max": float(stats["pkt_len_max"]),
            "pkt_len_min": float(stats["pkt_len_min"]),
            "flow_pkts_per_sec": stats["pkt_rate"],
            "flow_bytes_per_sec": stats["byte_rate"],
            "syn_flag_count": float(stats["syn_cnt"]),
            "ack_flag_count": float(stats["ack_cnt"]),
            "fin_flag_count": float(stats["fin_cnt"]),
            "rst_flag_count": float(stats["rst_cnt"]),
            "psh_flag_count": float(stats["psh_cnt"]),
            "flow_iat_mean": stats["flow_iat_mean"]
        }


class FlowEngine:
    """
    Manages active network flows, aggregation from packet stream,
    expiration cleanup, and notification callbacks for detection.
    """

    def __init__(
        self,
        idle_timeout_sec: float = 15.0,
        active_timeout_sec: float = 60.0
    ):
        self.idle_timeout_sec = idle_timeout_sec
        self.active_timeout_sec = active_timeout_sec

        self._flows: Dict[str, NetworkFlow] = {}
        self._lock = threading.Lock()

        self._flow_callbacks: List[Callable[[Dict[str, Any], NetworkFlow], None]] = []

        self._cleanup_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.is_running = False

    def start(self) -> None:
        """Start the background flow expiration worker."""
        if self.is_running:
            return
        self._stop_event.clear()
        self.is_running = True
        self._cleanup_thread = threading.Thread(
            target=self._expiration_worker,
            name="FlowExpirationWorker",
            daemon=True
        )
        self._cleanup_thread.start()
        logger.info("FlowEngine started (idle_timeout=%.1fs, active_timeout=%.1fs)",
                    self.idle_timeout_sec, self.active_timeout_sec)

    def stop(self) -> None:
        """Stop flow engine worker."""
        self._stop_event.set()
        self.is_running = False
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2.0)
            self._cleanup_thread = None
        logger.info("FlowEngine stopped.")

    def register_callback(self, cb: Callable[[Dict[str, Any], NetworkFlow], None]) -> None:
        """Register a callback for flow updates or completions."""
        with self._lock:
            if cb not in self._flow_callbacks:
                self._flow_callbacks.append(cb)

    def process_packet(self, pkt: Dict[str, Any], raw_pkt: Any = None) -> Optional[NetworkFlow]:
        """
        Process a captured packet, add it to its bidirectional flow,
        and trigger flow callbacks.
        """
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip or src_ip == "UNKNOWN" or dst_ip == "UNKNOWN":
            return None

        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        proto = pkt.get("protocol", "IP")

        flow_key, _ = make_canonical_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        with self._lock:
            flow = self._flows.get(flow_key)
            if flow is None:
                flow = NetworkFlow(
                    flow_key=flow_key,
                    initiator_ip=src_ip,
                    responder_ip=dst_ip,
                    initiator_port=src_port,
                    responder_port=dst_port,
                    protocol=proto,
                    start_time=pkt.get("timestamp", time.time())
                )
                self._flows[flow_key] = flow
                is_fwd = True
            else:
                is_fwd = (src_ip == flow.src_ip and src_port == flow.src_port)

            flow.add_packet(pkt, is_fwd)
            stats = flow.get_statistics()

        # Fire callbacks outside lock to prevent deadlocks
        callbacks = list(self._flow_callbacks)
        for cb in callbacks:
            try:
                cb(stats, flow)
            except Exception as cb_err:
                logger.error("Flow callback error: %s", cb_err)

        return flow

    def get_active_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return list of current active flow summaries."""
        with self._lock:
            flows = list(self._flows.values())

        # Sort by most recent activity
        flows.sort(key=lambda f: f.last_time, reverse=True)
        return [f.get_statistics() for f in flows[:limit]]

    def get_flow_count(self) -> int:
        """Return count of active flows in memory."""
        with self._lock:
            return len(self._flows)

    def _expiration_worker(self) -> None:
        """Periodic thread checking for idle and expired flows."""
        while not self._stop_event.is_set():
            time.sleep(5.0)
            now = time.time()
            expired_flows = []

            with self._lock:
                for key, flow in list(self._flows.items()):
                    idle_time = now - flow.last_time
                    total_dur = now - flow.start_time

                    if idle_time >= self.idle_timeout_sec or total_dur >= self.active_timeout_sec:
                        flow.state = "EXPIRED"
                        expired_flows.append(flow)
                        del self._flows[key]

            # Notify callbacks of flow expiration
            for flow in expired_flows:
                stats = flow.get_statistics()
                for cb in self._flow_callbacks:
                    try:
                        cb(stats, flow)
                    except Exception as e:
                        logger.error("Flow expiration callback error: %s", e)


# Global singleton instance
_flow_engine_instance: Optional[FlowEngine] = None

def get_flow_engine() -> FlowEngine:
    """Return the global FlowEngine singleton."""
    global _flow_engine_instance
    if _flow_engine_instance is None:
        _flow_engine_instance = FlowEngine()
    return _flow_engine_instance
