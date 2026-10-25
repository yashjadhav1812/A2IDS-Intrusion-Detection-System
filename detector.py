"""
Hybrid Threat Detection Engine for AI-NIDS/IPS.
Combines deterministic protocol signatures, statistical anomaly detection, and
supervised Random Forest classification. Aggregates alerts into cohesive incidents.
Never fabricates attacks or alert records.
"""

import time
import logging
import collections
from typing import Dict, Any, List, Optional, Tuple, Set

import database
from model import get_model_pipeline

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Real-time hybrid intrusion detection engine.
    Processes packets and network flows through rule-based and ML pipelines.
    """

    def __init__(
        self,
        syn_flood_threshold: int = 50,
        syn_flood_ack_ratio: float = 0.1,
        port_scan_threshold: int = 15,
        port_scan_window_sec: float = 5.0,
        vertical_scan_ports: Optional[List[int]] = None,
        udp_flood_threshold: int = 100,
        icmp_flood_threshold: int = 40,
        packet_rate_spike_threshold: int = 200,
        min_ml_confidence: float = 0.75,
        anomaly_score_threshold: float = -0.15
    ):
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_ack_ratio = syn_flood_ack_ratio
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.vertical_scan_ports: Set[int] = set(vertical_scan_ports or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080])
        self.udp_flood_threshold = udp_flood_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.packet_rate_spike_threshold = packet_rate_spike_threshold
        self.min_ml_confidence = min_ml_confidence
        self.anomaly_score_threshold = anomaly_score_threshold

        # Sliding window state tracking: {src_ip: deque([(timestamp, ...)])}
        self._syn_tracking: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=1000))
        self._port_tracking: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=1000))
        self._udp_tracking: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=1000))
        self._icmp_tracking: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=1000))

        # Incident deduplication: {(src_ip, category): (alert_id, last_alert_time)}
        self._active_incidents: Dict[Tuple[str, str], Tuple[int, float]] = {}
        self.incident_cooldown_sec: float = 60.0

        self.model_pipeline = get_model_pipeline()

    def process_packet(self, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate single packet metadata against signature rules.
        Returns alert dict if a threat is detected, else None.
        """
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip or src_ip in ("UNKNOWN", "127.0.0.1", "::1"):
            return None

        proto = pkt.get("protocol", "")
        tcp_flags = pkt.get("tcp_flags") or ""
        now = pkt.get("timestamp", time.time())
        dst_port = pkt.get("dst_port")

        # 1. TCP SYN Tracking (SYN flood and Port scanning)
        if proto in ("TCP", "HTTP", "TLS/HTTPS", "SSH") and "SYN" in tcp_flags and "ACK" not in tcp_flags:
            # Track SYN
            q_syn = self._syn_tracking[src_ip]
            q_syn.append(now)

            # Evict timestamps older than 5 seconds
            while q_syn and now - q_syn[0] > 5.0:
                q_syn.popleft()

            if len(q_syn) >= self.syn_flood_threshold:
                return self._create_or_update_alert(
                    title=f"Potential TCP SYN Flood from {src_ip}",
                    severity="CRITICAL",
                    category="SYN Flood",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=pkt.get("src_port"),
                    dst_port=dst_port,
                    protocol=proto,
                    detection_method="Rule (Sliding Window)",
                    evidence={
                        "syn_packets_in_5s": len(q_syn),
                        "threshold": self.syn_flood_threshold,
                        "recent_target": f"{dst_ip}:{dst_port}"
                    },
                    recommendation="Inspect connection states. Consider rate-limiting or temporary firewall block."
                )

            # Track Distinct Destination Ports for Port Scan
            if dst_port:
                q_ports = self._port_tracking[src_ip]
                q_ports.append((now, dst_port))

                while q_ports and now - q_ports[0][0] > self.port_scan_window_sec:
                    q_ports.popleft()

                distinct_ports = {p for _, p in q_ports}
                if len(distinct_ports) >= self.port_scan_threshold:
                    sensitive_hits = distinct_ports.intersection(self.vertical_scan_ports)
                    is_vertical = len(sensitive_hits) >= 4
                    return self._create_or_update_alert(
                        title=f"{'Vertical' if is_vertical else 'Horizontal'} Port Scan Detected from {src_ip}",
                        severity="HIGH" if is_vertical else "MEDIUM",
                        category="Port Scan",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=pkt.get("src_port"),
                        dst_port=dst_port,
                        protocol=proto,
                        detection_method="Rule (Port Tracker)",
                        evidence={
                            "distinct_ports_contacted": len(distinct_ports),
                            "scanned_ports_sample": sorted(list(distinct_ports))[:10],
                            "sensitive_service_ports_hit": sorted(list(sensitive_hits)),
                            "time_window_sec": self.port_scan_window_sec
                        },
                        recommendation="Host is probing open ports. Check for vulnerability scanning tools."
                    )

        # 2. UDP Flood Rule
        elif proto == "UDP":
            q_udp = self._udp_tracking[src_ip]
            q_udp.append(now)
            while q_udp and now - q_udp[0] > 5.0:
                q_udp.popleft()

            if len(q_udp) >= self.udp_flood_threshold:
                return self._create_or_update_alert(
                    title=f"UDP Traffic Burst / Flood from {src_ip}",
                    severity="HIGH",
                    category="UDP Flood",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=pkt.get("src_port"),
                    dst_port=dst_port,
                    protocol="UDP",
                    detection_method="Rule (Rate Analysis)",
                    evidence={
                        "udp_packets_in_5s": len(q_udp),
                        "rate_per_sec": round(len(q_udp) / 5.0, 1),
                        "threshold": self.udp_flood_threshold
                    },
                    recommendation="Evaluate if UDP burst is valid streaming or Denial-of-Service traffic."
                )

        # 3. ICMP Flood Rule
        elif proto in ("ICMP", "ICMPv6"):
            q_icmp = self._icmp_tracking[src_ip]
            q_icmp.append(now)
            while q_icmp and now - q_icmp[0] > 5.0:
                q_icmp.popleft()

            if len(q_icmp) >= self.icmp_flood_threshold:
                return self._create_or_update_alert(
                    title=f"ICMP Ping Flood from {src_ip}",
                    severity="MEDIUM",
                    category="ICMP Flood",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=None,
                    dst_port=None,
                    protocol="ICMP",
                    detection_method="Rule (Rate Analysis)",
                    evidence={
                        "icmp_packets_in_5s": len(q_icmp),
                        "threshold": self.icmp_flood_threshold
                    },
                    recommendation="Check if host is running ping sweep or ICMP DoS tool."
                )

        return None

    def process_flow(self, stats: Dict[str, Any], flow: Any) -> Optional[Dict[str, Any]]:
        """
        Evaluate an aggregated network flow using ML inference and statistical anomaly detection.
        """
        src_ip = stats.get("src_ip", "")
        dst_ip = stats.get("dst_ip", "")
        if not src_ip or src_ip in ("UNKNOWN", "127.0.0.1", "::1"):
            return None

        # Build feature vector
        features = flow.to_feature_vector() if hasattr(flow, "to_feature_vector") else {}
        if not features:
            return None

        # Run Machine Learning inference if model is available
        ml_res = self.model_pipeline.predict(features)
        if ml_res:
            pred_class = ml_res.get("predicted_class", "BENIGN")
            confidence = ml_res.get("confidence", 0.0)
            is_anomaly = ml_res.get("is_anomaly", False)
            anomaly_score = ml_res.get("anomaly_score", 0.0)

            # Update flow object anomaly status
            flow.is_anomalous = is_anomaly or (pred_class != "BENIGN")
            flow.anomaly_score = anomaly_score

            # Trigger alert if AI detects non-benign traffic with sufficient confidence
            if pred_class in ("SYN_FLOOD", "PORT_SCAN", "GENERIC_MALICIOUS") and confidence >= self.min_ml_confidence:
                severity = "CRITICAL" if pred_class == "SYN_FLOOD" else ("HIGH" if pred_class == "PORT_SCAN" else "MEDIUM")
                return self._create_or_update_alert(
                    title=f"Intrusion Alert: {pred_class.replace('_', ' ')} from {src_ip}",
                    severity=severity,
                    category=pred_class.replace("_", " ").title(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=stats.get("src_port"),
                    dst_port=stats.get("dst_port"),
                    protocol=stats.get("protocol", "IP"),
                    detection_method="AI Behavioral Engine",
                    predicted_class=pred_class,
                    confidence=confidence,
                    evidence={
                        "model_prediction": pred_class,
                        "calibrated_confidence": confidence,
                        "class_probabilities": ml_res.get("class_probabilities"),
                        "anomaly_score": anomaly_score,
                        "flow_duration_sec": stats.get("duration"),
                        "total_packets": stats.get("total_packets"),
                        "top_features": ml_res.get("top_contributing_features")
                    },
                    recommendation=f"Classified as {pred_class} with {int(confidence*100)}% confidence. Review evidence."
                )

            # Trigger alert on strong statistical outlier / anomaly even if class is borderline
            if is_anomaly and anomaly_score <= self.anomaly_score_threshold:
                return self._create_or_update_alert(
                    title=f"Statistical Flow Anomaly Detected from {src_ip}",
                    severity="LOW",
                    category="Anomaly",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=stats.get("src_port"),
                    dst_port=stats.get("dst_port"),
                    protocol=stats.get("protocol", "IP"),
                    detection_method="Traffic Anomaly Analysis",
                    predicted_class=pred_class,
                    confidence=confidence,
                    evidence={
                        "anomaly_score": anomaly_score,
                        "threshold": self.anomaly_score_threshold,
                        "flow_packet_rate": stats.get("pkt_rate"),
                        "flow_byte_rate": stats.get("byte_rate"),
                        "top_features": ml_res.get("top_contributing_features")
                    },
                    recommendation="Unusual traffic distribution compared to baseline. Monitor for further activity."
                )

        return None

    def _create_or_update_alert(
        self,
        title: str,
        severity: str,
        category: str,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        detection_method: str,
        evidence: Dict[str, Any],
        recommendation: str,
        predicted_class: Optional[str] = None,
        confidence: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Deduplicate and insert an alert as an incident in the database.
        If an alert for this (src_ip, category) occurred recently within cooldown,
        it is aggregated into the active incident.
        """
        now = time.time()
        incident_key = (src_ip, category)

        if incident_key in self._active_incidents:
            alert_id, last_time = self._active_incidents[incident_key]
            if now - last_time < self.incident_cooldown_sec:
                # Update cooldown timestamp to debounce spam
                self._active_incidents[incident_key] = (alert_id, now)
                return None

        # Check if source address is protected under host safety policy
        final_recommendation = recommendation
        import address_policy
        prot = address_policy.get_address_classifier().is_protected(src_ip)
        if prot.is_protected:
            final_recommendation = f"{recommendation} [POLICY NOTICE: Source address {src_ip} is categorized as {prot.category} ({prot.description}). Automated blocking will be rejected by Safety Controller to protect host connectivity. Verify for packet spoofing or local processes.]"

        # Build alert record
        alert_dict = {
            "timestamp": now,
            "title": title,
            "severity": severity,
            "category": category,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "detection_method": detection_method,
            "predicted_class": predicted_class,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": final_recommendation,
            "status": "OPEN",
            "operator_notes": "",
            "firewall_action_taken": "NONE"
        }

        # Persist alert to database
        try:
            alert_id = database.insert_alert(alert_dict)
            alert_dict["id"] = alert_id
            self._active_incidents[incident_key] = (alert_id, now)
            logger.warning("THREAT ALERT #%d [%s]: %s (from %s)", alert_id, severity, title, src_ip)
            return alert_dict
        except Exception as e:
            logger.error("Failed to insert alert into database: %s", e)
            return None


# Global singleton instance
_detector_instance: Optional[ThreatDetector] = None

def get_threat_detector() -> ThreatDetector:
    """Return the global ThreatDetector singleton."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = ThreatDetector()
    return _detector_instance
