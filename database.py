"""
Database module for AI-NIDS/IPS.
Handles SQLite schema management, WAL mode, thread-safe access,
and persistent logging for packets, flows, alerts, firewall actions, and audit events.
"""

import sqlite3
import json
import time
import os
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ids_events.db")
_STATIC_DEFAULT_DB_PATH = DEFAULT_DB_PATH
_MEMDB_HOLDER: Optional[sqlite3.Connection] = None


def _resolve_db_path(path: Optional[str] = None) -> str:
    """Dynamically resolve database path to respect in-memory overrides during testing."""
    if path is not None and path != _STATIC_DEFAULT_DB_PATH:
        return path
    return DEFAULT_DB_PATH


def get_db_connection(db_path: Optional[str] = None, auto_init: bool = True) -> sqlite3.Connection:
    """Return an SQLite connection configured with WAL mode and row factory."""
    global _MEMDB_HOLDER
    target_path = _resolve_db_path(db_path)
    if target_path == ":memory:":
        if _MEMDB_HOLDER is None:
            _MEMDB_HOLDER = sqlite3.connect("file:a2ids_memdb?mode=memory&cache=shared", uri=True, check_same_thread=False)
        conn = sqlite3.connect("file:a2ids_memdb?mode=memory&cache=shared", uri=True, timeout=15.0, check_same_thread=False)
    else:
        conn = sqlite3.connect(target_path, timeout=15.0, check_same_thread=False)

    conn.row_factory = sqlite3.Row
    if target_path != ":memory:":
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except Exception:
            pass
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    if auto_init:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='response_decisions'")
        if not cursor.fetchone():
            init_db(target_path)

    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables, foreign keys, and indexes."""
    target_path = _resolve_db_path(db_path)
    with get_db_connection(target_path, auto_init=False) as conn:
        cursor = conn.cursor()

        # 1. Packets table (real-time packet metadata)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                datetime_str TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                length INTEGER NOT NULL,
                tcp_flags TEXT,
                interface TEXT NOT NULL,
                direction TEXT DEFAULT 'UNKNOWN',
                detection_status TEXT DEFAULT 'NORMAL',
                alert_id INTEGER,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);")

        # 2. Flows table (bidirectional network flows)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_key TEXT UNIQUE NOT NULL,
                start_time REAL NOT NULL,
                last_time REAL NOT NULL,
                duration REAL NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                fwd_pkts INTEGER DEFAULT 0,
                bwd_pkts INTEGER DEFAULT 0,
                fwd_bytes INTEGER DEFAULT 0,
                bwd_bytes INTEGER DEFAULT 0,
                pkt_rate REAL DEFAULT 0.0,
                byte_rate REAL DEFAULT 0.0,
                syn_cnt INTEGER DEFAULT 0,
                ack_cnt INTEGER DEFAULT 0,
                fin_cnt INTEGER DEFAULT 0,
                rst_cnt INTEGER DEFAULT 0,
                state TEXT DEFAULT 'ACTIVE',
                is_anomalous INTEGER DEFAULT 0,
                anomaly_score REAL DEFAULT 0.0
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_flow_key ON flows(flow_key);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_last_time ON flows(last_time);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_state ON flows(state);")

        # 3. Alerts table (incidents & detections)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                datetime_str TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                detection_method TEXT NOT NULL,
                predicted_class TEXT,
                confidence REAL,
                evidence_json TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT DEFAULT 'OPEN',
                operator_notes TEXT DEFAULT '',
                firewall_action_taken TEXT DEFAULT 'NONE'
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);")

        # 4. Firewall rules table (active and historical blocks)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                direction TEXT DEFAULT 'ALL',
                action TEXT DEFAULT 'BLOCK',
                backend TEXT NOT NULL,
                reason TEXT NOT NULL,
                alert_id INTEGER,
                created_at REAL NOT NULL,
                expires_at REAL,
                is_active INTEGER DEFAULT 1,
                is_permanent INTEGER DEFAULT 0,
                verified_state TEXT DEFAULT 'UNVERIFIED',
                removal_reason TEXT,
                operator TEXT DEFAULT 'SYSTEM',
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_firewall_ip ON firewall_rules(ip_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_firewall_is_active ON firewall_rules(is_active);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_firewall_expires_at ON firewall_rules(expires_at);")
        # Migrate existing DB: add operator column if not present
        try:
            cursor.execute("ALTER TABLE firewall_rules ADD COLUMN operator TEXT DEFAULT 'SYSTEM'")
        except Exception:
            pass

        # 5. Audit log (security and operations log)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                datetime_str TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user_or_system TEXT NOT NULL,
                details TEXT NOT NULL,
                status TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);")

        # 6. System metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                packets_total INTEGER DEFAULT 0,
                bytes_total INTEGER DEFAULT 0,
                flows_active INTEGER DEFAULT 0,
                alerts_total INTEGER DEFAULT 0,
                blocks_active INTEGER DEFAULT 0
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp);")

        # 7. Protection Rules (Category A, B, C allowlists and definitions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protection_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                pattern TEXT NOT NULL,
                reason TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL,
                enabled INTEGER DEFAULT 1,
                can_override INTEGER DEFAULT 0,
                operator TEXT DEFAULT 'SYSTEM'
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_protection_rules_cat ON protection_rules(category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_protection_rules_pat ON protection_rules(pattern);")

        # 8. Threat Response Decisions (Audited decision per evaluated threat)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS response_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                target_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                action TEXT NOT NULL,
                decision_code TEXT NOT NULL,
                reason TEXT NOT NULL,
                protection_category TEXT NOT NULL,
                block_duration_sec REAL DEFAULT 0.0,
                evidence_json TEXT DEFAULT '{}',
                evaluated_at REAL NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_resp_dec_target ON response_decisions(target_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_resp_dec_eval ON response_decisions(evaluated_at);")

        # 9. Rejected Block Requests (Transparent safety log of blocked actions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rejected_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                alert_id INTEGER,
                reason_code TEXT NOT NULL,
                category TEXT NOT NULL,
                details TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                timestamp REAL NOT NULL,
                datetime_str TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rej_blocks_ip ON rejected_blocks(ip_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rej_blocks_time ON rejected_blocks(timestamp);")

        # 10. Firewall Operations Log (Direct kernel / OS command traces)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                operation TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                backend TEXT NOT NULL,
                command TEXT NOT NULL,
                returncode INTEGER,
                verified_state TEXT NOT NULL,
                details TEXT,
                operator TEXT NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fw_ops_ip ON firewall_operations(ip_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fw_ops_time ON firewall_operations(timestamp);")

        # 11. System State (Emergency stop, runtime toggles)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
        """)

        conn.commit()
        logger.info("Database initialized successfully at %s", db_path)


# -----------------------------------------------------------------------------
# Packets operations
# -----------------------------------------------------------------------------

def insert_packet(pkt: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Insert a single packet metadata record."""
    ts = pkt.get("timestamp", time.time())
    dt_str = pkt.get("datetime_str", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)))
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO packets (
                timestamp, datetime_str, src_ip, dst_ip, src_port, dst_port,
                protocol, length, tcp_flags, interface, direction, detection_status, alert_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, dt_str,
            str(pkt.get("src_ip", "")), str(pkt.get("dst_ip", "")),
            pkt.get("src_port"), pkt.get("dst_port"),
            str(pkt.get("protocol", "UNKNOWN")),
            int(pkt.get("length", 0)),
            pkt.get("tcp_flags"),
            str(pkt.get("interface", "unknown")),
            str(pkt.get("direction", "UNKNOWN")),
            str(pkt.get("detection_status", "NORMAL")),
            pkt.get("alert_id")
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_recent_packets(
    limit: int = 100,
    offset: int = 0,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    detection_status: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve recent packet records with optional filters."""
    query = "SELECT * FROM packets WHERE 1=1"
    params: List[Any] = []

    if protocol:
        query += " AND protocol = ?"
        params.append(protocol.upper())
    if src_ip:
        query += " AND src_ip LIKE ?"
        params.append(f"%{src_ip}%")
    if dst_ip:
        query += " AND dst_ip LIKE ?"
        params.append(f"%{dst_ip}%")
    if detection_status:
        query += " AND detection_status = ?"
        params.append(detection_status.upper())

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_packet_count(db_path: str = DEFAULT_DB_PATH) -> int:
    """Return total count of stored packet records."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM packets")
        row = cursor.fetchone()
        return row[0] if row else 0


# -----------------------------------------------------------------------------
# Flows operations
# -----------------------------------------------------------------------------

def upsert_flow(flow: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Insert or update a network flow record based on flow_key."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO flows (
                flow_key, start_time, last_time, duration, src_ip, dst_ip,
                src_port, dst_port, protocol, fwd_pkts, bwd_pkts, fwd_bytes,
                bwd_bytes, pkt_rate, byte_rate, syn_cnt, ack_cnt, fin_cnt,
                rst_cnt, state, is_anomalous, anomaly_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_key) DO UPDATE SET
                last_time = excluded.last_time,
                duration = excluded.duration,
                fwd_pkts = excluded.fwd_pkts,
                bwd_pkts = excluded.bwd_pkts,
                fwd_bytes = excluded.fwd_bytes,
                bwd_bytes = excluded.bwd_bytes,
                pkt_rate = excluded.pkt_rate,
                byte_rate = excluded.byte_rate,
                syn_cnt = excluded.syn_cnt,
                ack_cnt = excluded.ack_cnt,
                fin_cnt = excluded.fin_cnt,
                rst_cnt = excluded.rst_cnt,
                state = excluded.state,
                is_anomalous = excluded.is_anomalous,
                anomaly_score = excluded.anomaly_score
        """, (
            str(flow.get("flow_key")),
            float(flow.get("start_time", time.time())),
            float(flow.get("last_time", time.time())),
            float(flow.get("duration", 0.0)),
            str(flow.get("src_ip", "")),
            str(flow.get("dst_ip", "")),
            flow.get("src_port"),
            flow.get("dst_port"),
            str(flow.get("protocol", "UNKNOWN")),
            int(flow.get("fwd_pkts", 0)),
            int(flow.get("bwd_pkts", 0)),
            int(flow.get("fwd_bytes", 0)),
            int(flow.get("bwd_bytes", 0)),
            float(flow.get("pkt_rate", 0.0)),
            float(flow.get("byte_rate", 0.0)),
            int(flow.get("syn_cnt", 0)),
            int(flow.get("ack_cnt", 0)),
            int(flow.get("fin_cnt", 0)),
            int(flow.get("rst_cnt", 0)),
            str(flow.get("state", "ACTIVE")),
            1 if flow.get("is_anomalous") else 0,
            float(flow.get("anomaly_score", 0.0))
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_flows(
    limit: int = 100,
    offset: int = 0,
    state: Optional[str] = None,
    only_anomalous: bool = False,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve network flows with optional filters."""
    query = "SELECT * FROM flows WHERE 1=1"
    params: List[Any] = []

    if state:
        query += " AND state = ?"
        params.append(state.upper())
    if only_anomalous:
        query += " AND is_anomalous = 1"

    query += " ORDER BY last_time DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


# -----------------------------------------------------------------------------
# Alerts & Incidents operations
# -----------------------------------------------------------------------------

def insert_alert(alert: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Insert a new threat detection alert."""
    ts = alert.get("timestamp", time.time())
    dt_str = alert.get("datetime_str", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)))
    evidence = alert.get("evidence", {})
    evidence_json = json.dumps(evidence) if isinstance(evidence, (dict, list)) else str(evidence)

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, datetime_str, title, severity, category, src_ip, dst_ip,
                src_port, dst_port, protocol, detection_method, predicted_class,
                confidence, evidence_json, recommendation, status, operator_notes,
                firewall_action_taken
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, dt_str,
            str(alert.get("title", "Threat Detected")),
            str(alert.get("severity", "MEDIUM")).upper(),
            str(alert.get("category", "General Anomaly")),
            str(alert.get("src_ip", "")),
            str(alert.get("dst_ip", "")),
            alert.get("src_port"),
            alert.get("dst_port"),
            str(alert.get("protocol", "IP")),
            str(alert.get("detection_method", "Rule")),
            alert.get("predicted_class"),
            float(alert["confidence"]) if alert.get("confidence") is not None else None,
            evidence_json,
            str(alert.get("recommendation", "Investigate connection source.")),
            str(alert.get("status", "OPEN")).upper(),
            str(alert.get("operator_notes", "")),
            str(alert.get("firewall_action_taken", "NONE"))
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_alerts(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve alerts with parsed evidence JSON."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND status = ?"
        params.append(status.upper())
    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["evidence"] = json.loads(d.get("evidence_json", "{}"))
            except Exception:
                d["evidence"] = d.get("evidence_json", "{}")
            result.append(d)
        return result


def get_alert_by_id(alert_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve a single alert by ID."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["evidence"] = json.loads(d.get("evidence_json", "{}"))
        except Exception:
            d["evidence"] = d.get("evidence_json", "{}")
        return d


def update_alert_triage(
    alert_id: int,
    status: str,
    notes: Optional[str] = None,
    firewall_action: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> bool:
    """Update operator triage status and notes for an alert."""
    valid_statuses = {"OPEN", "INVESTIGATING", "CONFIRMED", "BENIGN", "FALSE_POSITIVE", "RESOLVED"}
    status = status.upper()
    if status not in valid_statuses:
        raise ValueError(f"Invalid status: {status}. Must be one of {valid_statuses}")

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        updates = ["status = ?"]
        params: List[Any] = [status]

        if notes is not None:
            updates.append("operator_notes = ?")
            params.append(notes)
        if firewall_action is not None:
            updates.append("firewall_action_taken = ?")
            params.append(firewall_action)

        params.append(alert_id)
        query = f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Firewall operations
# -----------------------------------------------------------------------------

def insert_firewall_rule(rule: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record an application-managed firewall block rule."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        # Migrate: ensure operator column exists
        try:
            cursor.execute("ALTER TABLE firewall_rules ADD COLUMN operator TEXT DEFAULT 'SYSTEM'")
            conn.commit()
        except Exception:
            pass
        cursor.execute("""
            INSERT INTO firewall_rules (
                ip_address, direction, action, backend, reason, alert_id,
                created_at, expires_at, is_active, is_permanent, verified_state, removal_reason, operator
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(rule.get("ip_address")),
            str(rule.get("direction", "ALL")),
            str(rule.get("action", "BLOCK")),
            str(rule.get("backend", "unknown")),
            str(rule.get("reason", "Suspicious traffic")),
            rule.get("alert_id"),
            float(rule.get("created_at", time.time())),
            float(rule["expires_at"]) if rule.get("expires_at") is not None else None,
            1 if rule.get("is_active", True) else 0,
            1 if rule.get("is_permanent", False) else 0,
            str(rule.get("verified_state", "UNVERIFIED")),
            rule.get("removal_reason"),
            str(rule.get("operator", "SYSTEM"))
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_active_firewall_rules(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Get all rules marked active in database with formatted timestamp strings."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM firewall_rules WHERE is_active = 1 ORDER BY id DESC")
        rows = [dict(row) for row in cursor.fetchall()]
        for r in rows:
            if r.get("created_at"):
                r["datetime_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))
            if r.get("expires_at"):
                r["expires_at_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["expires_at"]))
            else:
                r["expires_at_str"] = "NEVER (Permanent)" if r.get("is_permanent") else "N/A"
            # Ensure operator field always present for frontend badge logic
            if "operator" not in r or r["operator"] is None:
                r["operator"] = "SYSTEM"
        return rows


def get_expired_firewall_rules(now_ts: Optional[float] = None, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Get active non-permanent rules whose expiration timestamp has passed."""
    ts = now_ts or time.time()
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM firewall_rules
            WHERE is_active = 1
              AND is_permanent = 0
              AND expires_at IS NOT NULL
              AND expires_at <= ?
        """, (ts,))
        return [dict(row) for row in cursor.fetchall()]


def update_firewall_rule_status(
    rule_id: int,
    is_active: bool,
    verified_state: str,
    removal_reason: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> bool:
    """Update active status and verified state for a rule."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE firewall_rules
            SET is_active = ?, verified_state = ?, removal_reason = COALESCE(?, removal_reason)
            WHERE id = ?
        """, (1 if is_active else 0, verified_state, removal_reason, rule_id))
        conn.commit()
        return cursor.rowcount > 0


def update_firewall_rule_state_by_ip(
    ip_address: str,
    is_active: bool,
    verified_state: str,
    removal_reason: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> bool:
    """Update active rules for a specific IP address."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE firewall_rules
            SET is_active = ?, verified_state = ?, removal_reason = COALESCE(?, removal_reason)
            WHERE ip_address = ? AND is_active = 1
        """, (1 if is_active else 0, verified_state, removal_reason, ip_address))
        conn.commit()
        return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Audit log operations
# -----------------------------------------------------------------------------

def log_audit(
    event_type: str,
    details: str,
    user_or_system: str = "SYSTEM",
    status: str = "SUCCESS",
    db_path: str = DEFAULT_DB_PATH
) -> int:
    """Record an event in the security audit log."""
    ts = time.time()
    dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (timestamp, datetime_str, event_type, user_or_system, details, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ts, dt_str, event_type, user_or_system, details, status))
        conn.commit()
        return cursor.lastrowid or 0


def get_recent_audit_logs(limit: int = 100, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve recent audit logs in descending order."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]


# -----------------------------------------------------------------------------
# Aggregates & System Summary
# -----------------------------------------------------------------------------

def get_summary_stats(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Calculate live dashboard overview metrics."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        # Total packets and bytes
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(length), 0) FROM packets")
        row = cursor.fetchone()
        pkt_count = row[0] if row else 0
        total_bytes = row[1] if row else 0

        # Active flows
        cursor.execute("SELECT COUNT(*) FROM flows WHERE state = 'ACTIVE'")
        row = cursor.fetchone()
        active_flows = row[0] if row else 0

        # Alerts summary
        cursor.execute("SELECT COUNT(*) FROM alerts")
        row = cursor.fetchone()
        total_alerts = row[0] if row else 0

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
        row = cursor.fetchone()
        critical_alerts = row[0] if row else 0

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('OPEN', 'INVESTIGATING')")
        row = cursor.fetchone()
        unresolved_alerts = row[0] if row else 0

        # Active firewall blocks
        cursor.execute("SELECT COUNT(*) FROM firewall_rules WHERE is_active = 1")
        row = cursor.fetchone()
        active_blocks = row[0] if row else 0

        # Protocol distribution (last 1000 packets)
        cursor.execute("""
            SELECT protocol, COUNT(*) as cnt
            FROM (SELECT protocol FROM packets ORDER BY id DESC LIMIT 1000)
            GROUP BY protocol ORDER BY cnt DESC
        """)
        protocols = {row["protocol"]: row["cnt"] for row in cursor.fetchall()}

        return {
            "total_packets": pkt_count,
            "packets_captured": pkt_count,          # alias for dashboard JS
            "total_bytes": total_bytes,
            "active_flows": active_flows,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "unresolved_alerts": unresolved_alerts,
            "active_blocks": active_blocks,
            "active_firewall_blocks": active_blocks, # alias for dashboard JS
            "protocols": protocols
        }


def prune_old_data(
    retention_days: int = 7,
    max_packets: int = 50000,
    max_flows: int = 20000,
    db_path: str = DEFAULT_DB_PATH
) -> Tuple[int, int]:
    """Prune packet and flow records exceeding retention or limits."""
    cutoff_ts = time.time() - (retention_days * 86400)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        # Delete expired packets
        cursor.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff_ts,))
        deleted_pkts = cursor.rowcount

        # Bound maximum packets
        cursor.execute("SELECT COUNT(*) FROM packets")
        curr_pkts = cursor.fetchone()[0]
        if curr_pkts > max_packets:
            excess = curr_pkts - max_packets
            cursor.execute("""
                DELETE FROM packets WHERE id IN (
                    SELECT id FROM packets ORDER BY id ASC LIMIT ?
                )
            """, (excess,))
            deleted_pkts += cursor.rowcount

        # Bound maximum flows
        cursor.execute("DELETE FROM flows WHERE last_time < ? AND state = 'EXPIRED'", (cutoff_ts,))
        deleted_flows = cursor.rowcount

        cursor.execute("SELECT COUNT(*) FROM flows")
        curr_flows = cursor.fetchone()[0]
        if curr_flows > max_flows:
            excess = curr_flows - max_flows
            cursor.execute("""
                DELETE FROM flows WHERE id IN (
                    SELECT id FROM flows ORDER BY last_time ASC LIMIT ?
                )
            """, (excess,))
            deleted_flows += cursor.rowcount

        conn.commit()
        return deleted_pkts, deleted_flows


# -----------------------------------------------------------------------------
# Protection Rules, Decisions, Rejections, Operations & System State
# -----------------------------------------------------------------------------

def insert_response_decision(decision: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record an evaluated threat response decision."""
    ev = decision.get("evidence_summary", {})
    ev_json = json.dumps(ev) if isinstance(ev, dict) else str(ev)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO response_decisions (
                alert_id, target_ip, severity, confidence, action,
                decision_code, reason, protection_category, block_duration_sec,
                evidence_json, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            decision.get("alert_id"),
            str(decision.get("target_ip", "")),
            str(decision.get("severity", "LOW")),
            decision.get("confidence", 1.0),
            str(decision.get("action", "ALERT_ONLY")),
            str(decision.get("decision_code", "UNKNOWN")),
            str(decision.get("reason", "")),
            str(decision.get("protection_category", "UNPROTECTED")),
            float(decision.get("block_duration_sec", 0.0)),
            ev_json,
            float(decision.get("evaluated_at", time.time()))
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_response_decisions(
    limit: int = 50,
    offset: int = 0,
    target_ip: Optional[str] = None,
    action: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve evaluated threat response decisions."""
    query = "SELECT * FROM response_decisions WHERE 1=1"
    params: List[Any] = []
    if target_ip:
        query += " AND target_ip = ?"
        params.append(target_ip)
    if action:
        query += " AND action = ?"
        params.append(action)
    query += " ORDER BY evaluated_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def insert_rejected_block(rejected: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record a rejected firewall block request with explicit reason code."""
    ts = float(rejected.get("timestamp", time.time()))
    dt_str = rejected.get("datetime_str", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)))
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO rejected_blocks (
                ip_address, alert_id, reason_code, category, details, requested_by, timestamp, datetime_str
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(rejected.get("ip_address", "")),
            rejected.get("alert_id"),
            str(rejected.get("reason_code", "UNKNOWN")),
            str(rejected.get("category", "CATEGORY_A")),
            str(rejected.get("details", "")),
            str(rejected.get("requested_by", "SYSTEM")),
            ts,
            dt_str
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_rejected_blocks(
    limit: int = 50,
    offset: int = 0,
    ip_address: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Query rejected block log."""
    query = "SELECT * FROM rejected_blocks WHERE 1=1"
    params: List[Any] = []
    if ip_address:
        query += " AND ip_address = ?"
        params.append(ip_address)
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


def insert_firewall_operation(op: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record an OS firewall command execution and its verified result."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO firewall_operations (
                timestamp, operation, ip_address, backend, command,
                returncode, verified_state, details, operator
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            float(op.get("timestamp", time.time())),
            str(op.get("operation", "BLOCK")),
            str(op.get("ip_address", "")),
            str(op.get("backend", "")),
            str(op.get("command", "")),
            op.get("returncode"),
            str(op.get("verified_state", "UNVERIFIED")),
            str(op.get("details", "")),
            str(op.get("operator", "SYSTEM"))
        ))
        conn.commit()
        return cursor.lastrowid or 0


def get_firewall_operations(
    limit: int = 50,
    offset: int = 0,
    ip_address: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Retrieve history of OS firewall operations."""
    query = "SELECT * FROM firewall_operations WHERE 1=1"
    params: List[Any] = []
    if ip_address:
        query += " AND ip_address = ?"
        params.append(ip_address)
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


def get_system_state(key: str, default: Any = None, db_path: str = DEFAULT_DB_PATH) -> Any:
    """Get runtime system state variable."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_state WHERE key = ?", (key,))
        row = cursor.fetchone()
        if row:
            try:
                return json.loads(row["value"])
            except Exception:
                return row["value"]
        return default


def set_system_state(key: str, val: Any, db_path: str = DEFAULT_DB_PATH) -> None:
    """Store runtime system state variable."""
    now = time.time()
    val_str = json.dumps(val) if not isinstance(val, str) else val
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO system_state (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """, (key, val_str, now))
        conn.commit()

