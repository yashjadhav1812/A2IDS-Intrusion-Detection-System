"""
Main Flask Application for AI-NIDS/IPS.
REST API, SSE streaming, configuration management, and prevention policy engine.
Binds to localhost only. Never exposes privileged endpoints publicly.
"""

import os
import sys
import json
import time
import queue
import logging
import configparser
import threading
from typing import Dict, Any, Optional
from functools import wraps

from flask import Flask, request, jsonify, render_template, Response, stream_with_context, abort

# Initialize core subsystems
import database
import sniffer as sniffer_module
import flow_engine as flow_module
import detector as detector_module
import firewall as firewall_module
import ai_assistant as ai_module

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")

def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if os.path.exists(CONFIG_PATH):
        cfg.read(CONFIG_PATH)
    return cfg

config = load_config()

def get_cfg(section: str, key: str, fallback: Any = None) -> Any:
    return config.get(section, key, fallback=str(fallback) if fallback is not None else None)

# ─────────────────────────────────────────────
# Flask Application
# ─────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = get_cfg("system", "secret_key", "ids-local-dev-key-change-in-production")

# ─────────────────────────────────────────────
# SSE Event Queue (live packet streaming)
# ─────────────────────────────────────────────
_sse_clients: list = []
_sse_lock = threading.Lock()
_sse_queue: queue.Queue = queue.Queue(maxsize=5000)

# Prevention Mode: 1=Detection Only, 2=Assisted, 3=Automatic
_prevention_mode: int = int(get_cfg("prevention", "prevention_mode", 1))

# ─────────────────────────────────────────────
# Subsystem singletons
# ─────────────────────────────────────────────
def get_sniffer():   return sniffer_module.get_sniffer()
def get_flow_engine(): return flow_module.get_flow_engine()
def get_detector():   return detector_module.get_threat_detector()
def get_firewall():   return firewall_module.get_firewall_manager()
def get_assistant():  return ai_module.get_assistant()

# ─────────────────────────────────────────────
# Packet Processing Pipeline
# ─────────────────────────────────────────────
def on_packet_received(pkt: Dict[str, Any], raw_pkt: Any) -> None:
    """Callback chaining: Flow Aggregation → Threat Detection → Auto-Block → DB Persist → SSE Push"""
    try:
        # 1. Flow aggregation
        flow_eng = get_flow_engine()
        flow_result = flow_eng.process_packet(pkt)

        # 2. Packet-level detection
        det = get_detector()
        alert = det.process_packet(pkt)

        # 3. Flow-level detection (on flow update)
        flow_alert = None
        if flow_result:
            flow_alert = det.process_flow(flow_result.get_statistics(), flow_result)
            if flow_alert and _prevention_mode == 3:
                _maybe_auto_block(flow_alert)

        if alert and _prevention_mode == 3:
            _maybe_auto_block(alert)

        # 4. Accurate detection & firewall block status
        fw = get_firewall()
        src_ip = pkt.get("src_ip", "")
        if fw.is_ip_blocked(src_ip):
            det_status = "BLOCKED"
        elif alert or flow_alert:
            det_status = "THREAT"
        else:
            det_status = "NORMAL"

        pkt["detection_status"] = det_status

        # 5. Persist to database (bounded — prune handles overflow)
        database.insert_packet(pkt)

        # 6. Push packet to SSE queue for live dashboard
        pkt_summary = {
            "id": int(time.time() * 1000),
            "timestamp": pkt.get("datetime_str"),
            "src_ip": src_ip,
            "dst_ip": pkt.get("dst_ip"),
            "src_port": pkt.get("src_port"),
            "dst_port": pkt.get("dst_port"),
            "protocol": pkt.get("protocol"),
            "length": pkt.get("length"),
            "tcp_flags": pkt.get("tcp_flags"),
            "interface": pkt.get("interface"),
            "direction": pkt.get("direction"),
            "detection_status": det_status
        }
        try:
            _sse_queue.put_nowait({"type": "packet", "data": pkt_summary})
        except queue.Full:
            pass

    except Exception as e:
        logger.error("Packet pipeline error: %s", e)


def _maybe_auto_block(alert: Dict[str, Any]) -> None:
    """Evaluate threat response policy and apply automatic prevention via Safety Controller."""
    import response_policy
    import safety_controller

    src_ip = alert.get("src_ip", "")
    sev = alert.get("severity", "LOW")
    conf = alert.get("confidence")
    alert_id = alert.get("id")

    # Evaluate response policy
    resp_pol = response_policy.get_response_policy(
        prevention_mode=_prevention_mode,
        auto_block_severities=[s.strip() for s in get_cfg("prevention", "auto_block_severities", "CRITICAL,HIGH").split(",")],
        min_auto_block_confidence=float(get_cfg("detection", "min_ml_confidence", 0.85)),
        default_block_duration_sec=float(get_cfg("prevention", "default_block_duration_sec", 300))
    )
    # Ensure current runtime prevention mode is synchronized
    resp_pol.prevention_mode = _prevention_mode

    decision = resp_pol.evaluate(
        src_ip=src_ip,
        severity=sev,
        confidence=conf if conf is not None else 1.0,
        evidence=alert.get("evidence"),
        category=alert.get("category", "Threat Detection")
    )

    # Persist response decision to database
    decision_dict = decision.to_dict()
    decision_dict["alert_id"] = alert_id
    database.insert_response_decision(decision_dict)

    if decision.action == response_policy.ACTION_BLOCK:
        sc = safety_controller.get_safety_controller()
        block_res = sc.execute_block(
            ip_str=src_ip,
            reason=f"Auto-block: {alert.get('category')} - {alert.get('title')}",
            duration_sec=decision.block_duration_sec,
            alert_id=alert_id,
            operator="AUTO_PREVENTION",
            override_configurable=(decision.decision_code == response_policy.DECISION_CONFIGURABLE_EXCLUSION_OVERRIDDEN)
        )
        logger.info("Auto-block result for %s [Severity %s]: success=%s, state=%s, msg='%s'",
                    src_ip, sev, block_res.success, block_res.verified_state, block_res.message)
        if block_res.success and alert_id:
            database.update_alert_triage(alert_id, "CONFIRMED", firewall_action=f"AUTO_BLOCKED_{block_res.verified_state}")
            try:
                _sse_queue.put_nowait({"type": "auto_block", "data": {"ip": src_ip, "duration": decision.block_duration_sec, "alert_id": alert_id, "state": block_res.verified_state}})
            except queue.Full:
                pass
        elif alert_id:
            database.update_alert_triage(alert_id, "INVESTIGATING", firewall_action=f"BLOCK_REJECTED_{block_res.reason_code}")

    elif decision.action == response_policy.ACTION_REJECT_PROTECTED:
        if alert_id:
            database.update_alert_triage(alert_id, "INVESTIGATING", firewall_action=f"POLICY_{decision.decision_code}")
        logger.warning("Threat alert #%s from %s not blocked: %s", alert_id, src_ip, decision.reason)

# ─────────────────────────────────────────────
# Application Startup
# ─────────────────────────────────────────────
_app_initialized = False
_init_lock = threading.Lock()

@app.before_request
def ensure_initialized():
    global _app_initialized
    if not _app_initialized:
        with _init_lock:
            if not _app_initialized:
                database.init_db()
                database.log_audit("APP_STARTED", "AI-NIDS Flask application started.", "SYSTEM", "SUCCESS")
                sniff = get_sniffer()
                sniff.register_callback(on_packet_received)
                get_flow_engine().start()
                get_firewall().start_expiration_worker()
                _app_initialized = True
                logger.info("AI-NIDS application initialized successfully.")

# ─────────────────────────────────────────────
# Input Helpers
# ─────────────────────────────────────────────
def get_json_body() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}

def validate_int(val: Any, min_v: int = 0, max_v: int = 100000) -> Optional[int]:
    try:
        v = int(val)
        return v if min_v <= v <= max_v else None
    except (TypeError, ValueError):
        return None

# ─────────────────────────────────────────────
# Page Routes
# ─────────────────────────────────────────────
@app.route("/")
def page_overview():
    return render_template("index.html")

@app.route("/monitor")
def page_monitor():
    return render_template("monitor.html")

@app.route("/flows")
def page_flows():
    return render_template("analysis.html")

@app.route("/analysis")
def page_analysis():
    return render_template("analysis.html")

@app.route("/alerts")
def page_alerts():
    return render_template("alerts.html")

@app.route("/firewall")
def page_firewall():
    return render_template("firewall.html")

@app.route("/assistant")
def page_assistant():
    return render_template("assistant.html")

@app.route("/analytics")
def page_analytics():
    from flask import redirect
    return redirect("/")

@app.route("/reports")
def page_reports():
    return render_template("reports.html")

@app.route("/settings")
def page_settings():
    return render_template("settings.html")

# ─────────────────────────────────────────────
# REST API — Status
# ─────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    from model import get_model_pipeline
    sniff = get_sniffer()
    fw = get_firewall()
    ml = get_model_pipeline()
    stats = database.get_summary_stats()
    return jsonify({
        "sniffer": sniff.get_status(),
        "firewall": fw.check_backend_status(),
        "model": ml.get_status(),
        "assistant": get_assistant().get_status(),
        "prevention_mode": _prevention_mode,
        "autoblock_enabled": (_prevention_mode == 3),
        "stats": stats
    })

# ─────────────────────────────────────────────
# REST API — Interfaces
# ─────────────────────────────────────────────
@app.route("/api/interfaces")
def api_interfaces():
    interfaces = sniffer_module.get_available_interfaces()
    return jsonify({"interfaces": interfaces})

# ─────────────────────────────────────────────
# REST API — Capture Controls
# ─────────────────────────────────────────────
@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    body = get_json_body()
    interface = str(body.get("interface", "")).strip()
    bpf_filter = str(body.get("bpf_filter", "")).strip()

    if not interface:
        return jsonify({"success": False, "message": "No interface specified."}), 400

    sniff = get_sniffer()
    # Register pipeline callback if not already registered
    if on_packet_received not in sniff._packet_callbacks:
        sniff.register_callback(on_packet_received)

    ok, msg = sniff.start(interface, bpf_filter)
    database.log_audit("CAPTURE_START", f"Capture started on {interface} filter='{bpf_filter}'", "OPERATOR", "SUCCESS" if ok else "FAILED")
    return jsonify({"success": ok, "message": msg, "status": sniff.get_status()})

@app.route("/api/capture/pause", methods=["POST"])
def api_capture_pause():
    sniff = get_sniffer()
    ok, msg = sniff.pause()
    return jsonify({"success": ok, "message": msg})

@app.route("/api/capture/resume", methods=["POST"])
def api_capture_resume():
    sniff = get_sniffer()
    ok, msg = sniff.resume()
    return jsonify({"success": ok, "message": msg})

@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    sniff = get_sniffer()
    ok, msg = sniff.stop()
    database.log_audit("CAPTURE_STOP", f"Capture stopped on {sniff.current_interface}", "OPERATOR", "SUCCESS")
    return jsonify({"success": ok, "message": msg, "status": sniff.get_status()})

@app.route("/api/capture/clear", methods=["POST"])
def api_capture_clear():
    get_sniffer().clear_buffer()
    return jsonify({"success": True, "message": "Capture buffer cleared."})

@app.route("/api/capture/export", methods=["POST"])
def api_capture_export():
    body = get_json_body()
    filename = body.get("filename", f"capture_{int(time.time())}.pcap")
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".pcap"):
        safe_filename += ".pcap"
    filepath = os.path.join(BASE_DIR, "logs", safe_filename)
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

    ok, msg = get_sniffer().export_pcap(filepath)
    return jsonify({"success": ok, "message": msg, "filepath": filepath if ok else None})

# ─────────────────────────────────────────────
# REST API — Packets
# ─────────────────────────────────────────────
@app.route("/api/packets")
def api_packets():
    limit = validate_int(request.args.get("limit", 100), 1, 500) or 100
    offset = validate_int(request.args.get("offset", 0), 0, 100000) or 0
    src_ip = request.args.get("src_ip", "").strip() or None
    dst_ip = request.args.get("dst_ip", "").strip() or None
    protocol = request.args.get("protocol", "").strip().upper() or None
    det_status = request.args.get("detection_status", "").strip().upper() or None

    packets = database.get_recent_packets(limit=limit, offset=offset, protocol=protocol,
                                           src_ip=src_ip, dst_ip=dst_ip, detection_status=det_status)
    total = database.get_packet_count()
    sniff_status = get_sniffer().get_status()
    return jsonify({"packets": packets, "total": total, "sniffer": sniff_status})

# ─────────────────────────────────────────────
# REST API — Flows
# ─────────────────────────────────────────────
@app.route("/api/flows")
def api_flows():
    limit = validate_int(request.args.get("limit", 100), 1, 500) or 100
    offset = validate_int(request.args.get("offset", 0), 0, 100000) or 0
    only_anomalous = request.args.get("only_anomalous", "false").lower() == "true"

    db_flows = database.get_flows(limit=limit, offset=offset, only_anomalous=only_anomalous)
    live_flows = get_flow_engine().get_active_flows(limit=50)
    return jsonify({"db_flows": db_flows, "live_flows": live_flows,
                    "active_flow_count": get_flow_engine().get_flow_count()})

# ─────────────────────────────────────────────
# REST API — Alerts & Incidents
# ─────────────────────────────────────────────
@app.route("/api/alerts")
def api_alerts():
    limit = validate_int(request.args.get("limit", 50), 1, 200) or 50
    offset = validate_int(request.args.get("offset", 0), 0, 100000) or 0
    severity = request.args.get("severity", "").upper() or None
    status = request.args.get("status", "").upper() or None

    alerts = database.get_alerts(limit=limit, offset=offset, severity=severity, status=status)
    return jsonify({"alerts": alerts, "count": len(alerts)})

@app.route("/api/alerts/<int:alert_id>")
def api_alert_by_id(alert_id: int):
    alert = database.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": f"Alert #{alert_id} not found."}), 404
    return jsonify({"alert": alert})

@app.route("/api/alerts/<int:alert_id>/triage", methods=["POST"])
def api_alert_triage(alert_id: int):
    body = get_json_body()
    status = str(body.get("status", "")).upper().strip()
    notes = str(body.get("notes", "")).strip()

    valid_statuses = {"OPEN", "INVESTIGATING", "CONFIRMED", "BENIGN", "FALSE_POSITIVE", "RESOLVED"}
    if status not in valid_statuses:
        return jsonify({"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"}), 400

    ok = database.update_alert_triage(alert_id, status, notes)
    if ok:
        database.log_audit("ALERT_TRIAGE", f"Alert #{alert_id} → {status}. Notes: {notes[:100]}", "OPERATOR", "SUCCESS")
        return jsonify({"success": True, "message": f"Alert #{alert_id} marked as {status}."})
    return jsonify({"error": "Alert not found or update failed."}), 404

# ─────────────────────────────────────────────
# REST API — Firewall & Protection Policy
# ─────────────────────────────────────────────
@app.route("/api/firewall/status")
def api_firewall_status():
    import safety_controller
    import address_policy
    sc = safety_controller.get_safety_controller()
    ac = address_policy.get_address_classifier()
    safety_stat = sc.get_safety_status()
    active_rules = database.get_active_firewall_rules()
    summary = ac.get_all_protected_addresses()
    flat_protected = []
    for cat in ("category_a", "category_b", "category_c"):
        for item in summary.get(cat, []):
            flat_protected.append(item["address"])
    return jsonify({
        "status": safety_stat["backend"],
        "emergency_stop": sc.is_emergency_stop_active(),
        "active_rules": active_rules,
        "protected_ips": sorted(list(set(flat_protected))),
        "protected_summary": summary,
        "recent_rejections": safety_stat.get("recent_rejections", [])
    })

@app.route("/api/firewall/rules")
def api_firewall_rules():
    rules = database.get_active_firewall_rules()
    return jsonify({"rules": rules, "count": len(rules)})

@app.route("/api/firewall/block", methods=["POST"])
def api_firewall_block():
    import safety_controller
    body = get_json_body()
    ip = str(body.get("ip", "")).strip()
    reason = str(body.get("reason", "Manual operator block")).strip()
    duration_sec = body.get("duration_sec")
    is_permanent = bool(body.get("is_permanent", False))
    alert_id = body.get("alert_id")

    if not ip:
        return jsonify({"success": False, "message": "IP address required."}), 400

    dur = None
    if duration_sec is not None:
        dur = validate_int(duration_sec, 30, 86400)
        if dur is None:
            return jsonify({"success": False, "message": "Invalid duration. Must be 30–86400 seconds."}), 400

    sc = safety_controller.get_safety_controller()
    result = sc.execute_block(
        ip_str=ip,
        reason=reason,
        duration_sec=dur,
        is_permanent=is_permanent,
        alert_id=alert_id,
        operator="OPERATOR"
    )

    try:
        _sse_queue.put_nowait({"type": "firewall_update", "data": {"action": "BLOCK", "ip": ip, "success": result.success, "state": result.verified_state}})
    except queue.Full:
        pass

    return jsonify({
        "success": result.success,
        "message": result.message,
        "verified_state": result.verified_state,
        "reason_code": result.reason_code,
        "rule_id": result.rule_id,
        "rule": {
            "ip_address": result.ip_address,
            "verified_state": result.verified_state,
            "id": result.rule_id
        } if result.rule_id else None
    })

@app.route("/api/firewall/unblock", methods=["POST"])
def api_firewall_unblock():
    import safety_controller
    body = get_json_body()
    ip = str(body.get("ip", "")).strip()
    reason = str(body.get("reason", "Operator manual unblock")).strip()

    if not ip:
        return jsonify({"success": False, "message": "IP address required."}), 400

    sc = safety_controller.get_safety_controller()
    result = sc.execute_unblock(ip_str=ip, reason=reason, operator="OPERATOR")

    try:
        _sse_queue.put_nowait({"type": "firewall_update", "data": {"action": "UNBLOCK", "ip": ip, "success": result.success}})
    except queue.Full:
        pass

    return jsonify({
        "success": result.success,
        "message": result.message,
        "verified_state": result.verified_state
    })

@app.route("/api/firewall/protection-policy", methods=["GET", "POST", "DELETE"])
def api_protection_policy():
    """Retrieve or manage protected address categories."""
    import address_policy
    ac = address_policy.get_address_classifier()

    if request.method == "GET":
        ac.refresh_system_addresses()
        return jsonify({
            "success": True,
            "policies": ac.get_all_protected_addresses()
        })

    if request.method == "POST":
        body = get_json_body()
        cidr_or_ip = str(body.get("cidr_or_ip", "")).strip()
        reason = str(body.get("reason", "Operator configured exclusion")).strip()
        dur = body.get("duration_sec")
        expires_at = (time.time() + float(dur)) if dur else None

        if not cidr_or_ip:
            return jsonify({"success": False, "message": "IP address or CIDR subnet required."}), 400

        ok = ac.add_configurable_exclusion(cidr_or_ip, reason=reason, operator="OPERATOR", expires_at=expires_at)
        if ok:
            database.log_audit("CONFIGURABLE_EXCLUSION_ADDED", f"Added {cidr_or_ip}: {reason}", "OPERATOR", "SUCCESS")
            return jsonify({"success": True, "message": f"Added exclusion for {cidr_or_ip}."})
        return jsonify({"success": False, "message": f"Invalid IP/subnet syntax: '{cidr_or_ip}'"}), 400

    if request.method == "DELETE":
        body = get_json_body()
        cidr_or_ip = str(body.get("cidr_or_ip", "")).strip()
        if not cidr_or_ip:
            return jsonify({"success": False, "message": "IP address or CIDR subnet required."}), 400

        ok = ac.remove_configurable_exclusion(cidr_or_ip)
        if ok:
            database.log_audit("CONFIGURABLE_EXCLUSION_REMOVED", f"Removed {cidr_or_ip}", "OPERATOR", "SUCCESS")
            return jsonify({"success": True, "message": f"Removed exclusion for {cidr_or_ip}."})
        return jsonify({"success": False, "message": "Exclusion not found."}), 404

@app.route("/api/firewall/rejected-requests")
def api_rejected_requests():
    """Query transparent log of rejected block actions."""
    limit = min(validate_int(request.args.get("limit", 50), 1, 200) or 50, 200)
    rejections = database.get_rejected_blocks(limit=limit)
    return jsonify({"rejections": rejections, "count": len(rejections)})

@app.route("/api/firewall/decisions")
def api_threat_decisions():
    """Query threat response policy decisions."""
    limit = min(validate_int(request.args.get("limit", 50), 1, 200) or 50, 200)
    decisions = database.get_response_decisions(limit=limit)
    return jsonify({"decisions": decisions, "count": len(decisions)})

@app.route("/api/firewall/operations")
def api_firewall_operations():
    """Query low-level OS firewall command execution log."""
    limit = min(validate_int(request.args.get("limit", 50), 1, 200) or 50, 200)
    ops = database.get_firewall_operations(limit=limit)
    return jsonify({"operations": ops, "count": len(ops)})

@app.route("/api/firewall/emergency-stop", methods=["GET", "POST"])
def api_firewall_emergency_stop():
    """Emergency halt / resume for all automated blocking operations."""
    import safety_controller
    sc = safety_controller.get_safety_controller()

    if request.method == "GET":
        return jsonify({"emergency_stop": sc.is_emergency_stop_active()})

    body = get_json_body()
    action = str(body.get("action", "activate")).lower()
    flush = bool(body.get("flush", True))

    if action == "activate":
        res = sc.trigger_emergency_stop(operator="OPERATOR", flush_rules=flush)
        return jsonify({"success": True, "emergency_stop": True, "details": res})
    elif action == "resume":
        res = sc.resume_prevention(operator="OPERATOR")
        return jsonify({"success": True, "emergency_stop": False, "details": res})
    else:
        return jsonify({"error": "Invalid action. Must be 'activate' or 'resume'."}), 400

# ─────────────────────────────────────────────
# REST API — Prevention Mode
# ─────────────────────────────────────────────
@app.route("/api/prevention/mode", methods=["GET", "POST"])
def api_prevention_mode():
    global _prevention_mode
    if request.method == "POST":
        body = get_json_body()
        mode = validate_int(body.get("mode", 1), 1, 3)
        if mode is None:
            return jsonify({"error": "Mode must be 1 (Detection Only), 2 (Assisted), or 3 (Automatic)."}), 400

        old_mode = _prevention_mode
        _prevention_mode = mode
        import response_policy
        resp_pol = response_policy.get_response_policy()
        resp_pol.prevention_mode = mode

        mode_names = {1: "Detection Only", 2: "Assisted Prevention", 3: "Automatic Prevention"}
        database.log_audit("PREVENTION_MODE_CHANGE",
                            f"Mode changed from {old_mode} ({mode_names.get(old_mode)}) to {mode} ({mode_names.get(mode)})",
                            "OPERATOR", "SUCCESS")
        return jsonify({"success": True, "prevention_mode": _prevention_mode, "mode_name": mode_names.get(mode)})

    mode_names = {1: "Detection Only", 2: "Assisted Prevention", 3: "Automatic Prevention"}
    return jsonify({"prevention_mode": _prevention_mode, "mode_name": mode_names.get(_prevention_mode), "autoblock_enabled": (_prevention_mode == 3)})

@app.route("/api/prevention/autoblock", methods=["POST"])
def api_prevention_autoblock():
    global _prevention_mode
    body = get_json_body()
    enabled = bool(body.get("enabled", False))
    _prevention_mode = 3 if enabled else 1
    mode_name = "Automatic Prevention" if enabled else "Detection Only"
    database.log_audit("AUTOBLOCK_TOGGLED",
                       f"Auto-Block set to {'ON (Mode 3)' if enabled else 'OFF (Mode 1)'}",
                       "OPERATOR", "SUCCESS")
    return jsonify({
        "success": True,
        "autoblock_enabled": enabled,
        "prevention_mode": _prevention_mode,
        "mode_name": mode_name
    })

# ─────────────────────────────────────────────
# REST API — Model Status
# ─────────────────────────────────────────────
@app.route("/api/model/status")
def api_model_status():
    from model import get_model_pipeline
    return jsonify({"model": get_model_pipeline().get_status()})

# ─────────────────────────────────────────────
# REST API — AI Assistant Chat
# ─────────────────────────────────────────────
@app.route("/api/assistant/chat", methods=["POST"])
def api_assistant_chat():
    body = get_json_body()
    message = str(body.get("message", "")).strip()
    alert_id = body.get("alert_id")
    alert_id = int(alert_id) if alert_id else None

    if not message:
        return jsonify({"error": "Empty message."}), 400

    result = get_assistant().chat(message, alert_id=alert_id)
    return jsonify(result)

# ─────────────────────────────────────────────
# REST API — Audit Log
# ─────────────────────────────────────────────
@app.route("/api/audit")
def api_audit():
    limit = validate_int(request.args.get("limit", 100), 1, 500) or 100
    logs = database.get_recent_audit_logs(limit=limit)
    return jsonify({"logs": logs, "count": len(logs)})

# ─────────────────────────────────────────────
# REST API — Summary Stats
# ─────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    return jsonify(database.get_summary_stats())

# ─────────────────────────────────────────────
# SSE Endpoint — Real-Time Event Stream
# ─────────────────────────────────────────────
@app.route("/api/stream")
def api_stream():
    def event_generator():
        heartbeat_interval = 5.0
        last_heartbeat = time.time()

        while True:
            now = time.time()

            # Try to read a queued SSE event
            try:
                event = _sse_queue.get(timeout=1.0)
                payload = json.dumps(event)
                yield f"data: {payload}\n\n"
            except queue.Empty:
                pass

            # Heartbeat with live stats
            if now - last_heartbeat >= heartbeat_interval:
                sniff = get_sniffer()
                stats = {
                    "type": "heartbeat",
                    "data": {
                        "is_capturing": sniff.is_running,
                        "is_paused": sniff.is_paused,
                        "packets_per_sec": sniff.get_status().get("packets_per_sec", 0),
                        "total_packets": sniff.total_packets_captured,
                        "active_flows": get_flow_engine().get_flow_count(),
                        "timestamp": int(now * 1000)
                    }
                }
                yield f"data: {json.dumps(stats)}\n\n"
                last_heartbeat = now

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

# ─────────────────────────────────────────────
# Report Export (CSV)
# ─────────────────────────────────────────────
@app.route("/api/export/alerts")
def api_export_alerts():
    alerts = database.get_alerts(limit=10000)
    lines = ["id,timestamp,title,severity,category,src_ip,dst_ip,protocol,detection_method,status"]
    for a in alerts:
        lines.append(",".join(str(a.get(k, "")) for k in
                              ["id", "datetime_str", "title", "severity", "category",
                               "src_ip", "dst_ip", "protocol", "detection_method", "status"]))
    csv_content = "\n".join(lines)
    return Response(csv_content, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ids_alerts.csv"})

@app.route("/api/export/packets")
def api_export_packets():
    packets = database.get_recent_packets(limit=5000)
    lines = ["id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags,interface,direction"]
    for p in packets:
        lines.append(",".join(str(p.get(k, "")) for k in
                              ["id", "datetime_str", "src_ip", "dst_ip", "src_port", "dst_port",
                               "protocol", "length", "tcp_flags", "interface", "direction"]))
    csv_content = "\n".join(lines)
    return Response(csv_content, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ids_packets.csv"})

# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────
if __name__ == "__main__":
    host = get_cfg("system", "host", "127.0.0.1")
    port = int(get_cfg("system", "port", 5000))
    debug = get_cfg("system", "debug", "false").lower() == "true"

    # Initialize database before serving
    database.init_db()
    database.log_audit("APP_STARTED", "AI-NIDS Flask application started.", "SYSTEM", "SUCCESS")

    # Initialize subsystems
    get_sniffer().register_callback(on_packet_received)
    get_flow_engine().start()
    get_firewall().start_expiration_worker()

    logger.info("AI-NIDS/IPS starting at http://%s:%d", host, port)
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
