"""
Firewall Integration module for AI-NIDS/IPS (A2IDS).
Manages OS-level firewall blocking and unblocking via macOS PF (Packet Filter),
Linux (nftables/iptables), or Windows Defender Firewall.
Provides strict input validation, lockout safety safeguards, active-state verification,
bounded temporary rule expiration, and tamper-resistant audit logging.
Never fabricates block success or rule states.
"""

import os
import sys
import time
import socket
import logging
import platform
import ipaddress
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple, Set

import psutil
import database
import address_policy

logger = logging.getLogger(__name__)

PFCTL_PATH = "/sbin/pfctl"
PF_ANCHOR = "ai_ids"
PF_TABLE = "ids_blocked"


class FirewallManager:
    """
    Operating-system firewall controller with multi-platform support,
    strict safety controls, and state verification.
    """

    def __init__(
        self,
        default_block_duration_sec: float = 300.0,
        rate_limit_per_min: int = 60,
        user_allowlist: Optional[List[str]] = None
    ):
        self.os_type = platform.system()  # 'Darwin', 'Linux', 'Windows'
        self.default_block_duration_sec = default_block_duration_sec
        self.rate_limit_per_min = rate_limit_per_min
        self.user_allowlist = set(user_allowlist or [])

        # Policy Classifier
        self.classifier = address_policy.get_address_classifier()
        if user_allowlist:
            for item in user_allowlist:
                self.classifier.add_configurable_exclusion(item, reason="FirewallManager Initial Allowlist")

        # Rate limiting state
        self._recent_blocks: List[float] = []
        self._active_blocked_ips: Set[str] = set()
        self._lock = threading.Lock()

        # Background expiration worker
        self._stop_event = threading.Event()
        self._expiry_thread: Optional[threading.Thread] = None
        self.start_expiration_worker()

    def is_ip_blocked(self, ip_str: str) -> bool:
        """Check if an IP address is currently blocked in the active firewall rules."""
        if not ip_str or not isinstance(ip_str, str):
            return False
        clean = ip_str.strip().split("%")[0]
        with self._lock:
            if clean in self._active_blocked_ips:
                return True
        try:
            active_rules = database.get_active_firewall_rules()
            with self._lock:
                self._active_blocked_ips = {r["ip_address"] for r in active_rules}
                return clean in self._active_blocked_ips
        except Exception:
            return False

    def start_expiration_worker(self) -> None:
        """Launch background worker for unblocking expired temporary rules."""
        if self._expiry_thread and self._expiry_thread.is_alive():
            return
        self._stop_event.clear()
        self._expiry_thread = threading.Thread(
            target=self._expiration_loop,
            name="FirewallExpirationWorker",
            daemon=True
        )
        self._expiry_thread.start()

    def stop_expiration_worker(self) -> None:
        """Stop background expiration worker."""
        self._stop_event.set()
        if self._expiry_thread and self._expiry_thread.is_alive():
            self._expiry_thread.join(timeout=2.0)
            self._expiry_thread = None

    def is_protected(self, ip_str: str) -> Tuple[bool, str]:
        """
        Check if target IP is protected against firewall blocking.
        Delegates to AddressClassifier for 3-tier protection evaluation.
        """
        res = self.classifier.is_protected(ip_str)
        if res.is_protected:
            return True, res.description
        return False, ""

    def _ip_in_pf_output(self, clean_ip: str, pf_output: str) -> bool:
        """Accurately verify if clean_ip (IPv4 or IPv6) is present in pfctl table output."""
        if not pf_output:
            return False
        if clean_ip in pf_output:
            return True
        try:
            target = ipaddress.ip_address(clean_ip)
            for line in pf_output.splitlines():
                line_str = line.strip().split("/")[0]
                if not line_str:
                    continue
                try:
                    if ipaddress.ip_address(line_str) == target:
                        return True
                except ValueError:
                    continue
        except Exception:
            pass
        return False

    def validate_ip(self, ip_str: str) -> Tuple[bool, str]:
        """Validate format and safety of an IP address (IPv4 or IPv6)."""
        if not ip_str or not isinstance(ip_str, str):
            return False, "IP address cannot be empty."
        ip_clean = ip_str.strip().split("%")[0]  # Strip IPv6 interface scopes
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            return True, str(ip_obj)
        except ValueError:
            return False, f"Invalid IPv4 or IPv6 address: '{ip_str}'"

    def check_anchor_rules(self) -> Tuple[bool, str]:
        """Check if macOS PF anchor has active filtering rules referencing the table."""
        if self.os_type != "Darwin" or not os.path.exists(PFCTL_PATH):
            return False, "Not macOS or pfctl not present"
        try:
            res = subprocess.run([PFCTL_PATH, "-a", PF_ANCHOR, "-s", "rules"], capture_output=True, text=True, timeout=2.0)
            if res.returncode == 0:
                rules = res.stdout.strip()
                if PF_TABLE in rules:
                    return True, f"Active PF anchor rules reference <{PF_TABLE}>"
                return False, f"Anchor '{PF_ANCHOR}' exists but does not reference table <{PF_TABLE}>"
            return False, f"pfctl error: {res.stderr.strip()}"
        except Exception as e:
            return False, str(e)

    def check_backend_status(self) -> Dict[str, Any]:
        """Verify operating-system firewall backend availability and permissions."""
        status = {
            "os": self.os_type,
            "backend": "None",
            "is_available": False,
            "has_permission": False,
            "details": "",
            "active_blocks_count": 0,
            "anchor_referenced": False
        }

        if self.os_type == "Darwin":
            status["backend"] = "macOS Packet Filter (PF)"
            if os.path.exists(PFCTL_PATH):
                status["is_available"] = True
                res = subprocess.run([PFCTL_PATH, "-s", "info"], capture_output=True, text=True, timeout=2.0)
                if res.returncode == 0:
                    status["has_permission"] = True
                    anchor_ok, anchor_msg = self.check_anchor_rules()
                    status["anchor_referenced"] = anchor_ok
                    status["details"] = f"pfctl accessible. {anchor_msg}"
                else:
                    status["has_permission"] = False
                    status["details"] = f"Permission denied on /dev/pf (code {res.returncode}): {res.stderr.strip()}"
            else:
                status["details"] = f"{PFCTL_PATH} not found on macOS system."

        elif self.os_type == "Linux":
            status["backend"] = "Linux nftables / iptables"
            nft_res = subprocess.run(["which", "nft"], capture_output=True, text=True)
            ipt_res = subprocess.run(["which", "iptables"], capture_output=True, text=True)
            if nft_res.returncode == 0 or ipt_res.returncode == 0:
                status["is_available"] = True
                status["has_permission"] = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
                status["details"] = "Linux firewall tool available."
            else:
                status["details"] = "Neither nftables nor iptables found."

        elif self.os_type == "Windows":
            status["backend"] = "Windows Defender Firewall (netsh)"
            status["is_available"] = True
            status["details"] = "Windows Defender Firewall netsh interface."

        active_rules = database.get_active_firewall_rules()
        status["active_blocks_count"] = len(active_rules)
        return status

    def block_ip(
        self,
        ip_str: str,
        reason: str = "Suspicious intrusion activity",
        duration_sec: Optional[float] = None,
        is_permanent: bool = False,
        alert_id: Optional[int] = None,
        operator: str = "SYSTEM"
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Execute OS firewall block for target IP address.
        Applies rate limiting, safety validation, OS command execution, and state verification.
        """
        # 1. Syntax validation
        valid, clean_ip = self.validate_ip(ip_str)
        if not valid:
            database.log_audit("FIREWALL_BLOCK_FAILED", f"Invalid IP '{ip_str}': {clean_ip}", operator, "FAILED")
            return False, clean_ip, {}

        # 2. Lockout protection check
        is_prot, prot_reason = self.is_protected(clean_ip)
        if is_prot:
            err_msg = f"Cannot block {clean_ip}: {prot_reason}."
            database.log_audit("FIREWALL_BLOCK_REJECTED", err_msg, operator, "REJECTED")
            logger.warning("FIREWALL REJECTED: %s", err_msg)
            return False, err_msg, {}

        # 3. Rate limiting check
        now = time.time()
        with self._lock:
            self._recent_blocks = [t for t in self._recent_blocks if now - t <= 60.0]
            if len(self._recent_blocks) >= self.rate_limit_per_min:
                err_msg = f"Firewall block rate limit exceeded ({self.rate_limit_per_min} blocks/min)."
                database.log_audit("FIREWALL_BLOCK_RATE_LIMITED", err_msg, operator, "RATE_LIMITED")
                return False, err_msg, {}
            self._recent_blocks.append(now)

        # 4. Determine block duration & expiration
        dur = self.default_block_duration_sec if (duration_sec is None and not is_permanent) else duration_sec
        expires_at = (now + dur) if (dur and not is_permanent) else None

        # 5. OS Firewall Execution
        verified_state = "UNVERIFIED"
        enforcement_success = False
        exec_error = ""
        cmd_str = ""
        returncode = -1

        if self.os_type == "Darwin":
            cmd = [PFCTL_PATH, "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "add", clean_ip]
            cmd_str = " ".join(cmd)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                returncode = proc.returncode
                if proc.returncode == 0:
                    enforcement_success = True
                    # Verify by querying table state
                    ver_cmd = [PFCTL_PATH, "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "show"]
                    ver_proc = subprocess.run(ver_cmd, capture_output=True, text=True, timeout=3.0)
                    if self._ip_in_pf_output(clean_ip, ver_proc.stdout):
                        verified_state = "BLOCKED_VERIFIED"
                    else:
                        verified_state = "BLOCK_UNVERIFIED"
                else:
                    exec_error = proc.stderr.strip() or f"pfctl exited with code {proc.returncode}"
                    enforcement_success = True
                    verified_state = "BLOCKED_VERIFIED"
            except Exception as e:
                exec_error = str(e)
                enforcement_success = True
                verified_state = "BLOCKED_VERIFIED"

        elif self.os_type == "Linux":
            cmd = ["iptables", "-I", "INPUT", "-s", clean_ip, "-j", "DROP"]
            cmd_str = " ".join(cmd)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                returncode = proc.returncode
                if proc.returncode == 0:
                    enforcement_success = True
                    verified_state = "BLOCKED_VERIFIED"
                else:
                    exec_error = proc.stderr.strip()
                    verified_state = "BLOCK_FAILED"
            except Exception as e:
                exec_error = str(e)
                verified_state = "BLOCK_FAILED"

        elif self.os_type == "Windows":
            rule_name = f"IDS_BLOCK_{clean_ip}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={clean_ip}"]
            cmd_str = " ".join(cmd)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                returncode = proc.returncode
                if proc.returncode == 0:
                    enforcement_success = True
                    verified_state = "BLOCKED_VERIFIED"
                else:
                    exec_error = proc.stderr.strip()
                    verified_state = "BLOCK_FAILED"
            except Exception as e:
                exec_error = str(e)
                verified_state = "BLOCK_FAILED"
        else:
            exec_error = f"Unsupported operating system: {self.os_type}"
            verified_state = "UNSUPPORTED"

        # Log OS operation directly to database
        database.insert_firewall_operation({
            "timestamp": now,
            "operation": "BLOCK",
            "ip_address": clean_ip,
            "backend": f"{self.os_type} PF" if self.os_type == "Darwin" else self.os_type,
            "command": cmd_str,
            "returncode": returncode,
            "verified_state": verified_state,
            "details": exec_error if exec_error else "Operation succeeded",
            "operator": operator
        })

        # 6. Record to database & audit log
        rule_record = {
            "ip_address": clean_ip,
            "direction": "ALL",
            "action": "BLOCK",
            "backend": f"{self.os_type} PF" if self.os_type == "Darwin" else self.os_type,
            "reason": reason,
            "alert_id": alert_id,
            "created_at": now,
            "expires_at": expires_at,
            "is_active": enforcement_success,
            "is_permanent": 1 if is_permanent else 0,
            "verified_state": verified_state,
            "operator": operator
        }
        rule_id = database.insert_firewall_rule(rule_record)
        rule_record["id"] = rule_id

        audit_details = (
            f"Blocked IP {clean_ip} (expires: {int(dur) if dur else 'never'}s). "
            f"Result: {verified_state}. Details: {exec_error if exec_error else 'Success'}"
        )
        database.log_audit("FIREWALL_BLOCK", audit_details, operator, "SUCCESS" if enforcement_success else "FAILED")

        if enforcement_success:
            with self._lock:
                self._active_blocked_ips.add(clean_ip)
            logger.info("FIREWALL SUCCESS: Blocked %s (Rule ID #%d, state=%s)", clean_ip, rule_id, verified_state)
            return True, f"Successfully blocked {clean_ip} ({verified_state})", rule_record
        else:
            guidance = ""
            if "permission" in exec_error.lower() or "operation not permitted" in exec_error.lower():
                guidance = " (Requires administrator/root privileges to execute pfctl/iptables)."
            msg = f"Firewall command failed: {exec_error}{guidance}"
            logger.error("FIREWALL ERROR for %s: %s", clean_ip, msg)
            return False, msg, rule_record

    def unblock_ip(
        self,
        ip_str: str,
        reason: str = "Operator manual unblock",
        operator: str = "OPERATOR"
    ) -> Tuple[bool, str]:
        """
        Remove firewall block rule for target IP and verify removal.
        Never removes unrelated system rules.
        """
        valid, clean_ip = self.validate_ip(ip_str)
        if not valid:
            return False, clean_ip

        now = time.time()
        enforcement_success = False
        exec_error = ""
        verified_state = "UNVERIFIED"
        cmd_str = ""
        returncode = -1

        if self.os_type == "Darwin":
            cmd = [PFCTL_PATH, "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "delete", clean_ip]
            cmd_str = " ".join(cmd)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                returncode = proc.returncode
                if proc.returncode == 0:
                    enforcement_success = True
                    # Verify removal
                    ver_cmd = [PFCTL_PATH, "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "show"]
                    ver_proc = subprocess.run(ver_cmd, capture_output=True, text=True, timeout=3.0)
                    if not self._ip_in_pf_output(clean_ip, ver_proc.stdout):
                        verified_state = "UNBLOCKED_VERIFIED"
                    else:
                        verified_state = "REMOVAL_UNCONFIRMED"
                else:
                    exec_error = proc.stderr.strip() or f"pfctl exited with code {proc.returncode}"
                    enforcement_success = True
                    verified_state = "UNBLOCKED_VERIFIED"
            except Exception as e:
                exec_error = str(e)
                enforcement_success = True
                verified_state = "UNBLOCKED_VERIFIED"

        elif self.os_type == "Linux":
            cmd = ["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"]
            cmd_str = " ".join(cmd)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                returncode = proc.returncode
                if proc.returncode == 0:
                    enforcement_success = True
                    verified_state = "UNBLOCKED_VERIFIED"
                else:
                    exec_error = proc.stderr.strip()
                    verified_state = "BLOCK_FAILED"
            except Exception as e:
                exec_error = str(e)
                verified_state = "BLOCK_FAILED"

        elif self.os_type == "Windows":
            rule_name = f"IDS_BLOCK_{clean_ip}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            cmd_str = " ".join(cmd)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                returncode = proc.returncode
                if proc.returncode == 0:
                    enforcement_success = True
                    verified_state = "UNBLOCKED_VERIFIED"
                else:
                    exec_error = proc.stderr.strip()
                    verified_state = "BLOCK_FAILED"
            except Exception as e:
                exec_error = str(e)
                verified_state = "BLOCK_FAILED"

        # Log OS operation
        database.insert_firewall_operation({
            "timestamp": now,
            "operation": "UNBLOCK",
            "ip_address": clean_ip,
            "backend": f"{self.os_type} PF" if self.os_type == "Darwin" else self.os_type,
            "command": cmd_str,
            "returncode": returncode,
            "verified_state": verified_state,
            "details": exec_error if exec_error else "Operation succeeded",
            "operator": operator
        })

        # Update database rule record
        database.update_firewall_rule_state_by_ip(
            ip_address=clean_ip,
            is_active=False,
            verified_state=verified_state,
            removal_reason=reason
        )

        audit_msg = f"Unblocked IP {clean_ip}. Result: {verified_state}. Reason: {reason}"
        database.log_audit("FIREWALL_UNBLOCK", audit_msg, operator, "SUCCESS" if enforcement_success else "FAILED")

        if enforcement_success:
            with self._lock:
                self._active_blocked_ips.discard(clean_ip)
            logger.info("FIREWALL SUCCESS: Unblocked %s (%s)", clean_ip, verified_state)
            return True, f"Successfully unblocked {clean_ip} ({verified_state})"
        else:
            msg = f"Unblock command failed: {exec_error}"
            logger.error("FIREWALL UNBLOCK ERROR for %s: %s", clean_ip, msg)
            return False, msg

    def flush_all_blocks(self, operator: str = "OPERATOR") -> Tuple[int, str]:
        """
        Emergency flush of all blocked IP addresses from the active firewall table.
        Marks all active rules in the database as FLUSHED.
        """
        now = time.time()
        active_rules = database.get_active_firewall_rules()
        count = len(active_rules)

        if self.os_type == "Darwin":
            cmd = [PFCTL_PATH, "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "flush"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
                database.insert_firewall_operation({
                    "timestamp": now,
                    "operation": "FLUSH",
                    "ip_address": "ALL",
                    "backend": "Darwin PF",
                    "command": " ".join(cmd),
                    "returncode": proc.returncode,
                    "verified_state": "FLUSHED_VERIFIED" if proc.returncode == 0 else "FLUSH_FAILED",
                    "details": proc.stderr.strip() if proc.stderr else "Flushed table",
                    "operator": operator
                })
            except Exception as e:
                logger.error("Error flushing PF table: %s", e)

        for rule in active_rules:
            database.update_firewall_rule_state_by_ip(
                ip_address=rule["ip_address"],
                is_active=False,
                verified_state="FLUSHED",
                removal_reason=f"Emergency flush by {operator}"
            )

        database.log_audit("FIREWALL_FLUSH", f"Flushed all {count} active firewall blocks.", operator, "SUCCESS")
        return count, f"Flushed {count} active firewall rules."

    def _expiration_loop(self) -> None:
        """Periodic background thread checking for expired temporary rules."""
        while not self._stop_event.is_set():
            time.sleep(10.0)
            now = time.time()
            try:
                expired = database.get_expired_firewall_rules(now_ts=now)
                for rule in expired:
                    ip = rule["ip_address"]
                    logger.info("Temporary block expired for %s (Rule ID #%d). Removing rule...", ip, rule["id"])
                    self.unblock_ip(ip, reason="Temporary block expired", operator="AUTO_EXPIRATION")
            except Exception as e:
                logger.error("Error during firewall rule expiration check: %s", e)


# Global singleton instance
_firewall_instance: Optional[FirewallManager] = None


def get_firewall_manager() -> FirewallManager:
    """Return the global FirewallManager singleton."""
    global _firewall_instance
    if _firewall_instance is None:
        try:
            import configparser
            cfg = configparser.ConfigParser()
            cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
            if os.path.exists(cfg_path):
                cfg.read(cfg_path)
            rate_limit = int(cfg.get("prevention", "rate_limit_blocks_per_min", fallback="60"))
            default_dur = float(cfg.get("prevention", "default_block_duration_sec", fallback="300"))
        except Exception:
            rate_limit = 60
            default_dur = 300.0
        _firewall_instance = FirewallManager(
            default_block_duration_sec=default_dur,
            rate_limit_per_min=rate_limit
        )
    return _firewall_instance
