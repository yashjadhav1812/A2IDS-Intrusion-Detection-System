"""
Safety Controller for A2IDS.
Serves as the single authoritative enforcement gate for all firewall block and unblock
requests originating from automated prevention, manual UI actions, or the AI assistant.
Enforces multi-tier address protection, rate limits, emergency stop controls,
and transparent rejection auditing.
"""

import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

import address_policy
import response_policy
import database

logger = logging.getLogger(__name__)

# Rejection Reason Codes
REJECT_EMERGENCY_STOP = "REJECTED_EMERGENCY_STOP"
REJECT_ESSENTIAL_PROTECTION = "REJECTED_ESSENTIAL_PROTECTION"
REJECT_OPERATIONAL_PROTECTION = "REJECTED_OPERATIONAL_PROTECTION"
REJECT_CONFIGURABLE_EXCLUSION = "REJECTED_CONFIGURABLE_EXCLUSION"
REJECT_INVALID_IP = "REJECTED_INVALID_IP"
REJECT_RATE_LIMIT = "REJECTED_RATE_LIMIT"


@dataclass
class BlockResult:
    success: bool
    ip_address: str
    verified_state: str  # BLOCKED_VERIFIED, BLOCK_UNVERIFIED, BLOCK_FAILED, REJECTED
    reason_code: str
    message: str
    protection_tier: str = "UNPROTECTED"
    rule_id: Optional[int] = None
    alert_id: Optional[int] = None
    duration_sec: Optional[float] = None
    executed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UnblockResult:
    success: bool
    ip_address: str
    verified_state: str  # UNBLOCKED_VERIFIED, REMOVAL_FAILED, NOT_BLOCKED
    message: str
    executed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SafetyController:
    """
    Central validation and safety execution manager for network intrusion response.
    """

    def __init__(self):
        self.classifier = address_policy.get_address_classifier()
        self.emergency_stop = False
        # Load persisted emergency stop state if any
        stored_es = database.get_system_state("emergency_stop", False)
        if stored_es:
            self.emergency_stop = bool(stored_es)

    def is_emergency_stop_active(self) -> bool:
        """Check if emergency stop is engaged."""
        return self.emergency_stop

    def trigger_emergency_stop(self, operator: str = "OPERATOR", flush_rules: bool = True) -> Dict[str, Any]:
        """
        Immediately halt all automatic blocking and optionally flush active blocks.
        """
        self.emergency_stop = True
        database.set_system_state("emergency_stop", True)

        resp_pol = response_policy.get_response_policy()
        resp_pol.set_emergency_stop(True)

        flushed_count = 0
        flush_msg = "Rules preserved in current state."
        if flush_rules:
            import firewall
            fw = firewall.get_firewall_manager()
            flushed_count, flush_msg = fw.flush_all_blocks(operator=f"{operator}_EMERGENCY_STOP")

        database.log_audit(
            "EMERGENCY_STOP_ACTIVATED",
            f"Emergency stop activated by {operator}. Flush: {flush_rules} ({flushed_count} rules flushed).",
            operator,
            "CRITICAL"
        )
        logger.critical("EMERGENCY STOP ACTIVATED by %s. Automated blocking is FROZEN.", operator)

        return {
            "emergency_stop": True,
            "operator": operator,
            "flushed_count": flushed_count,
            "message": f"Emergency stop activated. {flush_msg}"
        }

    def resume_prevention(self, operator: str = "OPERATOR") -> Dict[str, Any]:
        """Disengage emergency stop and resume normal prevention operation."""
        self.emergency_stop = False
        database.set_system_state("emergency_stop", False)

        resp_pol = response_policy.get_response_policy()
        resp_pol.set_emergency_stop(False)

        database.log_audit(
            "EMERGENCY_STOP_RESUMED",
            f"Prevention resumed by {operator}. System is active.",
            operator,
            "SUCCESS"
        )
        logger.info("Emergency stop disengaged by %s. Prevention resumed.", operator)

        return {
            "emergency_stop": False,
            "operator": operator,
            "message": "Prevention operations resumed successfully."
        }

    def execute_block(
        self,
        ip_str: str,
        reason: str = "Security response",
        duration_sec: Optional[float] = None,
        is_permanent: bool = False,
        alert_id: Optional[int] = None,
        operator: str = "SYSTEM",
        override_configurable: bool = False
    ) -> BlockResult:
        """
        Authoritatively validate and execute a firewall block request.
        Unified entry point for automated rules, manual UI, and AI assistant.
        """
        now = time.time()

        # 1. Emergency Stop Gate
        if self.emergency_stop:
            err_msg = "Block rejected: Emergency stop switch is currently ACTIVE."
            database.insert_rejected_block({
                "ip_address": ip_str,
                "alert_id": alert_id,
                "reason_code": REJECT_EMERGENCY_STOP,
                "category": "EMERGENCY_HALT",
                "details": err_msg,
                "requested_by": operator,
                "timestamp": now
            })
            return BlockResult(
                success=False,
                ip_address=ip_str,
                verified_state="REJECTED",
                reason_code=REJECT_EMERGENCY_STOP,
                message=err_msg,
                protection_tier="EMERGENCY_HALT",
                alert_id=alert_id
            )

        # 2. IP Syntax and Classification
        cls = self.classifier.classify_address(ip_str)
        if not cls.is_valid:
            err_msg = f"Block rejected: {cls.description}"
            database.insert_rejected_block({
                "ip_address": ip_str,
                "alert_id": alert_id,
                "reason_code": REJECT_INVALID_IP,
                "category": "INVALID",
                "details": err_msg,
                "requested_by": operator,
                "timestamp": now
            })
            return BlockResult(
                success=False,
                ip_address=ip_str,
                verified_state="REJECTED",
                reason_code=REJECT_INVALID_IP,
                message=err_msg,
                protection_tier="INVALID",
                alert_id=alert_id
            )

        # 3. Category A — Essential System Protection (NEVER blocked)
        if cls.category == "CATEGORY_A":
            err_msg = f"Block rejected: Essential host protection ({cls.description}). Blocking would sever system connectivity."
            database.insert_rejected_block({
                "ip_address": cls.ip_str,
                "alert_id": alert_id,
                "reason_code": REJECT_ESSENTIAL_PROTECTION,
                "category": "CATEGORY_A_ESSENTIAL",
                "details": err_msg,
                "requested_by": operator,
                "timestamp": now
            })
            database.log_audit(
                "BLOCK_REJECTED_ESSENTIAL",
                f"Attempted block of essential IP {cls.ip_str} rejected. Possible spoofing. Source: {operator}",
                operator,
                "REJECTED"
            )
            return BlockResult(
                success=False,
                ip_address=cls.ip_str,
                verified_state="REJECTED",
                reason_code=REJECT_ESSENTIAL_PROTECTION,
                message=err_msg,
                protection_tier="CATEGORY_A_ESSENTIAL",
                alert_id=alert_id
            )

        # 4. Category B — Operational Protection (Gateway / DNS)
        if cls.category == "CATEGORY_B":
            # Requires explicit operator override
            if operator.upper() != "OPERATOR_OVERRIDE":
                err_msg = f"Block rejected: Operational address protection ({cls.description}). Requires manual approval."
                database.insert_rejected_block({
                    "ip_address": cls.ip_str,
                    "alert_id": alert_id,
                    "reason_code": REJECT_OPERATIONAL_PROTECTION,
                    "category": "CATEGORY_B_OPERATIONAL",
                    "details": err_msg,
                    "requested_by": operator,
                    "timestamp": now
                })
                return BlockResult(
                    success=False,
                    ip_address=cls.ip_str,
                    verified_state="REJECTED",
                    reason_code=REJECT_OPERATIONAL_PROTECTION,
                    message=err_msg,
                    protection_tier="CATEGORY_B_OPERATIONAL",
                    alert_id=alert_id
                )

        # 5. Category C — Configurable Exclusions
        if cls.category == "CATEGORY_C" and not override_configurable:
            err_msg = f"Block rejected: Target matches operator configurable exclusion list ({cls.description})."
            database.insert_rejected_block({
                "ip_address": cls.ip_str,
                "alert_id": alert_id,
                "reason_code": REJECT_CONFIGURABLE_EXCLUSION,
                "category": "CATEGORY_C_CONFIGURABLE",
                "details": err_msg,
                "requested_by": operator,
                "timestamp": now
            })
            return BlockResult(
                success=False,
                ip_address=cls.ip_str,
                verified_state="REJECTED",
                reason_code=REJECT_CONFIGURABLE_EXCLUSION,
                message=err_msg,
                protection_tier="CATEGORY_C_CONFIGURABLE",
                alert_id=alert_id
            )

        # 6. Execute OS-level Firewall Enforcement
        import firewall
        fw = firewall.get_firewall_manager()
        success, msg, rule = fw.block_ip(
            ip_str=cls.ip_str,
            reason=reason,
            duration_sec=duration_sec,
            is_permanent=is_permanent,
            alert_id=alert_id,
            operator=operator
        )

        verified_state = rule.get("verified_state", "BLOCKED_VERIFIED" if success else "BLOCK_FAILED")
        rule_id = rule.get("id")

        return BlockResult(
            success=success,
            ip_address=cls.ip_str,
            verified_state=verified_state,
            reason_code="BLOCKED_SUCCESS" if success else "ENFORCEMENT_FAILED",
            message=msg,
            protection_tier=cls.category,
            rule_id=rule_id,
            alert_id=alert_id,
            duration_sec=duration_sec,
            executed_at=now
        )

    def execute_unblock(
        self,
        ip_str: str,
        reason: str = "Operator manual unblock",
        operator: str = "OPERATOR"
    ) -> UnblockResult:
        """Execute unblocking of an address through firewall controller."""
        import firewall
        fw = firewall.get_firewall_manager()
        success, msg = fw.unblock_ip(ip_str=ip_str, reason=reason, operator=operator)
        return UnblockResult(
            success=success,
            ip_address=ip_str,
            verified_state="UNBLOCKED_VERIFIED" if success else "REMOVAL_FAILED",
            message=msg
        )

    def get_safety_status(self) -> Dict[str, Any]:
        """Aggregate health, active rules, rejected requests, and emergency status."""
        import firewall
        fw = firewall.get_firewall_manager()
        backend_status = fw.check_backend_status()
        recent_rejections = database.get_rejected_blocks(limit=10)
        protected_summary = self.classifier.get_all_protected_addresses()

        return {
            "emergency_stop": self.emergency_stop,
            "backend": backend_status,
            "protected_addresses_count": {
                "category_a": len(protected_summary["category_a"]),
                "category_b": len(protected_summary["category_b"]),
                "category_c": len(protected_summary["category_c"])
            },
            "recent_rejections": recent_rejections
        }


# Singleton instance
_safety_controller_instance: Optional[SafetyController] = None


def get_safety_controller() -> SafetyController:
    """Retrieve or initialize global SafetyController instance."""
    global _safety_controller_instance
    if _safety_controller_instance is None:
        _safety_controller_instance = SafetyController()
    return _safety_controller_instance
