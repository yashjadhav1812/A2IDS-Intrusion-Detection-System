"""
Threat Response Policy Engine for A2IDS.
Evaluates threat detections, severity levels, confidence bounds, prevention modes,
and address protection tiers to produce authoritative response decisions.
Decouples threat detection from firewall enforcement.
"""

import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

import address_policy

logger = logging.getLogger(__name__)

# Response Actions
ACTION_BLOCK = "BLOCK"
ACTION_ALERT_ONLY = "ALERT_ONLY"
ACTION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
ACTION_REJECT_PROTECTED = "REJECT_PROTECTED"

# Decision Codes
DECISION_AUTO_BLOCK_APPROVED = "AUTO_BLOCK_APPROVED"
DECISION_DETECTION_ONLY_MODE = "PREVENTION_MODE_DETECTION_ONLY"
DECISION_ASSISTED_MODE_APPROVAL = "ASSISTED_MODE_REQUIRES_APPROVAL"
DECISION_EMERGENCY_STOP_ACTIVE = "EMERGENCY_STOP_ACTIVE"
DECISION_SEVERITY_BELOW_THRESHOLD = "SEVERITY_BELOW_THRESHOLD"
DECISION_CONFIDENCE_BELOW_THRESHOLD = "CONFIDENCE_BELOW_THRESHOLD"
DECISION_ESSENTIAL_PROTECTION = "ESSENTIAL_ADDRESS_PROTECTION"
DECISION_OPERATIONAL_PROTECTION = "OPERATIONAL_ADDRESS_PROTECTION"
DECISION_CONFIGURABLE_EXCLUSION_HONORED = "CONFIGURABLE_EXCLUSION_HONORED"
DECISION_CONFIGURABLE_EXCLUSION_OVERRIDDEN = "CONFIGURABLE_EXCLUSION_OVERRIDDEN"


@dataclass
class ResponseDecision:
    action: str  # BLOCK, ALERT_ONLY, REQUIRE_APPROVAL, REJECT_PROTECTED
    target_ip: str
    decision_code: str
    reason: str
    severity: str
    confidence: float
    protection_category: str
    block_duration_sec: float
    is_emergency_stop: bool = False
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatResponsePolicy:
    """
    Evaluates alerts and produces explicit, auditable response decisions.
    """

    def __init__(
        self,
        prevention_mode: int = 1,
        auto_block_severities: Optional[List[str]] = None,
        min_auto_block_confidence: float = 0.85,
        default_block_duration_sec: float = 300.0,
        allow_override_configurable: bool = True
    ):
        self.prevention_mode = prevention_mode  # 1: Detection Only, 2: Assisted, 3: Automatic
        self.auto_block_severities = set(auto_block_severities or ["CRITICAL", "HIGH"])
        self.min_auto_block_confidence = min_auto_block_confidence
        self.default_block_duration_sec = default_block_duration_sec
        self.allow_override_configurable = allow_override_configurable
        self.emergency_stop = False
        self.classifier = address_policy.get_address_classifier()

    def set_emergency_stop(self, active: bool) -> None:
        """Toggle emergency stop mode."""
        self.emergency_stop = active
        logger.warning("ThreatResponsePolicy: Emergency stop state set to %s", active)

    def evaluate(
        self,
        src_ip: str,
        severity: str,
        confidence: float = 1.0,
        evidence: Optional[Dict[str, Any]] = None,
        category: str = "Threat Detection"
    ) -> ResponseDecision:
        """
        Evaluate an alert and return a structured ResponseDecision.
        Never suppresses the alert itself.
        """
        now = time.time()
        ev = evidence or {}
        sev = (severity or "MEDIUM").upper()
        conf = float(confidence) if confidence is not None else 1.0

        # 1. Emergency Stop Check
        if self.emergency_stop:
            return ResponseDecision(
                action=ACTION_ALERT_ONLY,
                target_ip=src_ip,
                decision_code=DECISION_EMERGENCY_STOP_ACTIVE,
                reason="Automatic blocking halted by active Emergency Stop switch.",
                severity=sev,
                confidence=conf,
                protection_category="EMERGENCY_HALT",
                block_duration_sec=0.0,
                is_emergency_stop=True,
                evidence_summary=ev,
                evaluated_at=now
            )

        # 2. Address Protection Tier Check
        prot_res = self.classifier.is_protected(src_ip)

        # Category A: Essential Protection (Can NEVER be blocked)
        if prot_res.category == "CATEGORY_A_ESSENTIAL":
            return ResponseDecision(
                action=ACTION_REJECT_PROTECTED,
                target_ip=src_ip,
                decision_code=DECISION_ESSENTIAL_PROTECTION,
                reason=f"Block rejected: Essential host protection ({prot_res.description}). Possible source spoofing.",
                severity=sev,
                confidence=conf,
                protection_category="CATEGORY_A",
                block_duration_sec=0.0,
                evidence_summary=ev,
                evaluated_at=now
            )

        # Category B: Operational Protection (Gateway / DNS)
        if prot_res.category == "CATEGORY_B_OPERATIONAL":
            return ResponseDecision(
                action=ACTION_REQUIRE_APPROVAL,
                target_ip=src_ip,
                decision_code=DECISION_OPERATIONAL_PROTECTION,
                reason=f"Block deferred: Operational address ({prot_res.description}). Manual approval required to avoid network disruption.",
                severity=sev,
                confidence=conf,
                protection_category="CATEGORY_B",
                block_duration_sec=0.0,
                evidence_summary=ev,
                evaluated_at=now
            )

        # Category C: Configurable Exclusion
        is_override = False
        if prot_res.category == "CATEGORY_C_CONFIGURABLE":
            if self.allow_override_configurable and (sev in ("CRITICAL", "HIGH")):
                is_override = True
            else:
                return ResponseDecision(
                    action=ACTION_REJECT_PROTECTED,
                    target_ip=src_ip,
                    decision_code=DECISION_CONFIGURABLE_EXCLUSION_HONORED,
                    reason=f"Block rejected: Target matched operator configurable exclusion ({prot_res.description}).",
                    severity=sev,
                    confidence=conf,
                    protection_category="CATEGORY_C",
                    block_duration_sec=0.0,
                    evidence_summary=ev,
                    evaluated_at=now
                )

        # 3. Prevention Mode Evaluation
        if self.prevention_mode == 1:
            # Mode 1: Detection Only
            return ResponseDecision(
                action=ACTION_ALERT_ONLY,
                target_ip=src_ip,
                decision_code=DECISION_DETECTION_ONLY_MODE,
                reason="Prevention mode is set to Detection Only (Mode 1). Automated blocking is disabled.",
                severity=sev,
                confidence=conf,
                protection_category="UNPROTECTED" if not is_override else "CATEGORY_C_OVERRIDDEN",
                block_duration_sec=0.0,
                evidence_summary=ev,
                evaluated_at=now
            )

        if self.prevention_mode == 2:
            # Mode 2: Assisted Prevention (Generates approval recommendation)
            return ResponseDecision(
                action=ACTION_REQUIRE_APPROVAL,
                target_ip=src_ip,
                decision_code=DECISION_ASSISTED_MODE_APPROVAL,
                reason="Assisted Prevention (Mode 2) active: Requires operator confirmation before firewall enforcement.",
                severity=sev,
                confidence=conf,
                protection_category="UNPROTECTED" if not is_override else "CATEGORY_C_OVERRIDDEN",
                block_duration_sec=self.default_block_duration_sec,
                evidence_summary=ev,
                evaluated_at=now
            )

        # Mode 3: Automatic Prevention
        # Check severity threshold
        if sev not in self.auto_block_severities:
            return ResponseDecision(
                action=ACTION_ALERT_ONLY,
                target_ip=src_ip,
                decision_code=DECISION_SEVERITY_BELOW_THRESHOLD,
                reason=f"Threat severity '{sev}' is below automated blocking threshold ({', '.join(sorted(self.auto_block_severities))}).",
                severity=sev,
                confidence=conf,
                protection_category="UNPROTECTED" if not is_override else "CATEGORY_C_OVERRIDDEN",
                block_duration_sec=0.0,
                evidence_summary=ev,
                evaluated_at=now
            )

        # Check confidence threshold
        if conf < self.min_auto_block_confidence:
            return ResponseDecision(
                action=ACTION_ALERT_ONLY,
                target_ip=src_ip,
                decision_code=DECISION_CONFIDENCE_BELOW_THRESHOLD,
                reason=f"Threat confidence {conf:.2f} is below minimum auto-block threshold ({self.min_auto_block_confidence:.2f}).",
                severity=sev,
                confidence=conf,
                protection_category="UNPROTECTED" if not is_override else "CATEGORY_C_OVERRIDDEN",
                block_duration_sec=0.0,
                evidence_summary=ev,
                evaluated_at=now
            )

        # Automatic Block Approved
        dec_code = DECISION_CONFIGURABLE_EXCLUSION_OVERRIDDEN if is_override else DECISION_AUTO_BLOCK_APPROVED
        override_note = " (Configurable exclusion overridden due to high/critical threat severity)" if is_override else ""
        return ResponseDecision(
            action=ACTION_BLOCK,
            target_ip=src_ip,
            decision_code=dec_code,
            reason=f"Automated firewall block authorized for {sev} risk threat ({conf:.1%} confidence){override_note}.",
            severity=sev,
            confidence=conf,
            protection_category="UNPROTECTED" if not is_override else "CATEGORY_C_OVERRIDDEN",
            block_duration_sec=self.default_block_duration_sec,
            evidence_summary=ev,
            evaluated_at=now
        )


# Singleton instance
_response_policy_instance: Optional[ThreatResponsePolicy] = None


def get_response_policy(
    prevention_mode: int = 1,
    auto_block_severities: Optional[List[str]] = None,
    min_auto_block_confidence: float = 0.85,
    default_block_duration_sec: float = 300.0,
    allow_override_configurable: bool = True
) -> ThreatResponsePolicy:
    """Retrieve or initialize the global ThreatResponsePolicy instance."""
    global _response_policy_instance
    if _response_policy_instance is None:
        _response_policy_instance = ThreatResponsePolicy(
            prevention_mode=prevention_mode,
            auto_block_severities=auto_block_severities,
            min_auto_block_confidence=min_auto_block_confidence,
            default_block_duration_sec=default_block_duration_sec,
            allow_override_configurable=allow_override_configurable
        )
    return _response_policy_instance
