"""
Address Policy Engine for A2IDS.
Provides robust IP classification, category-based protection policies,
and safeguards against accidental host lockout.
Categorizes addresses into:
  - Category A: Essential System Protection (Loopback, Local Interfaces, Broadcast)
  - Category B: Operational Protection (Default Gateway, Configured DNS Resolvers)
  - Category C: Configurable Exclusions (Operator-defined exceptions and subnets)
"""

import os
import re
import socket
import logging
import platform
import subprocess
import ipaddress
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set, Tuple, Union

import psutil

logger = logging.getLogger(__name__)


# Standard Machine-Readable Decision Codes
REASON_UNPROTECTED = "UNPROTECTED_TARGET"
REASON_INVALID_FORMAT = "INVALID_ADDRESS_FORMAT"
REASON_ESSENTIAL_LOOPBACK = "ESSENTIAL_LOOPBACK_PROTECTED"
REASON_ESSENTIAL_LOCAL_INTERFACE = "ESSENTIAL_LOCAL_INTERFACE_PROTECTED"
REASON_ESSENTIAL_SPECIAL = "ESSENTIAL_SPECIAL_ADDRESS_PROTECTED"
REASON_OPERATIONAL_GATEWAY = "OPERATIONAL_GATEWAY_PROTECTED"
REASON_OPERATIONAL_DNS = "OPERATIONAL_CONFIGURED_DNS_PROTECTED"
REASON_CONFIGURABLE_EXCLUSION = "CONFIGURABLE_EXCLUSION_MATCHED"


@dataclass
class AddressClassification:
    ip_str: str
    is_valid: bool
    version: int = 0
    is_loopback: bool = False
    is_multicast: bool = False
    is_unspecified: bool = False
    is_link_local: bool = False
    is_private: bool = False
    is_global: bool = False
    is_local_interface: bool = False
    is_gateway: bool = False
    is_configured_dns: bool = False
    is_configurable_exclusion: bool = False
    category: str = "UNPROTECTED"  # "CATEGORY_A", "CATEGORY_B", "CATEGORY_C", "UNPROTECTED", "INVALID"
    reason_code: str = REASON_UNPROTECTED
    description: str = "Target address is eligible for automated security enforcement."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProtectionCheckResult:
    is_protected: bool
    category: str  # "CATEGORY_A_ESSENTIAL", "CATEGORY_B_OPERATIONAL", "CATEGORY_C_CONFIGURABLE", "NONE"
    reason_code: str
    description: str
    can_override: bool = False
    matched_entry: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AddressClassifier:
    """
    Classifies IPv4 and IPv6 addresses into Essential, Operational,
    and Configurable protection tiers.
    """

    def __init__(self, initial_exclusions: Optional[List[str]] = None):
        self._lock = threading.RLock()
        self.os_type = platform.system()

        # Dynamic cache
        self.local_interfaces: Dict[str, Set[str]] = {}  # iface_name -> set of IP strings
        self.all_local_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        self.default_gateways: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        self.configured_dns: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()

        # Category C: Configurable exclusions: list of (network_obj, reason, created_at, expires_at)
        self.configurable_exclusions: List[Dict[str, Any]] = []
        if initial_exclusions:
            for item in initial_exclusions:
                self.add_configurable_exclusion(item, reason="Initial Configuration Allowlist")

        self.refresh_system_addresses()

    def _sanitize_ip_input(self, raw_input: str) -> str:
        """Strip whitespaces, interface scopes (%en0), and CIDR /32 or /128 if present."""
        if not raw_input or not isinstance(raw_input, str):
            return ""
        clean = raw_input.strip()
        # Remove interface scope if any (e.g. fe80::1%en0)
        clean = clean.split("%")[0]
        return clean

    def refresh_system_addresses(self) -> None:
        """
        Dynamically discover local interfaces, default gateway, and DNS resolvers.
        Carefully filters socket families to never include MAC addresses.
        """
        with self._lock:
            # 1. Local interfaces
            new_local_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
            new_local_map: Dict[str, Set[str]] = {}

            try:
                for iface_name, addrs in psutil.net_if_addrs().items():
                    iface_ips = set()
                    for addr in addrs:
                        # Strictly accept only AF_INET and AF_INET6
                        if addr.family in (socket.AF_INET, getattr(socket, "AF_INET6", 30)):
                            raw_ip = self._sanitize_ip_input(addr.address)
                            try:
                                ip_obj = ipaddress.ip_address(raw_ip)
                                new_local_ips.add(ip_obj)
                                iface_ips.add(str(ip_obj))
                            except ValueError:
                                continue
                    if iface_ips:
                        new_local_map[iface_name] = iface_ips
                self.local_interfaces = new_local_map
                self.all_local_ips = new_local_ips
            except Exception as e:
                logger.error("Failed to discover local interfaces: %s", e)

            # 2. Default Gateways
            new_gateways: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
            try:
                if self.os_type == "Darwin":
                    res = subprocess.run(
                        ["route", "-n", "get", "default"],
                        capture_output=True,
                        text=True,
                        timeout=2.0
                    )
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            if "gateway:" in line:
                                gw_str = line.split("gateway:")[1].strip()
                                try:
                                    new_gateways.add(ipaddress.ip_address(gw_str))
                                except ValueError:
                                    pass
                elif self.os_type == "Linux":
                    # Parse /proc/net/route or ip route
                    res = subprocess.run(
                        ["ip", "route", "show", "default"],
                        capture_output=True,
                        text=True,
                        timeout=2.0
                    )
                    if res.returncode == 0:
                        parts = res.stdout.split()
                        if "via" in parts:
                            gw_idx = parts.index("via") + 1
                            if gw_idx < len(parts):
                                try:
                                    new_gateways.add(ipaddress.ip_address(parts[gw_idx]))
                                except ValueError:
                                    pass
            except Exception as e:
                logger.debug("Failed to discover default gateway: %s", e)
            self.default_gateways = new_gateways

            # 3. Configured DNS Resolvers from /etc/resolv.conf
            new_dns: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
            resolv_path = "/etc/resolv.conf"
            try:
                if os.path.exists(resolv_path):
                    with open(resolv_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("nameserver"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    dns_ip = self._sanitize_ip_input(parts[1])
                                    try:
                                        new_dns.add(ipaddress.ip_address(dns_ip))
                                    except ValueError:
                                        pass
            except Exception as e:
                logger.debug("Failed reading %s: %s", resolv_path, e)

            # Fallback to standard resolver protection if resolv.conf unreadable in sandbox/container
            if not new_dns:
                try:
                    new_dns.add(ipaddress.ip_address("8.8.8.8"))
                    new_dns.add(ipaddress.ip_address("1.1.1.1"))
                except ValueError:
                    pass
            self.configured_dns = new_dns

    def add_configurable_exclusion(
        self,
        cidr_or_ip: str,
        reason: str = "Operator Allowlist",
        operator: str = "OPERATOR",
        expires_at: Optional[float] = None
    ) -> bool:
        """Add an operator exclusion (single IP or CIDR network)."""
        clean = self._sanitize_ip_input(cidr_or_ip)
        try:
            # Handle single host or network
            net = ipaddress.ip_network(clean, strict=False)
            with self._lock:
                # Avoid duplicates
                for item in self.configurable_exclusions:
                    if item["network"] == net:
                        item["reason"] = reason
                        item["expires_at"] = expires_at
                        return True

                self.configurable_exclusions.append({
                    "raw": clean,
                    "network": net,
                    "reason": reason,
                    "operator": operator,
                    "created_at": psutil.time.time(),
                    "expires_at": expires_at,
                    "enabled": True
                })
            return True
        except ValueError:
            logger.warning("Invalid exclusion address/subnet syntax: %s", cidr_or_ip)
            return False

    def remove_configurable_exclusion(self, cidr_or_ip: str) -> bool:
        """Remove a configurable exclusion."""
        clean = self._sanitize_ip_input(cidr_or_ip)
        with self._lock:
            try:
                target_net = ipaddress.ip_network(clean, strict=False)
                initial_len = len(self.configurable_exclusions)
                self.configurable_exclusions = [
                    item for item in self.configurable_exclusions if item["network"] != target_net
                ]
                return len(self.configurable_exclusions) < initial_len
            except ValueError:
                return False

    def classify_address(self, raw_ip: str) -> AddressClassification:
        """Classify an IP string into detailed attributes and protection category."""
        clean = self._sanitize_ip_input(raw_ip)
        try:
            ip_obj = ipaddress.ip_address(clean)
        except ValueError:
            return AddressClassification(
                ip_str=raw_ip,
                is_valid=False,
                category="INVALID",
                reason_code=REASON_INVALID_FORMAT,
                description=f"Invalid IPv4/IPv6 syntax: '{raw_ip}'"
            )

        classification = AddressClassification(
            ip_str=str(ip_obj),
            is_valid=True,
            version=ip_obj.version,
            is_loopback=ip_obj.is_loopback,
            is_multicast=ip_obj.is_multicast,
            is_unspecified=ip_obj.is_unspecified,
            is_link_local=ip_obj.is_link_local,
            is_private=ip_obj.is_private,
            is_global=ip_obj.is_global
        )

        with self._lock:
            # Check local interface addresses
            if ip_obj in self.all_local_ips:
                classification.is_local_interface = True

            # Check default gateways
            if ip_obj in self.default_gateways:
                classification.is_gateway = True

            # Check configured DNS
            if ip_obj in self.configured_dns:
                classification.is_configured_dns = True

            # Check configurable exclusions
            now = psutil.time.time()
            for excl in self.configurable_exclusions:
                if not excl.get("enabled", True):
                    continue
                exp = excl.get("expires_at")
                if exp and now > exp:
                    continue
                if ip_obj in excl["network"]:
                    classification.is_configurable_exclusion = True
                    break

        # Category Determination (Hierarchy: A -> B -> C -> UNPROTECTED)
        if (
            classification.is_loopback
            or classification.is_local_interface
            or classification.is_unspecified
            or classification.is_multicast
            or classification.is_link_local
        ):
            classification.category = "CATEGORY_A"
            if classification.is_loopback:
                classification.reason_code = REASON_ESSENTIAL_LOOPBACK
                classification.description = "Essential loopback address (127.0.0.0/8 or ::1). Loss would compromise host services."
            elif classification.is_local_interface:
                classification.reason_code = REASON_ESSENTIAL_LOCAL_INTERFACE
                classification.description = "Essential local host interface IP. Cannot be blocked without severing active host networking."
            else:
                classification.reason_code = REASON_ESSENTIAL_SPECIAL
                classification.description = "Essential protocol reserved, multicast, or link-local address."
            return classification

        if classification.is_gateway or classification.is_configured_dns:
            classification.category = "CATEGORY_B"
            if classification.is_gateway:
                classification.reason_code = REASON_OPERATIONAL_GATEWAY
                classification.description = "Operational default gateway address. Blocking would disconnect host from external networks."
            else:
                classification.reason_code = REASON_OPERATIONAL_DNS
                classification.description = "Operational host DNS resolver configured in /etc/resolv.conf. Blocking requires operator approval."
            return classification

        if classification.is_configurable_exclusion:
            classification.category = "CATEGORY_C"
            classification.reason_code = REASON_CONFIGURABLE_EXCLUSION
            classification.description = "Matches operator-configured exclusion rule. Subject to configurable override policy."
            return classification

        classification.category = "UNPROTECTED"
        classification.reason_code = REASON_UNPROTECTED
        classification.description = "External address eligible for automated firewall prevention."
        return classification

    def is_protected(self, raw_ip: str) -> ProtectionCheckResult:
        """
        Determine if an IP address is protected, and whether it can be safely overridden.
        """
        cls = self.classify_address(raw_ip)
        if not cls.is_valid:
            return ProtectionCheckResult(
                is_protected=True,
                category="NONE",
                reason_code=cls.reason_code,
                description=cls.description,
                can_override=False
            )

        if cls.category == "CATEGORY_A":
            return ProtectionCheckResult(
                is_protected=True,
                category="CATEGORY_A_ESSENTIAL",
                reason_code=cls.reason_code,
                description=cls.description,
                can_override=False
            )

        if cls.category == "CATEGORY_B":
            return ProtectionCheckResult(
                is_protected=True,
                category="CATEGORY_B_OPERATIONAL",
                reason_code=cls.reason_code,
                description=cls.description,
                can_override=False
            )

        if cls.category == "CATEGORY_C":
            return ProtectionCheckResult(
                is_protected=True,
                category="CATEGORY_C_CONFIGURABLE",
                reason_code=cls.reason_code,
                description=cls.description,
                can_override=True
            )

        return ProtectionCheckResult(
            is_protected=False,
            category="NONE",
            reason_code=REASON_UNPROTECTED,
            description="Address is unprotected and may be blocked automatically.",
            can_override=True
        )

    def get_all_protected_addresses(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return categorized structure of all currently protected addresses for UI / API."""
        with self._lock:
            cat_a = []
            # Loopback
            cat_a.append({
                "address": "127.0.0.1/8, ::1/128",
                "type": "Loopback",
                "reason": "Host Kernel Interprocess Communication",
                "source": "RFC 1122 / RFC 4291",
                "can_override": False
            })
            # Local Interfaces
            for iface, ips in self.local_interfaces.items():
                for ip in sorted(ips):
                    cat_a.append({
                        "address": ip,
                        "type": f"Local Interface ({iface})",
                        "reason": f"Active IP bound to network interface {iface}",
                        "source": "Dynamic Host Discovery (psutil)",
                        "can_override": False
                    })

            cat_b = []
            # Gateways
            for gw in sorted(str(g) for g in self.default_gateways):
                cat_b.append({
                    "address": gw,
                    "type": "Default Gateway",
                    "reason": "Default route egress gateway for host traffic",
                    "source": "OS Routing Table",
                    "can_override": False
                })
            # Configured DNS
            for dns in sorted(str(d) for d in self.configured_dns):
                cat_b.append({
                    "address": dns,
                    "type": "Configured DNS",
                    "reason": "System resolver in /etc/resolv.conf",
                    "source": "/etc/resolv.conf",
                    "can_override": False
                })

            cat_c = []
            now = psutil.time.time()
            for excl in self.configurable_exclusions:
                cat_c.append({
                    "address": excl["raw"],
                    "type": "Subnet / Host Exclusion",
                    "reason": excl["reason"],
                    "operator": excl.get("operator", "OPERATOR"),
                    "created_at": excl.get("created_at"),
                    "expires_at": excl.get("expires_at"),
                    "enabled": excl.get("enabled", True),
                    "can_override": True
                })

            return {
                "category_a": cat_a,
                "category_b": cat_b,
                "category_c": cat_c
            }


# Global singleton instance
_address_classifier_instance: Optional[AddressClassifier] = None
_instance_lock = threading.Lock()


def get_address_classifier() -> AddressClassifier:
    """Retrieve or initialize the global AddressClassifier singleton."""
    global _address_classifier_instance
    with _instance_lock:
        if _address_classifier_instance is None:
            _address_classifier_instance = AddressClassifier()
        return _address_classifier_instance
