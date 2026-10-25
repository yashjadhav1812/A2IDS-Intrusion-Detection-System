# macOS Packet Filter (PF) Firewall Architecture & Enforcement Engine

## 1. Executive Summary & Principles
The A2IDS intrusion prevention system enforces network blocking directly at the operating system packet filter level on macOS (`/sbin/pfctl`). 

A critical architectural principle governs this system:
> **Detection, protection policy, enforcement, and verification are separate operations.**  
> A threat detection is not proof that a block was attempted, an OS command return code of `0` is not proof that the firewall rule dropped packets, and adding an IP to an in-memory table is not proof that the active packet filter is evaluating rules against that table.

---

## 2. PF Anchor and Table Hierarchy

macOS manages network filtering via the BSD Packet Filter (`pfctl`). To avoid polluting or overwriting system-level rules in `/etc/pf.conf`, A2IDS integrates using dedicated PF **Anchors** and **Persist Tables**:

- **Anchor Name:** `ai_ids`
- **Table Name:** `ids_blocked`

```mermaid
flowchart TD
    subgraph macOS PF Kernel Subsystem
        PFConf["/etc/pf.conf (Main Ruleset)"]
        AnchorRef["anchor 'ai_ids'"]
        PFConf --> AnchorRef
        
        subgraph Anchor "ai_ids"
            TableDef["table &lt;ids_blocked&gt; persist"]
            DropIn["block drop in quick from &lt;ids_blocked&gt; to any"]
            DropOut["block drop out quick to &lt;ids_blocked&gt; from any"]
            TableDef --> DropIn
            TableDef --> DropOut
        end
        
        AnchorRef --> Anchor
    end
    
    subgraph A2IDS Safety & Enforcement Engine
        Decision["Response Policy: BLOCK Decision"] --> Controller["SafetyController.execute_block()"]
        Controller --> FirewallMgr["FirewallManager"]
        FirewallMgr --> PFExec["/sbin/pfctl -a ai_ids -t ids_blocked -T add &lt;ip&gt;"]
        PFExec --> TableDef
        FirewallMgr --> Verify["Verification: /sbin/pfctl -a ai_ids -t ids_blocked -T show"]
        Verify --> State["Verified State: BLOCKED_VERIFIED"]
    end
```

### Table Structure
The table `<ids_blocked>` holds both IPv4 and IPv6 addresses. In PF, tables handle both families simultaneously. When an address is added:
```bash
/sbin/pfctl -a ai_ids -t ids_blocked -T add 203.0.113.50
/sbin/pfctl -a ai_ids -t ids_blocked -T add 2401:4900:5613:a2c7:d0c3:143f:1193:641a
```

### Referencing Filtering Rules
Merely creating a table or adding an address to `<ids_blocked>` does not block traffic unless an active filtering rule explicitly drops traffic matching the table:
```pf
table <ids_blocked> persist
block drop in quick from <ids_blocked> to any
block drop out quick to <ids_blocked> from any
```
If PF is enabled (`pfctl -e`) and the anchor contains these rules, matching packets are dropped immediately at the network layer (`quick` keyword avoids subsequent rule evaluation).

---

## 3. Four-Tier Verification Protocol

Before declaring an IP blocked, A2IDS executes a multi-step verification protocol:

1. **Kernel PF Subsystem Enabled Check**:
   - Command: `/sbin/pfctl -s info`
   - Validates that `Status: Enabled` is returned by the kernel.
2. **Anchor Ruleset Check**:
   - Command: `/sbin/pfctl -a ai_ids -s rules`
   - Verifies that `block drop in quick from <ids_blocked> to any` exists.
3. **Table Membership Verification**:
   - Command: `/sbin/pfctl -a ai_ids -t ids_blocked -T show`
   - Parse stdout with canonical IP matching (using `ipaddress.ip_address` equivalence for IPv4 and IPv6, rather than naive substring searching).
4. **State Assignment**:
   - `BLOCKED_VERIFIED`: Table query confirmed IP membership in the active anchor.
   - `BLOCK_UNVERIFIED`: Command exited 0, but IP was not confirmed in table listing.
   - `BLOCK_FAILED`: `pfctl` exited with error code or permission denied.
   - `UNBLOCKED_VERIFIED`: Confirmed removed from table listing.
   - `BLOCK_EXPIRED`: Time-to-live expired and address was cleanly unblocked.

---

## 4. IPv6 & Dual-Stack Address Handling

A2IDS provides full parity for IPv6:
- IPv6 addresses (e.g. `2401:4900:5613:a2c7:d0c3:143f:1193:641a`) are parsed using Python `ipaddress.IPv6Address`.
- Scoped link-local identifiers (`fe80::...%en0`) are sanitized by stripping interface scopes before sending to `pfctl`.
- PF table commands natively parse IPv6 addresses. Output matching normalizes compressed and expanded IPv6 representations so that `2401:4900:5613:a2c7:0000:0000:0000:0001` matches `2401:4900:5613:a2c7::1`.

---

## 5. Safe Unblocking and Non-Interference

When a rule expires or is manually revoked:
1. `pfctl -a ai_ids -t ids_blocked -T delete <ip>` is executed.
2. The table listing is verified to confirm removal.
3. No other PF tables, system anchors, or unrelated firewall rules are touched.
4. The database records the unblock timestamp and verified state.

---

## 6. Emergency Stop Switch

If network disruption or accidental lockout is suspected:
1. The **Emergency Stop** trigger immediately halts all automatic blocking threads.
2. An optional flush command (`pfctl -a ai_ids -t ids_blocked -T flush`) empties the blocking table within 50ms without stopping packet sniffing or alert logging.
3. System state switches to `EMERGENCY_STOP_ACTIVE` and auditable logs are committed.
