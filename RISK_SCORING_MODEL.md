# iKARMA Risk Scoring Model - Complete Breakdown

## Overview
The risk scoring model evaluates Windows kernel drivers found in memory dumps using a points-based system (0–100 scale) combined with driver classification and contextual signals. The goal is to differentiate between legitimate system drivers and potentially suspicious/malicious drivers.

---

## 1. SIGNAL CATEGORIES & SCORING POINTS

### Category A: IOCTL Handler Presence & Type (40 points max)
| Signal | Points | Rationale |
|--------|--------|-----------|
| Custom IOCTL (handler inside driver) | +40 | Driver implements own IOCTL dispatch; highest attack surface |
| Generic IOCTL (handler outside driver) | +10 | Uses shared/framework handler (e.g., WDF); lower risk, reusable code |
| No IOCTL handler found | +0 | No device interface; minimal kernel-user interaction surface |

**Why this matters**: Custom IOCTL handlers are where driver bugs/exploits hide. They're userland entry points to kernel code.

---

### Category B: Driver Size & Complexity (15 points max)
| Signal | Points | Rationale |
|--------|--------|-----------|
| Very small (< 0x10000 bytes) | -8 | Likely stub/simple handler; limited functionality |
| Medium (0x20000–0x40000 bytes) | +5 | Moderate complexity |
| Large (0x40000–0x100000 bytes) | +10 | Complex driver; more code = more attack surface |
| Very large (> 0x100000 bytes) | +10 | Full-featured driver; high complexity |

**Why this matters**: Larger drivers have more code paths and potential vulnerabilities. But if it's a known MS driver (ntfs, tcpip), size is less concerning.

---

### Category C: Driver Classification (25 points reduction max)
| Classification | Points | Rationale |
|---|---|---|
| Known system driver (MS whitelist) | -25 | Heavily audited; widely deployed; low risk |
| Known network driver (special list) | -20 | Network stack is well-audited; even with Custom IOCTL, safe |
| Safe name pattern (e.g., `*class.sys`, `win32k*`) | -10 | Pattern indicates device stub or class driver; safe |
| Unknown/third-party driver | +0 | No reduction; score stands |
| Suspicious vendor/unsigned | +15 | (Future: if signature check available) |

**Why this matters**: Most driver exploits target niche/proprietary drivers, not Windows core. MS drivers are battle-tested.

---

### Category D: Handler Location (8 points max reduction)
| Signal | Points | Rationale |
|--------|--------|-----------|
| Generic IOCTL (handler outside module) | -8 | Code is shared; not unique to this driver; lower custom code risk |
| Custom IOCTL (handler inside module) | +0 | Driver's own code; unique attack surface |

**Why this matters**: Generic handlers are standardized, reviewed by multiple eyes (WDF, framework). Custom handlers are driver-specific and less audited.

---

### Category E: Disassembly Signals (Future Phase 2 - Not Yet Implemented)
| Signal | Points | Rationale |
|--------|--------|-----------|
| High call density (calls > 8) | +10 | Multiple kernel API interactions; more complexity |
| REP MOVS / memory copy patterns | +12 | Bulk copy of user data; common exploit vector |
| Large instruction count (> 100) | +5 | Complex handler logic; more edge cases |
| Suspicious API references (if resolvable) | +15 | Calls to known-risky APIs (e.g., ZwQuerySystemInformation) |

**Why this matters**: Disassembly reveals capability (what the driver actually does). A handler with many CALLs + rep-movs is higher risk.

---

## 2. DRIVER CLASSIFICATION LISTS

### System Driver Whitelist (Category C)
**Reduced by -25 points if matched**

**Core system drivers** (OS critical path):
- msrpc, ksecdd, clfs, tm, fltmgr, acpi, cng, pci, partmgr, volmgr, mountmgr, ataport, disk, ntfs, diskcache

**Network stack** (treated separately, -20):
- ndis, tcpip, afd, netbt, netbios, http, winsock, wfplwfs

**Graphics/display** (typically safe):
- win32k, win32kfull, win32kbase, dxgkrnl, dxgmms2, basicdisplay, basicrender

**USB/device stubs** (safe patterns):
- usbxhci, usbhub, usbkd, kdnic, kbdclass, mouclass, hidclass, cdrom

**Virtualization guests** (known-good vendors):
- vboxguest, vboxsf, vboxmouse, vboxwddm, vmguestlib

**Total in whitelist**: ~80+ known-good driver names

---

### Safe Name Patterns (Category C - Reduced by -10 points)
| Pattern | Reason |
|---------|--------|
| Ends with `class.sys` | Generic device class handler (kbdclass, mouclass, diskclass) |
| Ends with `port.sys` | Port/miniport driver (ataport, scsiport) |
| Ends with `mini.sys` | Miniport driver (generic, minimal functionality) |
| Starts with `win32k*` | Core Windows subsystem; heavily audited |
| Starts with `usb*` | USB stack; standardized; well-tested |
| Starts with `hid*` | Human Interface Device; limited scope |
| Starts with `display*` | Display driver stub; framework-based |
| Starts with `vbox*` | VirtualBox guest tools; open-source; audited |

---

### Special Category: Network Drivers (Category C - Reduced by -20 points)
Network drivers in Windows are designed to be exploitable from userland (IPC protocol). However, they're **extremely well-audited** due to bug bounties and security research.

**List** (if matched, apply -20 instead of -25):
- ndis, tcpip, http, afd, netbt, netbios, winsock, wfplwfs, ipsec, ike, ikeext

**Why lower than system drivers**: Larger attack surface (network exposure), but offset by intense scrutiny.

---

## 3. SCORING FORMULA (STEP-BY-STEP)

### Step 1: Base Score Calculation
```
score = 0

# Category A: IOCTL Type (Primary signal)
if analysis == "Custom IOCTL":
    score += 40
elif analysis == "Generic IOCTL":
    score += 10
else:
    score += 0  # No handler

# Category B: Driver Size (Complexity proxy)
if size < 0x10000:
    score -= 8
elif size > 0x100000:
    score += 10
elif size > 0x40000:
    score += 5

# Category D: Generic IOCTL further reduction
if "Generic" in ioctl_handler_display:
    score -= 8
```

### Step 2: Driver Classification Penalties/Bonuses
```
# Category C: Apply classification reductions
if is_known_system_driver(driver_name):
    score -= 25
elif is_network_driver(driver_name):
    score -= 20
elif matches_safe_name_pattern(driver_name):
    score -= 10

# (Future) Category C: Signature/vendor check
if unsigned and not_known_vendor:
    score += 15
```

### Step 3: Clamp & Label
```
# Normalize score
score = max(0, min(100, score))

# Map to label
if score < 30:
    label = "Low"
elif score < 70:
    label = "Medium"
else:
    label = "High"

return f"{label} ({score}%)"
```

---

## 4. SCORING EXAMPLES

### Example 1: Well-Known System Driver
**Driver**: `ntfs.sys` (size: 0x28d000, Custom IOCTL)
```
Base:               +40 (Custom IOCTL)
Size:               +10 (very large, > 0x100000)
System driver:      -25 (NTFS in whitelist)
                    -----
Score:              25

Label:              Low (25%)
Rationale:          Core system driver; even with Custom IOCTL, heavily audited
```

### Example 2: Network Driver
**Driver**: `tcpip.sys` (size: 0x2db000, Custom IOCTL)
```
Base:               +40 (Custom IOCTL)
Size:               +10 (very large)
Network driver:     -20 (tcpip in network list)
                    -----
Score:              30

Label:              Low (30%) → Medium (30%)
Rationale:          Core network stack; well-audited; Custom IOCTL expected
```

### Example 3: Small Device Stub
**Driver**: `volume.sys` (size: 0xb000, Custom IOCTL)
```
Base:               +40 (Custom IOCTL)
Size:               -8 (very small, < 0x10000)
System driver:      -25 (volume in whitelist)
                    -----
Score:              7

Label:              Low (7%)
Rationale:          Tiny driver; likely simple handler; known system driver
```

### Example 4: Unknown Third-Party Driver (High Risk)
**Driver**: `maldrv.sys` (size: 0x80000, Custom IOCTL, unsigned)
```
Base:               +40 (Custom IOCTL)
Size:               +10 (large, > 0x40000)
Unknown/unsigned:   +15 (no whitelist match; unsigned)
                    -----
Score:              65

Label:              Medium (65%)
Rationale:          Custom IOCTL + unknown vendor + size = review candidate
```

### Example 5: Generic Handler with Large System Driver
**Driver**: `Wdf01000.sys` (size: 0xd1000, Generic IOCTL)
```
Base:               +10 (Generic IOCTL)
Generic handler:    -8 (shared/framework)
System driver:      -25 (WDF framework driver, system)
                    -----
Score:              -23 → 0 (clamped)

Label:              Low (0%)
Rationale:          Framework-based; shared handler; generic; safe
```

---

## 5. CONFIDENCE & EXPLANATION (Future)

Each score should include a short explanation of the top 2–3 contributing signals:

| Score | Signals | Explanation |
|-------|---------|-------------|
| Low (7%) | Custom IOCTL +40, Size -8, System driver -25 | "Small system driver with custom handler; low risk" |
| Medium (45%) | Custom IOCTL +40, Size +5 | "Custom IOCTL + medium size; known system driver; review if needed" |
| High (75%) | Custom IOCTL +40, Size +10, Unknown +15, Unsigned +15 | "Unknown driver; unsigned; large custom IOCTL handler; HIGH PRIORITY" |

---

## 6. THRESHOLDS & TRIAGE POLICY

### Recommended Analyst Action
```
Score Range     Label    Action
-----------     -----    ------
0–29            Low      No action required; archive for audit trail
30–49           Medium   Queued for analyst review (low priority)
50–69           Medium   Queued for analyst review (medium priority)
70–100          High     IMMEDIATE review; sandbox; hash lookup; YARA scan
```

### Confidence Modifiers (Future)
- **High confidence** (0.7–1.0): Multiple signals available (IOCTL + size + classification + disasm)
- **Medium confidence** (0.4–0.7): 2–3 signals available
- **Low confidence** (< 0.4): Only IOCTL type available; metadata missing

---

## 7. DESIGN PHILOSOPHY

### Principles
1. **Explainability**: Every point is traceable to a specific signal; score is human-readable.
2. **Conservative**: System drivers get significant reduction to minimize false positives.
3. **Extensible**: Additional signals (disasm, signature, hash) can be layered on without breaking existing logic.
4. **Actionable**: Score maps directly to analyst workflow (Low = archive, Medium = queue, High = urgent).

### Design Tradeoffs
- **Precision vs. Recall**: Tuned to reduce false positives (system drivers) over catching every possible risky behavior. Analysts review Medium/High; Low drivers are audited asynchronously.
- **Simplicity vs. Accuracy**: Points-based model is easy to understand and tune. More sophisticated ML would be harder to explain and maintain.
- **Early Detection**: Even Low scores are captured for baseline/anomaly detection over time.

---

## 8. FUTURE ENHANCEMENTS (Phase 2+)

### Near-term (Low Effort)
- [ ] Expand disassembly signals: call_count, rep-movs detection, instruction_count
- [ ] Add file signature check: signed vs. unsigned, certificate vendor
- [ ] Add hash reputation: VirusTotal match, known-good/known-bad hashes
- [ ] Detect DKOM: compare module list vs. object manager; flag mismatches

### Medium-term (Moderate Effort)
- [ ] Machine learning: train on dataset of known-good vs. malicious drivers
- [ ] Import list analysis: detect risky API imports (registry, direct I/O, DMA)
- [ ] Stack trace correlation: link driver load to process/event logs

### Long-term (High Effort)
- [ ] Behavioral simulation: execute handler in sandbox; observe system calls
- [ ] Cross-dump correlation: aggregate signals from 100s of dumps; flag anomalies
- [ ] Threat intel integration: feed scores into incident response/threat DB

---

## 9. IMPLEMENTATION CHECKLIST

### Phase 1 (Current - MVP)
- [x] IOCTL handler detection (Custom vs. Generic vs. None)
- [x] System driver whitelist (80+ drivers)
- [x] Size-based complexity scoring
- [x] Basic scoring formula (40-point IOCTL + size/classification adjustments)
- [ ] Safe name patterns (class.sys, port.sys, etc.)
- [ ] Network driver special case (-20 reduction)
- [ ] Handler location bonus (Generic -8)

### Phase 2 (Next Sprint)
- [ ] Capstone disassembly: call_count, rep-movs, instruction_count
- [ ] File signature check: signed/unsigned, certificate vendor
- [ ] Hash reputation: VT lookup, known-bad flagging
- [ ] Confidence scoring: track signal availability

### Phase 3 (Future)
- [ ] DKOM detection
- [ ] Import list analysis
- [ ] Behavioral anomalies
- [ ] ML-based risk modeling

---

## 10. EXAMPLE OUTPUT TABLE

After Phase 1 implementation, expected output:

| Base Address | Driver Name | Size | IOCTL Handler | Analysis | Risk Level |
|---|---|---|---|---|---|
| 0xf80c9f400000 | msrpc.sys | 0x62000 | Not Found | Enumerated | **Low (0%)** |
| 0xf80c9f470000 | ksecdd.sys | 0x2b000 | Custom | Custom IOCTL | **Low (15%)** |
| 0xf80ca01d0000 | Ntfs.sys | 0x28d000 | Custom | Custom IOCTL | **Low (25%)** |
| 0xf80ca0700000 | tcpip.sys | 0x2db000 | Custom | Custom IOCTL | **Low (30%)** |
| 0xf80382000000 | VBoxSF.sys | 0x5f000 | Custom | Custom IOCTL | **Low (15%)** |
| 0xf8037f320000 | malware.sys | 0x80000 | Custom | Custom IOCTL | **High (65%)** ← Flagged for review |

---

## Summary


---

## Phase 1.5: Anti-Rename Detection – Concept

Malicious drivers often disguise themselves by changing their name in memory or on disk to mimic legitimate system drivers. The anti-rename detection logic compares the driver’s name from two sources:
- The name from the module list (what’s loaded in memory, e.g., `tcpip_malicious.sys`)
- The name from the DRIVER_OBJECT structure (kernel registry, e.g., `tcpip`)

If these names don’t match, or if the driver’s size is inconsistent with known-good drivers, the risk score is increased. This helps catch BYOVD (Bring Your Own Vulnerable Driver) and rootkit attacks that rely on name spoofing.

### Anti-Rename Detection Table/Checklist

| Signal/Check | How It Works | Points Added | Rationale |
|--------------|--------------|-------------|-----------|
| **Name mismatch** | Compare normalized DRIVER_OBJECT name vs. module name (strip `.sys`, lowercase, split on `\\`) | +20 | Renamed drivers are suspicious; legitimate drivers rarely change names |
| **Size anomaly** | Compare actual driver size vs. expected size for known system drivers | +15 | Malware may use a smaller/larger binary to avoid detection |
| **Handler location anomaly** | If IOCTL handler is outside expected code range and not a known generic handler | +15 | Indicates possible code injection or hijacking |
| **Whitelist override** | If name matches whitelist but size or handler is anomalous, do not apply full whitelist reduction | -25 (blocked) | Prevents false negatives for spoofed names |
| **Log reasons** | Record which checks triggered for analyst review | — | Improves explainability and auditability |

### Example Scoring Flow

1. Extract both names:
    - `driver_obj_name` (from DRIVER_OBJECT, e.g., `tcpip`)
    - `module_name` (from module list, e.g., `tcpip_malicious.sys`)
2. Normalize both names (lowercase, strip `.sys`, split on `\\`)
3. If names differ, add +20 to risk score and log “Name mismatch”
4. If size differs from expected (e.g., `tcpip` should be ~0x2db000, but actual is 0x80000), add +15 and log “Size anomaly”
5. If handler address is outside expected range, add +15 and log “Handler anomaly”
6. If whitelist match but anomalies detected, block -25 reduction
7. Clamp score, assign label, and output reasons

### Example Table

| Driver Name (Module) | DRIVER_OBJECT Name | Size | Expected Size | Name Match? | Size Match? | Handler Location | Points Added | Reason(s) |
|----------------------|-------------------|------|---------------|-------------|-------------|------------------|--------------|-----------|
| tcpip_malicious.sys  | tcpip             | 0x80000 | 0x2db000      | No          | No          | Inside module    | +35          | Name mismatch, Size anomaly |
| ntfs.sys             | ntfs              | 0x28d000 | 0x28d000      | Yes         | Yes         | Inside module    | 0            | — |
| vboxguest.sys        | vboxguest         | 0x5f000 | 0x5f000       | Yes         | Yes         | Inside module    | 0            | — |
| malware.sys          | system32          | 0x90000 | N/A           | No          | N/A         | Outside module   | +35          | Name mismatch, Handler anomaly |

### Analyst Action

- **Score ≥ 50**: Immediate review (possible rootkit/BYOVD)
- **Score 30–49**: Queue for review (possible anomaly)
- **Score < 30**: Archive (likely legitimate)

This logic is fast, explainable, and catches real-world attacks that rely on driver name spoofing.

---

## Phase 2: Feasible Advanced Detection Techniques

### Pattern-Based Opcode Recognition
- Use Capstone to disassemble IOCTL handler code from memory dump.
- Scan for dangerous mnemonics: `mov`, `lea`, `jmp`, `call`, `push`, `pop`.
- Check operand patterns: direct memory access (`[cr3]`, `[physmem]`), process manipulation (`[eprocess]`, `pid`).
- Flag instructions that perform arbitrary read/write, physical memory access, or process manipulation.
- Assign risk points for each detected pattern.

### API Proximity Detection
- Build a table of known kernel API addresses (e.g., `MmMapIoSpace`, `ZwOpenSection`).
- For each CALL/JMP in handler code, check if target address is within ±0x50 (high risk) or ±0x200 (medium risk) of a known API.
- Flag and score based on proximity.

### Semantic API Signature Matching
- Maintain a database of byte patterns and Capstone instruction sequences for dangerous APIs.
- Scan handler code for these signatures, even if symbols are stripped or memory is fragmented.
- Assign high risk if a match is found.

### Integration & Scoring
- For each driver, aggregate risk points from opcode patterns, API proximity, and signature matches.
- Add to existing risk score.
- Log which signals triggered for analyst review.

#### Example Table: Advanced Detection Signals

| Signal Type                | Detection Method                | Points Added | Example Pattern/Match                | Rationale                        |
|----------------------------|---------------------------------|--------------|--------------------------------------|-----------------------------------|
| Dangerous opcode pattern   | Capstone mnemonic/operand scan  | +15          | `mov [cr3], eax`                     | Arbitrary memory access           |
| Physical memory access     | Capstone + operand structure    | +20          | `call MmMapIoSpace`                  | Direct physical memory mapping    |
| Process manipulation       | Capstone + register semantics   | +15          | `mov [eprocess+pid], ...`            | Process hiding/termination        |
| API proximity (high risk)  | CALL/JMP within ±0x50 of API    | +20          | CALL near `ZwTerminateProcess`       | Likely direct API abuse           |
| API proximity (medium)     | CALL/JMP within ±0x200 of API   | +10          | CALL near `MmMapLockedPagesSpecifyCache` | Possible API abuse           |
| Semantic signature match   | Byte pattern/Capstone sequence  | +25          | ZwOpenSection syscall stub           | Known dangerous API usage         |

#### Analyst Action

- **Score ≥ 70**: Immediate review (likely rootkit/BYOVD)
- **Score 40–69**: Queue for review (possible anomaly)
- **Score < 40**: Archive (likely legitimate)

#### Integration Steps
1. Add Capstone disassembly to plugin (if not present).
2. Build or import kernel API address table.
3. Create opcode and signature pattern database.
4. Implement scanning logic in driver analysis loop.
5. Aggregate and log risk signals for each driver.

