# 🧪 PERSON 4: QUICK REFERENCE CARD

**Your Role:** Testing & Anti-Forensics  
**Your Mission:** 10 test memory dumps + DKOM PoC + comprehensive testing

---

## ⏰ THIS WEEK (Nov 15-21)

### Day 1-2: Acquire Test Dumps

**10 Required Memory Dumps:**

1. **Clean Windows 10 (64-bit)**
   - Fresh VM, minimal drivers
   - Expected: All Low risk

2. **Clean Windows 11 (64-bit)**
   - Fresh VM, different OS version
   - Expected: All Low risk

3. **System with Known Vulnerable Driver**
   - Research: LOLDrivers.io
   - Try to get: gdrv.sys, RTCore64.sys, or DBUtil_2_3.sys
   - Expected: High/Critical risk for that driver

4. **Legitimate Hardware Driver System**
   - Install NVIDIA/Realtek/Intel drivers
   - Expected: Low/Medium risk (false positive test)

5. **Multiple Drivers System**
   - Load 5-10 different drivers
   - Expected: Stress test, performance check

6. **Second Vulnerable Driver**
   - Different driver than #3
   - Expected: High risk, different API patterns

7. **Clean Windows 10 (32-bit)** - Optional
   - If time permits, test 32-bit support
   - Expected: Plugin handles architecture correctly

8. **Antivirus/EDR System**
   - System with security software installed
   - Expected: Medium risk (some APIs detected but benign)

9. **DKOM Scenario**
   - Driver hidden from PsLoadedModuleList
   - Expected: Validator plugin detects it

10. **Bonus: Rootkit Sample** - If safe and time permits
    - Real malware sample in controlled VM
    - Expected: Critical risk, multiple detections

**How to Create Dumps:**
```powershell
# Install WinPmem
# https://github.com/Velocidex/WinPmem

# Run as Administrator
winpmem_mini_x64.exe memory_dump.raw

# Name files descriptively:
# clean_win10_baseline.raw
# vulnerable_gdrv_sys.raw
# dkom_hidden_driver.raw
```

**Document Each Dump:**
```markdown
# tests/TEST_INVENTORY.md

## Dump 1: clean_win10_baseline.raw
- OS: Windows 10 Pro 22H2 (64-bit)
- Date Created: 2025-11-15
- Size: 4.2 GB
- Drivers Expected: ~50 standard drivers
- Expected Risk: All Low
- Purpose: Baseline false positive test

## Dump 2: vulnerable_gdrv_sys.raw
- OS: Windows 10 Pro (64-bit)
- Driver: gdrv.sys (Gigabyte driver)
- Known Capabilities: Arbitrary physical memory access
- Expected Detection: MmMapIoSpace, ZwMapViewOfSection
- Expected Risk: Critical (90+)
- Purpose: True positive validation
```

**Success Check:** 10 dumps acquired + documented ✅

### Day 3-4: Initial Testing
```bash
# Run Person 1's scanner on first 5 dumps
vol3 -f clean_win10.raw ikarma.byovd_scanner > results1.txt
vol3 -f vulnerable.raw ikarma.byovd_scanner > results2.txt
# ... etc

# Document results
# tests/TEST_RESULTS_INITIAL.md
```

**Success Check:** Initial test results documented ✅

### Day 5-7: DKOM Proof-of-Concept

**Option A: Write Simple Driver (Advanced)**
```c
// Simple driver that hides itself
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Unlink from PsLoadedModuleList
    PLIST_ENTRY currentEntry = (PLIST_ENTRY)DriverObject->DriverSection;
    RemoveEntryList(currentEntry);
    
    return STATUS_SUCCESS;
}
```

**Option B: Use Existing Tool (Easier)**
- Research existing DKOM tools (academic use only!)
- Use in controlled VM
- Document the technique

**Option C: Thorough Documentation (Safest)**
- Research DKOM techniques thoroughly
- Document how they work
- Explain what validator plugin should detect
- Create mock scenario (manually modify memory dump metadata)

**Create DKOM Test Dump:**
1. Load driver in VM
2. Execute DKOM technique
3. Take memory dump
4. Verify Person 3's validator detects it

**Document in:** `tests/DKOM_POC.md`

**Success Check:** DKOM scenario created + documented ✅

---

## 📋 NEXT WEEK (Nov 22-28)

### Day 8-9: Comprehensive Testing

**Test Matrix (30 test runs):**
```
10 dumps × 3 plugins = 30 test runs

Scanner Tests (10):
- Dump 1 → Scanner → Check output
- Dump 2 → Scanner → Check output
- ... etc

Capability Tests (5):
- Dump 3 → Capability --driver evil.sys
- ... etc

Validator Tests (5):
- Dump 9 → Validator → Should find DKOM
- ... etc
```

**Calculate Metrics:**
```
True Positive (TP) = Correctly flagged vulnerable driver
False Positive (FP) = Incorrectly flagged benign driver
True Negative (TN) = Correctly passed benign driver
False Negative (FN) = Missed vulnerable driver

Detection Rate = TP / (TP + FN)
False Positive Rate = FP / (FP + TN)
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
```

**Performance Metrics:**
```
Time per dump = Measure execution time
Memory usage = Monitor with Task Manager
Throughput = Drivers analyzed per minute
```

**Create Comparison:**
```
Manual Analysis (IDA Pro):
- 30-60 minutes per driver
- Requires expert analyst
- High accuracy but slow

iKARMA:
- 1-2 minutes for 100 drivers
- Automated, consistent
- 90% accuracy, very fast

Time Saved = (Manual Time - iKARMA Time) / Manual Time
```

### Day 10-11: Results Compilation
- Create spreadsheets with all metrics
- Generate graphs/charts
- Write test report summary
- Give data to Person 5 for report

### Day 12-13: Final Validation
- Re-test any failed cases
- Verify all metrics are correct
- Prepare backup test scenarios for demo

---

## 🆘 IF YOU'RE STUCK

**Problem:** Can't find vulnerable driver samples  
**Solution:** Use LOLDrivers.io, ask on security Discord, or use older driver versions

**Problem:** VM keeps crashing when loading driver  
**Solution:** Take snapshot before loading, use nested virtualization, or just document

**Problem:** DKOM PoC too dangerous/complex  
**Solution:** Option C (documentation only) is perfectly acceptable

**Problem:** Test results don't make sense  
**Solution:** Re-run tests, check memory dump integrity, ask Person 1 for help

**Problem:** Don't have enough test dumps  
**Solution:** Create more clean baselines (easy), focus quality over quantity

---

## ✅ DAILY CHECKLIST

```
[ ] Acquire/create 1-2 memory dumps
[ ] Document each dump in TEST_INVENTORY.md
[ ] Run tests on latest code
[ ] Report bugs to team
[ ] Update test results
[ ] Post daily update
```

---

## 🎯 YOUR SUCCESS METRICS

- 10 memory dumps acquired ✅
- All dumps documented ✅
- DKOM scenario created ✅
- Comprehensive test results ✅
- Metrics calculated ✅
- Comparison to manual analysis ✅

**Key Files:**
- `tests/TEST_INVENTORY.md` (dump documentation)
- `tests/TEST_RESULTS.md` (results compilation)
- `tests/DKOM_POC.md` (DKOM documentation)
- `tests/metrics.xlsx` (calculated metrics)

**Key Deliverable:** You provide the PROOF that iKARMA works!
