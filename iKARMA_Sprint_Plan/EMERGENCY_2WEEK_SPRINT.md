# 🚨 EMERGENCY 2-WEEK SPRINT: iKARMA BYOVD Detection Suite

**Date Created:** November 15, 2025  
**Deadline:** November 29, 2025 (14 days)  
**Grade Weight:** 30% of module  
**Status:** CRITICAL - Behind schedule, need rapid execution

---

## 📊 CURRENT STATUS (What We Have)

✅ **COMPLETED:**
- Driver enumeration working (`driver_analysis.py`)
- IOCTL handler extraction functional
- Basic Capstone disassembly integration
- Placeholder modules created (`utils/api_scanner.py`, `core/risk_scorer.py`)
- Project structure established

❌ **MISSING (Critical for 30% grade):**
- No actual API pattern detection (Person 2's core work)
- No actual risk scoring algorithm (Person 3's core work)
- No DKOM detection or cross-view validation
- No comprehensive testing (only 1 memory dump tested)
- Documentation incomplete

---

## 🎯 THE NEW STRATEGY: 3-Plugin Suite

Instead of one mega-plugin, we're building **THREE focused plugins** that work together:

```
iKARMA BYOVD Detection Suite:
├── ikarma.byovd_scanner      → Fast triage (100 drivers in 2 min)
├── ikarma.byovd_capability   → Deep-dive analysis (1 driver, full detail)
└── ikarma.byovd_validator    → Anti-forensic detection (DKOM checks)
```

**Why this is better:**
1. Shows more work (3 plugins vs 1)
2. Each plugin has a clear forensic purpose
3. Easier to divide work among team
4. More impressive for presentations/conferences
5. Demonstrates mastery of Volatility3 plugin development

---

## 👥 ROLE ASSIGNMENTS (Updated for Reality)

### **Person 1: Team Lead & Integration** 🔧
**What you've done:** Created `driver_analysis.py`, got IOCTL extraction working  
**What you need to do:** Transform it into 2 production plugins + integrate Person 2 & 3's work

**Time allocation:**
- Week 1: 70% coding, 30% integration
- Week 2: 30% coding, 70% testing/polish

---

### **Person 2: API Hunter** 🎯
**What you've done:** Created placeholder `api_scanner.py`  
**What you need to do:** Implement REAL pattern matching for 20+ dangerous APIs

**Time allocation:**
- Week 1: 90% research + implementation
- Week 2: 10% refinement, then help Person 4 with testing

---

### **Person 3: Risk Analyst** 📊
**What you've done:** Created placeholder `risk_scorer.py`  
**What you need to do:** Implement scoring algorithm + confidence framework + DKOM detection plugin

**Time allocation:**
- Week 1: 60% scoring, 40% confidence framework
- Week 2: 50% DKOM plugin, 50% integration

---

### **Person 4: Testing & Anti-Forensics** 🧪
**What you've done:** Initial research  
**What you need to do:** Acquire 10 test memory dumps + create DKOM PoC + comprehensive testing

**Time allocation:**
- Week 1: 70% test acquisition, 30% research
- Week 2: 90% testing, 10% PoC documentation

---

### **Person 5: Documentation Lead** 📝
**What you've done:** Initial structure  
**What you need to do:** Complete methodology, results, presentation, demo video

**Time allocation:**
- Week 1: 40% methodology, 60% mock-ups
- Week 2: 30% results compilation, 70% presentation materials

---

## 📅 DETAILED 14-DAY SCHEDULE

### **WEEK 1: CORE FUNCTIONALITY**

#### **Day 1-2 (Nov 15-16): Foundation Sprint**

**Person 1:** 
- [ ] Refactor `driver_analysis.py` → `byovd_scanner.py`
- [ ] Add command-line options: `--high-risk-only`, `--export-json`, `--detailed`
- [ ] Wire up calls to Person 2 & 3's modules (even if they return mock data)
- [ ] Add progress indicators and better console output formatting
- [ ] **Deliverable:** Working plugin that calls (stubbed) API scanner and risk scorer

**Person 2:**
- [ ] Study `DANGEROUS_APIS.md` - categorize APIs into groups:
  - Memory Access (MmMapIoSpace, ZwMapViewOfSection, etc.)
  - Process Manipulation (PsLookupProcessByProcessId, ZwTerminateProcess)
  - Kernel Objects (ObReferenceObjectByHandle, etc.)
- [ ] Create `core/api_patterns.py` - structured database of 20 APIs with risk scores
- [ ] Implement THREE detection methods in `utils/api_scanner.py`:
  1. String matching (fast, finds API names in disassembly)
  2. Call instruction analysis (high confidence)
  3. String reference detection (moderate confidence)
- [ ] **Deliverable:** Working `find_dangerous_apis()` that detects at least 10 APIs

**Person 3:**
- [ ] Design risk scoring algorithm in `core/risk_scorer.py`:
  ```python
  Base Score = Σ (API_risk × API_confidence)
  
  Modifiers:
  × 1.5 if dangerous API combination detected
  × 1.3 if no input validation detected
  × 1.2 if code is obfuscated
  
  Final Score → Risk Level (Low/Medium/High/Critical)
  ```
- [ ] Implement `calculate_risk()` function
- [ ] Start `core/confidence.py` framework:
  - Direct call = 0.95 confidence
  - String reference = 0.8 confidence
  - Opcode pattern = 0.7 confidence
- [ ] **Deliverable:** Working risk scorer with at least 3 confidence factors

**Person 4:**
- [ ] Acquire 5 memory dumps:
  1. Clean Windows 10 baseline
  2. Clean Windows 11 baseline
  3. System with known vulnerable driver (research LOLDrivers)
  4. System with legitimate hardware driver (NVIDIA/Realtek)
  5. Start creating DKOM scenario VM
- [ ] Document each dump in `tests/TEST_INVENTORY.md`:
  - OS version, architecture
  - Expected drivers present
  - Expected risk scores
- [ ] **Deliverable:** 5 test dumps ready + inventory document

**Person 5:**
- [ ] Create complete report structure with sections:
  1. Abstract (placeholder)
  2. Introduction (draft from existing docs)
  3. Literature Review (cite 5+ papers)
  4. Methodology (draft architecture)
  5. Implementation (placeholder)
  6. Results (placeholder tables/graphs)
  7. Discussion
  8. Conclusion
  9. References
- [ ] Create presentation structure (15-20 slides):
  - Title, Problem, Solution, Architecture, Demo, Results, Conclusion
- [ ] **Deliverable:** 50% complete report draft + presentation skeleton

---

#### **Day 3-4 (Nov 17-18): Integration & Testing Sprint**

**Person 1:**
- [ ] Integrate Person 2's API scanner - test with real disassembly from test dumps
- [ ] Integrate Person 3's risk scorer - verify score calculations
- [ ] Debug integration issues (API scanner output format matches risk scorer input)
- [ ] Add JSON export functionality:
  ```json
  {
    "driver": "evil.sys",
    "risk_score": 87,
    "risk_level": "High",
    "detected_apis": [...],
    "confidence": 0.82,
    "reasons": [...]
  }
  ```
- [ ] **Deliverable:** Fully integrated `byovd_scanner.py` producing real results

**Person 2:**
- [ ] Expand API database to 20+ APIs
- [ ] Add opcode pattern detection for 3 vulnerability types:
  1. Missing bounds check before memory access
  2. Missing NULL pointer validation
  3. Missing privilege level checks
- [ ] Example pattern:
  ```python
  def detect_unsafe_dereference(instructions):
      """Detect: mov rax, [user_ptr] ; mov [rax], data  (no validation!)"""
      for i in range(len(instructions) - 1):
          if is_user_pointer_load(instructions[i]):
              if is_dereference(instructions[i+1]) and not has_validation_between(i, i+1):
                  return True
      return False
  ```
- [ ] Test against Person 4's memory dumps
- [ ] **Deliverable:** Enhanced API scanner with opcode analysis

**Person 3:**
- [ ] Implement confidence framework completely
- [ ] Add "because" tag generation:
  ```python
  reasons = [
      "MmMapIoSpace detected (arbitrary physical memory access)",
      "No input validation found before memory operation",
      "Detection confidence: High (direct call instruction)"
  ]
  ```
- [ ] Test risk scorer with various API combinations
- [ ] Start designing `byovd_validator.py` plugin architecture
- [ ] **Deliverable:** Complete risk scorer + confidence framework

**Person 4:**
- [ ] Finish acquiring all 10 test dumps:
  6. Second vulnerable driver sample
  7. Third clean baseline (different OS version)
  8. System with multiple drivers (stress test)
  9. DKOM scenario (hidden driver)
  10. Bonus: System with rootkit (if time permits)
- [ ] Run Person 1's scanner against all 5 current dumps
- [ ] Document results in `tests/TEST_RESULTS.md`:
  - What was detected
  - False positives
  - False negatives
  - Performance (time per dump)
- [ ] **Deliverable:** 10 test dumps + initial test results

**Person 5:**
- [ ] Write complete Methodology section:
  - Multi-method API detection approach (cite literature)
  - Risk scoring algorithm (mathematical formula)
  - Confidence framework (evidence hierarchy)
- [ ] Create architecture diagrams:
  - System overview (3 plugins)
  - Data flow diagram (memory dump → results)
  - API detection process flowchart
- [ ] Draft presentation slides with mock-up results
- [ ] **Deliverable:** 70% complete report + 50% complete presentation

---

#### **Day 5-7 (Nov 19-21): Advanced Features Sprint**

**Person 1:**
- [ ] Create second plugin: `byovd_capability.py`
  - Deep-dive analysis of ONE driver
  - Input: `--driver evil.sys` or `--address 0xfffff80001234567`
  - Output: Full disassembly (500+ instructions), all detected APIs with addresses, call chain analysis
- [ ] Implement call chain detection:
  ```python
  # Detect: MmMapIoSpace → MmCopyMemory chain (very dangerous)
  # Detect: PsLookupProcessByProcessId → manipulation chain
  ```
- [ ] Add detailed logging mode: `--verbose`
- [ ] **Deliverable:** Working `byovd_capability.py` plugin

**Person 2:**
- [ ] Add import table analysis (if PE header is readable from memory):
  ```python
  def analyze_import_table(driver_base, layer):
      """Parse IAT for dangerous API imports"""
      pe = parse_pe_from_memory(driver_base, layer)
      imports = pe.DIRECTORY_ENTRY_IMPORT
      return [imp for imp in imports if imp.name in DANGEROUS_APIS]
  ```
- [ ] Implement API combination detection:
  ```python
  DANGEROUS_COMBINATIONS = {
      ('MmMapIoSpace', 'MmCopyMemory'): {'multiplier': 1.5, 'reason': 'Arbitrary read/write capability'},
      ('PsLookupProcessByProcessId', 'KeStackAttachProcess'): {'multiplier': 1.4, 'reason': 'Process injection capability'}
  }
  ```
- [ ] Document all detection methods in `utils/api_scanner.py` header
- [ ] **Deliverable:** Enhanced detection with import analysis + combinations

**Person 3:**
- [ ] Create third plugin: `byovd_validator.py`
- [ ] Implement cross-view validation:
  ```python
  # View 1: Official kernel module list (PsLoadedModuleList)
  official_drivers = get_from_modules_plugin(context, kernel)
  
  # View 2: Pool scanning for PE headers (independent)
  carved_drivers = scan_pools_for_pe_headers(context, layer)
  
  # View 3: Object Manager \Driver\ namespace
  object_drivers = enumerate_driver_objects(context, kernel)
  
  # Find discrepancies (DKOM indicators)
  hidden = carved_drivers - official_drivers
  inconsistent = check_size_mismatches(official_drivers, carved_drivers)
  ```
- [ ] Implement basic DKOM detection:
  - List unlinking detection
  - Size mismatches
  - Timestamp anomalies
- [ ] **Deliverable:** Working `byovd_validator.py` plugin with DKOM detection

**Person 4:**
- [ ] Create DKOM proof-of-concept:
  - Option A: Write simple kernel driver that unlinks itself
  - Option B: Use existing tool to hide a driver
  - Option C: Document the technique thoroughly (if implementation too risky)
- [ ] Create memory dump with hidden driver
- [ ] Verify Person 3's validator plugin detects it
- [ ] Run comprehensive test suite on all 3 plugins:
  - Create test matrix (10 dumps × 3 plugins = 30 test runs)
- [ ] **Deliverable:** DKOM PoC + comprehensive test results

**Person 5:**
- [ ] Write Implementation section (full technical details)
- [ ] Create "Related Work" comparison table:
  | Tool | Capability | iKARMA Advantage |
  |------|-----------|------------------|
  | POPKORN | Requires binaries | Memory-only analysis |
  | IoctlHunter | No risk scoring | Automated scoring |
  | Vol3 driverscan | No capability analysis | Full risk profiling |
- [ ] Draft Results section with placeholder tables:
  - Detection accuracy table
  - False positive/negative rates
  - Performance benchmarks
- [ ] **Deliverable:** 85% complete report

---

### **WEEK 2: TESTING, POLISH & PRESENTATION**

#### **Day 8-9 (Nov 22-23): Testing & Bug Fixing**

**Person 1:**
- [ ] Fix all bugs reported by Person 4
- [ ] Optimize performance (profile code, reduce bottlenecks)
- [ ] Add error handling for edge cases:
  - Corrupted memory dumps
  - Missing symbols
  - Paged-out memory
- [ ] Polish output formatting (color coding, tables, clear summaries)
- [ ] **Deliverable:** Production-ready 3-plugin suite

**Person 2:**
- [ ] Help Person 4 with testing
- [ ] Fine-tune detection thresholds to reduce false positives
- [ ] Document all 20+ APIs in `DETECTED_APIS.md`:
  - API name
  - What it does
  - Why it's dangerous
  - Risk score
  - Detection method
- [ ] **Deliverable:** Complete API documentation

**Person 3:**
- [ ] Refine risk scoring based on test results
- [ ] Adjust thresholds (maybe Low: 0-40, Medium: 41-70, High: 71-90, Critical: 91+)
- [ ] Ensure "because" tags are clear and forensically useful
- [ ] Polish validator plugin output
- [ ] **Deliverable:** Optimized scoring + polished validator

**Person 4:**
- [ ] Run final test suite on all 10 dumps
- [ ] Calculate metrics:
  ```
  Detection Rate = (True Positives) / (True Positives + False Negatives)
  False Positive Rate = (False Positives) / (True Negatives + False Positives)
  Precision = TP / (TP + FP)
  Recall = TP / (TP + FN)
  ```
- [ ] Create comparison: "Time to analyze manually (IDA) vs. iKARMA"
- [ ] **Deliverable:** Final test report with metrics

**Person 5:**
- [ ] Populate Results section with real data from Person 4
- [ ] Create graphs/charts:
  - Bar chart: Detection accuracy across test cases
  - Pie chart: Distribution of detected API categories
  - Table: Performance benchmarks
- [ ] Write Discussion section (interpret results, limitations, future work)
- [ ] **Deliverable:** 95% complete report

---

#### **Day 10-11 (Nov 24-25): Demo Preparation**

**Person 1:**
- [ ] Choose best demo scenario from Person 4's test dumps
- [ ] Create demo script:
  ```powershell
  # Demo Script
  # 1. Show clean system - low risk
  vol3 -f clean_win10.vmem ikarma.byovd_scanner
  
  # 2. Show vulnerable driver - high risk
  vol3 -f malicious.vmem ikarma.byovd_scanner
  
  # 3. Deep-dive on suspicious driver
  vol3 -f malicious.vmem ikarma.byovd_capability --driver evil.sys
  
  # 4. Check for DKOM
  vol3 -f dkom_scenario.vmem ikarma.byovd_validator
  ```
- [ ] Practice demo multiple times
- [ ] **Deliverable:** Polished demo script + rehearsed presentation

**Person 2 & 3:**
- [ ] Review all documentation for accuracy
- [ ] Prepare to answer technical questions about detection methods
- [ ] Create "Technical Deep-Dive" backup slides (if asked)
- [ ] **Deliverable:** Technical Q&A preparation

**Person 4:**
- [ ] Prepare "test results" slides showing metrics
- [ ] Create comparison charts (iKARMA vs manual analysis)
- [ ] Prepare backup test scenarios (if demo fails)
- [ ] **Deliverable:** Results presentation materials

**Person 5:**
- [ ] Finalize report (100% complete)
- [ ] Finalize presentation slides
- [ ] Start recording demo video:
  - 5-7 minutes total
  - Introduction (30 sec)
  - Problem explanation (1 min)
  - Live demo (3-4 min)
  - Results summary (1 min)
  - Conclusion (30 sec)
- [ ] **Deliverable:** Draft video (80% complete)

---

#### **Day 12-13 (Nov 26-27): Final Polish**

**ALL TEAM:**
- [ ] Full team review of report (everyone reads, provides feedback)
- [ ] Full team rehearsal of presentation
- [ ] Finish demo video recording
- [ ] Create poster (if required)
- [ ] Prepare submission package:
  ```
  submission/
  ├── report.pdf
  ├── presentation.pptx
  ├── demo_video.mp4
  ├── poster.pdf (if needed)
  ├── source_code.zip
  │   ├── plugins/
  │   ├── core/
  │   ├── utils/
  │   └── README.md
  └── test_results/
      ├── TEST_RESULTS.md
      ├── test_dumps/ (metadata, not actual files)
      └── metrics.xlsx
  ```

---

#### **Day 14 (Nov 28): Buffer Day**

**Purpose:** Final bug fixes, emergency changes, submission preparation
- DO NOT plan new features for this day
- Use only for critical fixes or submission issues

---

## 🎯 SUCCESS CRITERIA

### **Minimum Viable Product (Must Have):**
- ✅ 3 working Volatility3 plugins
- ✅ Detect 20+ dangerous APIs with 3 detection methods
- ✅ Risk scoring algorithm with confidence framework
- ✅ Basic DKOM detection (cross-view validation)
- ✅ 10 test cases with documented results
- ✅ Complete report (methodology + results + discussion)
- ✅ Presentation + demo video

### **Stretch Goals (Nice to Have):**
- Call chain analysis
- Import table parsing
- Advanced opcode pattern matching
- Web UI for results
- YARA rule integration

---

## 🚨 RISK MANAGEMENT

### **What If We Fall Behind?**

**Priority Levels:**
1. **CRITICAL (Must have for passing):**
   - At least 1 working plugin (scanner)
   - At least 10 API detections
   - Basic risk scoring
   - Complete report

2. **HIGH (Needed for good grade):**
   - 3 working plugins
   - 20 API detections
   - Confidence framework
   - Test results

3. **MEDIUM (Needed for excellent grade):**
   - Opcode analysis
   - DKOM detection
   - Comprehensive testing

4. **LOW (Bonus points):**
   - Call chains
   - Import analysis
   - Advanced features

**If behind schedule on Day 7:**
- Drop: Call chain analysis, import table parsing
- Keep: Core 3 plugins, API detection, risk scoring

**If behind schedule on Day 10:**
- Drop: Validator plugin (DKOM)
- Merge: Capability plugin into scanner
- Keep: 1 strong scanner plugin + comprehensive testing

---

## 📞 COMMUNICATION PROTOCOL

### **Daily Standups (15 min, same time every day):**
1. What I did yesterday
2. What I'm doing today
3. Am I blocked? (if yes, who can help)

### **Blockers:**
- If blocked for >2 hours → Post in group chat immediately
- If blocked for >4 hours → Emergency team call
- Don't suffer in silence - ASK FOR HELP

### **Code Check-ins:**
- Commit working code at end of each day
- Use branch names: `person1-scanner`, `person2-api-hunter`, etc.
- Person 1 merges to main after testing

---

## 📚 KEY RESOURCES

### **For Person 2 (API Hunter):**
- `DANGEROUS_APIS.md` (in repo)
- LOLDrivers GitHub: https://github.com/magicsword-io/LOLDrivers
- POPKORN paper: Search "BYOVD capability analysis"

### **For Person 3 (Risk Analyst):**
- Academic papers on risk scoring
- CVSS scoring methodology (for inspiration)
- Confidence scoring in ML (transfer concepts)

### **For Person 4 (Testing):**
- WinPmem: https://github.com/Velocidex/WinPmem
- VirtualBox for creating test VMs
- VirusTotal for finding vulnerable drivers

### **For Person 5 (Documentation):**
- IEEE paper template (if required)
- Academic writing guide
- Grammarly for proofreading

---

## ✅ DAILY CHECKLIST TEMPLATE

Copy this and use it every day:

```
Date: ___________
Person: ___________

Morning Tasks:
[ ] Check group chat for updates
[ ] Review yesterday's code changes
[ ] Plan today's 3 main tasks

Task 1: ___________________________
Started: _____  Completed: _____  Status: _____

Task 2: ___________________________
Started: _____  Completed: _____  Status: _____

Task 3: ___________________________
Started: _____  Completed: _____  Status: _____

Blockers:
_____________________________________

Help Needed From:
_____________________________________

Tomorrow's Priority:
_____________________________________

Code Committed: [ ] Yes  [ ] No
Docs Updated: [ ] Yes  [ ] No  [ ] N/A
```

---

## 🎓 WHY THIS WILL GET YOU 30%

1. **Technical Complexity:** 3 plugins, multiple detection methods, advanced algorithms
2. **Research Quality:** Literature review, methodology, evaluation metrics
3. **Practical Impact:** Real tool, solves real problem, saves analyst time
4. **Professional Presentation:** Complete documentation, polished demo, clear results
5. **Novel Contribution:** Multi-method detection, confidence framework, cross-view validation

**This is conference-worthy work if executed well.**

---

## 💪 FINAL MOTIVATION

You have 14 days. That's 336 hours. If each person works 4 hours/day focused time, that's 280 person-hours of work.

This is ACHIEVABLE, but only if:
1. Everyone follows their assigned tasks
2. No one gets paralyzed by uncertainty (use this guide)
3. Communication is daily and honest
4. You prioritize COMPLETION over PERFECTION

**Remember:** A working 80% solution submitted on time beats a perfect 100% solution that's never finished.

**LET'S DO THIS.** 🚀

---

## 📞 EMERGENCY CONTACTS

If you're stuck or panicking:
1. Post in group chat
2. Call emergency team meeting
3. Ask the LLM assistant (me) for help - paste this entire document and your specific question

**DO NOT waste time being stuck. Ask for help immediately.**

---

*Last Updated: November 15, 2025*
*Next Review: November 22, 2025 (midpoint check)*
