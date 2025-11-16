# iKARMA Testing Guide

**For:** Person 2 (API Hunter) and team collaboration
**Last Updated:** 2025-11-16

---

## Quick Answer: Who Do You Work With?

### **Person 2 (API Hunter) Collaboration Map:**

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR POSITION (Person 2)                 │
│                                                             │
│  Input from:   Person 1 (Team Lead)                        │
│  Output to:    Person 3 (Risk Analyst)                     │
│  Testing with: Person 4 (Tester)                           │
│  Docs for:     Person 5 (Documentation)                    │
└─────────────────────────────────────────────────────────────┘
```

### **Closest Collaboration:**

**1. Person 1 (Team Lead) - UPSTREAM DEPENDENCY**
- **What they give you:** Disassembled code (list of instruction strings)
- **What you give them:** Integrated scanner (they call your `find_dangerous_apis()`)
- **Testing together:** Integration test (see below)
- **Communication:** Daily sync on data formats

**2. Person 3 (Risk Analyst) - DOWNSTREAM CONSUMER**
- **What you give them:** List of API findings with risk scores
- **What they give you:** Feedback on detection accuracy
- **Testing together:** Output format validation
- **Communication:** Handoff meeting + documentation

**3. Person 4 (Tester) - QUALITY ASSURANCE**
- **What they give you:** Bug reports, edge cases, test scenarios
- **What you give them:** Test scripts, expected outputs
- **Testing together:** Validation with real memory dumps
- **Communication:** Test results review

---

## Test Levels (How to Test Your Work)

### Level 1: Unit Tests (Solo - No Dependencies)

**Test ONLY your code, no integration needed.**

#### Test 1A: API Database
```bash
cd "C:\Users\marty\OneDrive\Documents\GitHub\iKARMA"
python core/api_patterns.py
```

**Expected:**
- `[OK] Total APIs in database: 18`
- Lists all APIs, categories, critical APIs
- No errors

**What it tests:**
- Database structure is valid
- Utility functions work
- No import errors

**If it fails:** Fix `core/api_patterns.py`

---

#### Test 1B: API Scanner (Mock Data)
```bash
python utils/api_scanner.py
```

**Expected:**
- `[TEST 1-6]` All tests pass
- Detects 3-7 findings in mock data
- `Scanner is ready for integration`

**What it tests:**
- String matching works
- Call pattern analysis works
- String reference detection works
- Deduplication logic works
- Statistics generation works

**If it fails:** Fix `utils/api_scanner.py`

---

#### Test 1C: Python Imports
```bash
python -c "from core.api_patterns import API_DATABASE, get_all_api_names; print('[OK] Core imported')"
python -c "from utils.api_scanner import find_dangerous_apis; print('[OK] Utils imported')"
```

**Expected:** `[OK]` messages, no errors

**What it tests:**
- Module paths are correct
- `__init__.py` files work
- No circular imports

**If it fails:** Check `sys.path` and `__init__.py` files

---

### Level 2: Integration Tests (With Person 1's Code)

**Test your code works with Person 1's disassembly output.**

#### Test 2A: Full Pipeline Integration
```bash
python test_integration.py
```

**Expected:**
- `[STEP 1-6]` All steps complete
- `[SUCCESS] Integration test PASSED!`
- Shows 4 findings from mock disassembly

**What it tests:**
- Person 1's format → Your scanner: COMPATIBLE
- Your scanner → Person 3's format: VALID
- Data flows correctly through pipeline
- Statistics generation works

**If it fails:**
- Check disassembly format in `test_integration.py`
- Verify `find_dangerous_apis()` function signature
- Check output dictionary keys

---

#### Test 2B: Manual Integration Test (If Person 1's plugin is ready)
```bash
# This will work once Person 1 has a memory dump to test with
cd "C:\Users\marty\OneDrive\Documents\GitHub\iKARMA"
python -m volatility3.vol -f test_memory.dmp windows.driver_analysis --debug
```

**Expected:**
- Plugin runs without errors
- API findings appear in output (if dangerous APIs detected)
- No import errors

**What it tests:**
- Real Volatility3 integration
- Actual memory dump analysis
- Real disassembly → scanner pipeline

**If it fails:**
- Check Volatility3 installation: `pip show volatility3`
- Verify plugin integration in `plugins/driver_analysis.py`
- Check import paths

---

### Level 3: End-to-End Tests (With Person 3 & 4)

**Test the full workflow: Memory dump → Risk report**

#### Test 3A: Person 3 Handoff Test

**When Person 3 starts their work, run this:**

```python
# They will write code like this in core/risk_scorer.py
from utils.api_scanner import find_dangerous_apis

# Your output becomes their input
findings = find_dangerous_apis(disassembly_lines)

# They should be able to access:
for finding in findings:
    print(finding['name'])        # API name
    print(finding['risk'])        # 0-10 score
    print(finding['confidence'])  # 0.0-1.0
    print(finding['category'])    # Category string
    print(finding['why_dangerous'])  # Explanation
```

**Expected:** Person 3 can consume your data without modification

**If Person 3 says "I can't use this format":**
- Show them `test_integration.py` output
- Check `PERSON2_COMPLETION_REPORT.md` handoff section
- Review output format in `DETECTED_APIS.md`

---

#### Test 3B: Real Memory Dump Test (With Person 4)

**Once Person 4 has test memory dumps:**

```bash
# Person 4 will run this and give you results
vol3 -f known_byovd_sample.dmp windows.driver_analysis
```

**Expected (on known BYOVD malware):**
- Detects dangerous APIs (MmMapIoSpace, ZwTerminateProcess, etc.)
- Risk scores make sense
- No false negatives (should catch all known bad APIs)

**Expected (on clean system dump):**
- Few or no dangerous APIs
- Low false positives
- No crashes

**If false negatives (missed detection):**
- Add missing API to `core/api_patterns.py`
- Improve detection patterns
- Update tests

**If false positives (wrong detection):**
- Increase confidence thresholds
- Add context checks
- Improve pattern matching

---

## Test Checklist by Person

### ✅ Testing Solo (Person 2 only)

- [ ] `python core/api_patterns.py` passes
- [ ] `python utils/api_scanner.py` passes
- [ ] Import tests pass (both core and utils)
- [ ] `test_integration.py` passes
- [ ] All 18 APIs in database
- [ ] 3 detection methods working
- [ ] Documentation complete

**Time:** 10-15 minutes
**Frequency:** Every time you change code

---

### ✅ Testing with Person 1 (Team Lead)

**When to test together:**
- Before you commit changes
- When Person 1 updates disassembly format
- Before major milestones

**What to test:**
```bash
# 1. Run integration test
python test_integration.py

# 2. If Person 1 has real memory dump:
vol3 -f test.dmp windows.driver_analysis --debug

# 3. Verify output format matches expectations
```

**Communication checklist:**
- [ ] Disassembly format documented (format: `"0xaddr:\tmnemonic\top_str"`)
- [ ] Import paths working in `plugins/driver_analysis.py`
- [ ] Error handling tested (what if scanner fails?)
- [ ] Performance acceptable (<1 second per driver)

**Time:** 30-60 minutes
**Frequency:** Daily during integration phase

---

### ✅ Testing with Person 3 (Risk Analyst)

**When to test together:**
- At handoff (when Person 3 starts work)
- When they request format changes
- During risk scoring implementation

**What to test:**
```python
# Person 3 should be able to run this without errors:
from utils.api_scanner import find_dangerous_apis, get_scanner_statistics

mock_disasm = ["0x123:\tcall\tqword ptr [rip]", "0x124:\t; nt!MmMapIoSpace"]
findings = find_dangerous_apis(mock_disasm)

# Verify they can access all fields:
print(findings[0]['name'])          # Works?
print(findings[0]['risk'])          # Works?
print(findings[0]['confidence'])    # Works?

# Test statistics helper:
stats = get_scanner_statistics(findings)
print(stats['highest_risk'])        # Works?
```

**Communication checklist:**
- [ ] Output format documented in `DETECTED_APIS.md`
- [ ] All required keys present in findings dict
- [ ] Statistics helper function explained
- [ ] Example integration shown in `test_integration.py`

**Time:** 1-2 hours for handoff meeting
**Frequency:** Once at handoff, then as-needed

---

### ✅ Testing with Person 4 (Tester)

**When to test together:**
- When they have test memory dumps
- During validation phase
- For bug reproduction

**What to provide Person 4:**
1. **Test script:** `test_integration.py`
2. **Expected outputs:** See `PERSON2_COMPLETION_REPORT.md`
3. **Known limitations:** See `DETECTED_APIS.md` - Limitations section

**What to ask Person 4 for:**
- Real memory dumps (clean systems)
- Known BYOVD samples (malicious drivers)
- Edge cases (corrupted dumps, empty drivers)
- Performance metrics (time per driver)

**Metrics to track:**
- **Detection rate:** % of known bad APIs detected
- **False positive rate:** % of clean drivers flagged
- **Performance:** Seconds per driver analyzed
- **Crash rate:** % of dumps that cause errors

**Time:** 2-4 hours for test session
**Frequency:** 1-2 times during sprint

---

### ✅ Testing with Person 5 (Documentation)

**When to work together:**
- When they review your documentation
- If they need clarification
- For user guide examples

**What to provide:**
- [ ] `DETECTED_APIS.md` (comprehensive API docs)
- [ ] `utils/README.md` (quick start guide)
- [ ] `PERSON2_COMPLETION_REPORT.md` (completion report)
- [ ] `test_integration.py` (working examples)

**What they might ask:**
- "How do I explain this to non-technical users?"
- "Can you provide a simple example?"
- "What's the most important thing users should know?"

**Time:** 1-2 hours for review
**Frequency:** Once, during documentation phase

---

## Common Test Scenarios

### Scenario 1: "My imports don't work!"

**Symptom:** `ModuleNotFoundError: No module named 'core'`

**Diagnosis:**
```bash
# Check if files exist
ls core/__init__.py
ls utils/__init__.py

# Check Python path
python -c "import sys; print(sys.path)"

# Try direct import
cd iKARMA
python -c "from core.api_patterns import API_DATABASE"
```

**Fix:**
1. Make sure `__init__.py` files exist in `core/` and `utils/`
2. Run from project root directory
3. Check `sys.path.insert(0, ...)` in your code

---

### Scenario 2: "Integration test fails!"

**Symptom:** `test_integration.py` shows errors

**Diagnosis:**
```bash
# Run with more detail
python test_integration.py 2>&1 | more

# Check what step failed
# Look for [STEP X] in output
```

**Common causes:**
- **Step 1 fails:** Mock data format wrong
- **Step 2 fails:** Scanner has bugs
- **Step 3 fails:** Output format wrong
- **Step 5 fails:** Statistics function broken

**Fix:** Look at the error message, fix the specific function

---

### Scenario 3: "Person 3 says my output is wrong!"

**Symptom:** Person 3 can't use your findings

**Diagnosis:**
```python
# Check output format
findings = find_dangerous_apis(test_data)
print(findings[0].keys())  # Should have: name, risk, confidence, etc.
```

**Fix:**
1. Show them `test_integration.py` - this is the exact format
2. Check if they need additional fields
3. Update `find_dangerous_apis()` to include new fields

---

### Scenario 4: "False positives in clean drivers!"

**Symptom:** Clean drivers get flagged as dangerous

**Diagnosis:**
- Which API is being falsely detected?
- What's the confidence score?
- Is it a string match or pattern match?

**Fix:**
1. **Lower confidence:** APIs detected with low confidence (<0.7) are suspicious
2. **Context matters:** Some APIs are legitimate - Person 3 will handle this
3. **Improve patterns:** Make string matching more specific

---

## Quick Test Commands (Copy-Paste)

```bash
# Full test suite (run all tests)
cd "C:\Users\marty\OneDrive\Documents\GitHub\iKARMA"
python core/api_patterns.py && python utils/api_scanner.py && python test_integration.py

# Import test
python -c "from core import API_DATABASE; from utils import find_dangerous_apis; print('[OK] All imports work')"

# Quick function test
python -c "from utils.api_scanner import find_dangerous_apis; print(len(find_dangerous_apis(['0x1:\tcall\tMmMapIoSpace'])))"

# Database info
python -c "from core.api_patterns import get_all_api_names; print(f'{len(get_all_api_names())} APIs loaded')"
```

---

## Test Status Dashboard

### Person 2 (API Hunter) Test Status:

| Test Level | Status | Last Tested | Notes |
|------------|--------|-------------|-------|
| Unit tests (solo) | ✅ PASS | 2025-11-16 | All 18 APIs working |
| Integration test | ✅ PASS | 2025-11-16 | Person 1 format compatible |
| Import tests | ✅ PASS | 2025-11-16 | All modules import |
| Person 3 handoff | ⏳ PENDING | - | Waiting for Person 3 |
| Real memory dump | ⏳ PENDING | - | Waiting for Person 4 |
| Performance test | ⏳ PENDING | - | Waiting for Person 4 |

---

## When to Run Tests

### **Daily (During Development):**
- Unit tests (`python core/api_patterns.py`)
- Integration test (`python test_integration.py`)
- Import tests

### **Before Committing:**
- All unit tests
- Integration test
- No errors in output

### **Before Handoff to Person 3:**
- Full test suite
- Documentation review
- Output format validation

### **During Testing Phase:**
- Real memory dumps (with Person 4)
- Edge case tests
- Performance benchmarks

---

## Getting Help

**If tests fail:**

1. **Check this guide first** - Common scenarios above
2. **Run diagnostic commands** - See "Quick Test Commands"
3. **Ask Person 1** - Integration issues
4. **Ask Person 3** - Output format issues
5. **Ask Person 4** - Test data issues

**Documentation references:**
- `DETECTED_APIS.md` - What you detect and why
- `PERSON2_COMPLETION_REPORT.md` - What you've built
- `utils/README.md` - How to use your code
- `test_integration.py` - Working example

---

## Summary: Your Testing Workflow

```
┌─────────────────────────────────────┐
│  1. Write code                      │
│  2. Run unit tests (solo)           │ ← Do this daily
│  3. Run integration test            │
│  4. Commit if passing               │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│  5. Test with Person 1 (integration)│ ← Do before handoff
│  6. Fix any issues                  │
│  7. Update documentation            │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│  8. Hand off to Person 3            │ ← One-time handoff
│  9. Answer their questions          │
│ 10. Make changes if needed          │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│ 11. Test with Person 4 (validation) │ ← Testing phase
│ 12. Fix bugs they find              │
│ 13. Validate improvements           │
└─────────────────────────────────────┘
```

---

**Quick Answer:** You work MOST with **Person 1** (daily integration) and **Person 3** (handoff + feedback). Person 4 validates your work, Person 5 documents it.

**Current Status:** Ready for Person 3 to start work!

---

**Document Version:** 1.0
**Last Updated:** 2025-11-16
**Status:** Complete
