# iKARMA TEAM PROGRESS TRACKER

**Week 1: Nov 15-21 (BUILD PHASE)**  
**Week 2: Nov 22-28 (POLISH PHASE)**

---

## 📅 WEEK 1 CHECKLIST

### Day 1-2 (Nov 15-16): Foundation Sprint

#### Person 1: Team Lead ✅
- [ ] Refactor `driver_analysis.py` → `byovd_scanner.py`
- [ ] Add command-line options (--high-risk-only, --export-json, --detailed)
- [ ] Wire up API scanner calls (even with mock data)
- [ ] Wire up risk scorer calls
- [ ] Add progress indicators
- [ ] Better output formatting
- [ ] **CODE COMMITTED:** ___________

#### Person 2: API Hunter ✅
- [ ] Study `DANGEROUS_APIS.md`
- [ ] Create `core/api_patterns.py` with 10 APIs
- [ ] Implement string matching in `utils/api_scanner.py`
- [ ] Implement call instruction analysis
- [ ] Implement string reference detection
- [ ] Test with sample disassembly
- [ ] **CODE COMMITTED:** ___________

#### Person 3: Risk Analyst ✅
- [ ] Design risk scoring algorithm
- [ ] Implement `calculate_risk()` in `core/risk_scorer.py`
- [ ] Start `core/confidence.py` framework
- [ ] Implement 3 confidence factors
- [ ] Test with mock data
- [ ] Generate "because" tags
- [ ] **CODE COMMITTED:** ___________

#### Person 4: Testing ✅
- [ ] Acquire Clean Windows 10 dump
- [ ] Acquire Clean Windows 11 dump
- [ ] Acquire dump with vulnerable driver
- [ ] Acquire dump with hardware driver
- [ ] Start DKOM scenario VM setup
- [ ] Document all dumps in `tests/TEST_INVENTORY.md`
- [ ] **DUMPS DOCUMENTED:** ___________

#### Person 5: Documentation ✅
- [ ] Create report structure (9 sections)
- [ ] Create presentation structure (20 slides)
- [ ] Write Introduction (2 pages)
- [ ] Start Literature Review
- [ ] Find 5+ academic papers to cite
- [ ] Create Related Work comparison table
- [ ] **PAGES WRITTEN:** ___________

---

### Day 3-4 (Nov 17-18): Integration Sprint

#### Person 1: Team Lead ✅
- [ ] Integrate Person 2's API scanner
- [ ] Integrate Person 3's risk scorer
- [ ] Debug interface issues
- [ ] Test with Person 4's memory dumps
- [ ] Add JSON export functionality
- [ ] Fix integration bugs
- [ ] **INTEGRATION WORKING:** YES / NO

#### Person 2: API Hunter ✅
- [ ] Expand API database to 20+ APIs
- [ ] Add opcode pattern detection (3 patterns)
- [ ] Test against real memory dumps
- [ ] Fix false positive issues
- [ ] Add API combination detection
- [ ] Document detection methods
- [ ] **APIS DETECTED:** _____ / 20

#### Person 3: Risk Analyst ✅
- [ ] Complete confidence framework
- [ ] Add "because" tag generation
- [ ] Test risk scorer with various combinations
- [ ] Start designing `byovd_validator.py`
- [ ] Plan cross-view validation approach
- [ ] Document scoring thresholds
- [ ] **SCORING WORKING:** YES / NO

#### Person 4: Testing ✅
- [ ] Acquire remaining 5 test dumps
- [ ] Run scanner against all current dumps
- [ ] Document results in `tests/TEST_RESULTS.md`
- [ ] Report bugs to team
- [ ] Calculate initial metrics
- [ ] Start DKOM PoC research
- [ ] **TOTAL DUMPS:** _____ / 10

#### Person 5: Documentation ✅
- [ ] Complete Methodology section (4 pages)
- [ ] Create architecture diagrams (3 diagrams)
- [ ] Create data flow diagram
- [ ] Draft presentation slides with mock-ups
- [ ] Write Implementation section draft
- [ ] Interview technical team for details
- [ ] **REPORT COMPLETION:** _____% 

---

### Day 5-7 (Nov 19-21): Advanced Features Sprint

#### Person 1: Team Lead ✅
- [ ] Create `byovd_capability.py` plugin
- [ ] Implement deep-dive analysis (500+ instructions)
- [ ] Add call chain detection
- [ ] Add detailed logging mode (--verbose)
- [ ] Test capability plugin
- [ ] Polish scanner output
- [ ] **PLUGINS WORKING:** _____ / 2

#### Person 2: API Hunter ✅
- [ ] Add import table analysis
- [ ] Implement dangerous API combinations
- [ ] Add multiplier logic for combinations
- [ ] Document all detection methods
- [ ] Create `DETECTED_APIS.md`
- [ ] Help with testing
- [ ] **API DOCUMENTATION:** DONE / IN PROGRESS

#### Person 3: Risk Analyst ✅
- [ ] Create `byovd_validator.py` plugin
- [ ] Implement cross-view validation (3 views)
- [ ] Implement DKOM detection (3 techniques)
- [ ] Test validator with Person 4's DKOM dump
- [ ] Refine risk scoring based on tests
- [ ] Polish "because" tags
- [ ] **VALIDATOR WORKING:** YES / NO

#### Person 4: Testing ✅
- [ ] Create DKOM proof-of-concept
- [ ] Create memory dump with hidden driver
- [ ] Verify validator detects DKOM
- [ ] Run comprehensive test suite (30 tests)
- [ ] Create test matrix spreadsheet
- [ ] Document DKOM in `tests/DKOM_POC.md`
- [ ] **DKOM POC:** DONE / DOCUMENTED

#### Person 5: Documentation ✅
- [ ] Write complete Implementation section
- [ ] Write Related Work section
- [ ] Draft Results section (with placeholders)
- [ ] Create result tables (mock-ups)
- [ ] Create presentation diagrams
- [ ] Start video demo storyboard
- [ ] **REPORT COMPLETION:** _____% 

---

## 📅 WEEK 2 CHECKLIST

### Day 8-9 (Nov 22-23): Testing & Bug Fixing

#### Person 1: Team Lead ✅
- [ ] Fix all reported bugs
- [ ] Optimize performance
- [ ] Add error handling
- [ ] Polish output formatting
- [ ] Add color coding
- [ ] Final code cleanup
- [ ] **BUGS FIXED:** _____ / _____

#### Person 2: API Hunter ✅
- [ ] Help with comprehensive testing
- [ ] Fine-tune detection thresholds
- [ ] Reduce false positives
- [ ] Complete API documentation
- [ ] Final code review
- [ ] Prepare for technical Q&A
- [ ] **FALSE POSITIVE RATE:** _____%

#### Person 3: Risk Analyst ✅
- [ ] Refine scoring based on test results
- [ ] Adjust risk level thresholds
- [ ] Polish validator output
- [ ] Ensure "because" tags are clear
- [ ] Test all 3 confidence factors
- [ ] Final code review
- [ ] **SCORING ACCURACY:** _____%

#### Person 4: Testing ✅
- [ ] Run final test suite (all 10 dumps)
- [ ] Calculate detection rate
- [ ] Calculate false positive rate
- [ ] Calculate precision and recall
- [ ] Create time comparison (manual vs iKARMA)
- [ ] Write final test report
- [ ] **ALL METRICS CALCULATED:** YES / NO

#### Person 5: Documentation ✅
- [ ] Populate Results with real data
- [ ] Create graphs/charts
- [ ] Write Discussion section
- [ ] Write Conclusion section
- [ ] Complete all references
- [ ] Proofread entire report
- [ ] **REPORT COMPLETION:** _____% 

---

### Day 10-11 (Nov 24-25): Demo Preparation

#### Person 1: Team Lead ✅
- [ ] Choose best demo scenario
- [ ] Create demo script
- [ ] Practice demo 3+ times
- [ ] Time demo (should be 3-4 min)
- [ ] Prepare backup scenarios
- [ ] Review all documentation
- [ ] **DEMO REHEARSED:** _____ times

#### Person 2: API Hunter ✅
- [ ] Review all API documentation
- [ ] Prepare for technical questions
- [ ] Create technical deep-dive slides
- [ ] Help with demo preparation
- [ ] Final code check
- [ ] **READY FOR Q&A:** YES / NO

#### Person 3: Risk Analyst ✅
- [ ] Review scoring documentation
- [ ] Prepare for technical questions
- [ ] Create algorithm explanation slides
- [ ] Help with demo preparation
- [ ] Final code check
- [ ] **READY FOR Q&A:** YES / NO

#### Person 4: Testing ✅
- [ ] Prepare test results slides
- [ ] Create comparison charts
- [ ] Prepare metrics presentation
- [ ] Set up backup test scenarios
- [ ] Verify all test data accuracy
- [ ] **RESULTS SLIDES:** DONE / IN PROGRESS

#### Person 5: Documentation ✅
- [ ] Finalize report (100%)
- [ ] Finalize presentation slides
- [ ] Start recording demo video
- [ ] Record introduction segment
- [ ] Record live demo segment
- [ ] Record results segment
- [ ] **VIDEO RECORDING:** _____% complete

---

### Day 12-13 (Nov 26-27): Final Polish

#### ALL TEAM ✅
- [ ] Full team review of report
- [ ] Full team rehearsal of presentation
- [ ] Finish demo video recording
- [ ] Edit demo video
- [ ] Create poster (if required)
- [ ] Prepare submission package
- [ ] Test all submission files
- [ ] **TEAM REVIEW:** DONE / IN PROGRESS

#### Submission Package Checklist ✅
- [ ] `iKARMA_Final_Report.pdf` (20-25 pages)
- [ ] `iKARMA_Presentation.pdf`
- [ ] `iKARMA_Presentation.pptx` (editable)
- [ ] `iKARMA_Demo_Video.mp4` (5-7 minutes)
- [ ] `iKARMA_Poster.pdf` (if required)
- [ ] `iKARMA_Source_Code.zip`
  - [ ] All plugin files
  - [ ] All core modules
  - [ ] All utility modules
  - [ ] Test documentation
  - [ ] README.md
- [ ] All files tested and verified

---

### Day 14 (Nov 28): Buffer Day

#### Emergency Tasks Only ✅
- [ ] Critical bug fixes
- [ ] Submission format corrections
- [ ] Final file verification
- [ ] Upload submission
- [ ] **DO NOT ADD NEW FEATURES**

---

## 🎯 CRITICAL SUCCESS METRICS

### Minimum Requirements (MUST HAVE):
- [ ] **3 working plugins** (scanner, capability, validator)
- [ ] **20+ API detections** with 3 methods
- [ ] **Risk scoring algorithm** with confidence
- [ ] **Basic DKOM detection** (cross-view)
- [ ] **10 test cases** with results
- [ ] **Complete report** (20+ pages)
- [ ] **Presentation** (15-20 slides)
- [ ] **Demo video** (5-7 minutes)

### Quality Metrics:
- [ ] **Detection rate:** >90%
- [ ] **False positive rate:** <10%
- [ ] **Performance:** <2 min for 100 drivers
- [ ] **Code quality:** Clean, documented, working
- [ ] **Documentation:** Professional, complete, clear

---

## 📊 DAILY PROGRESS LOG

Copy this section each day:

```
DATE: _____________

PERSON 1:
Tasks completed today: _______________________________
Blockers: ___________________________________________
Tomorrow's priority: _________________________________

PERSON 2:
Tasks completed today: _______________________________
Blockers: ___________________________________________
Tomorrow's priority: _________________________________

PERSON 3:
Tasks completed today: _______________________________
Blockers: ___________________________________________
Tomorrow's priority: _________________________________

PERSON 4:
Tasks completed today: _______________________________
Blockers: ___________________________________________
Tomorrow's priority: _________________________________

PERSON 5:
Tasks completed today: _______________________________
Blockers: ___________________________________________
Tomorrow's priority: _________________________________

TEAM HEALTH: 😃 Good / 😐 Okay / 😟 Behind / 🚨 Critical
```

---

## 🚨 RISK INDICATORS

### 🚨 CRITICAL (Stop and ask for help):
- [ ] Behind by more than 2 days
- [ ] Major blocker for >4 hours
- [ ] Fundamental design flaw discovered
- [ ] Team member unavailable for >2 days

### ⚠️ WARNING (Adjust plan):
- [ ] Behind by 1 day
- [ ] Minor blockers accumulating
- [ ] False positive rate >20%
- [ ] Performance issues

### ✅ ON TRACK:
- [ ] Meeting daily milestones
- [ ] Code committed daily
- [ ] Daily standups happening
- [ ] Bugs getting fixed

---

## 💪 MOTIVATION TRACKER

Week 1 Progress: ████░░░░░░ _____% 
Week 2 Progress: ░░░░░░░░░░ _____% 
Overall Progress: ████░░░░░░ _____% 

**Days remaining:** _____  
**Days on track:** _____  
**Days behind:** _____  

**Team morale:** 😃 😃 😃 😃 😃

---

## 🎓 FINAL SUBMISSION CHECKLIST

### Pre-Submission (Nov 28, 6pm):
- [ ] All files compiled
- [ ] All files tested
- [ ] All files renamed correctly
- [ ] Submission package created
- [ ] Backup copies saved

### Submission Day (Nov 29):
- [ ] Upload to submission portal
- [ ] Verify upload successful
- [ ] Download and verify submitted files
- [ ] Confirmation email received
- [ ] Celebrate! 🎉

---

*Print this document and check off items as you complete them.*  
*Update the progress log daily during standup.*  
*Review weekly to ensure you're on track.*

**LAST UPDATED:** November 15, 2025
