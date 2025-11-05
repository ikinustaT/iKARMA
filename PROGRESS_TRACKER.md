# iKARMA Development Progress Tracker

Team Members: _________________________

## Phase 1: Foundation (Weeks 1-3)

### Week 1: Environment Setup
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Install Python & dependencies | | ⬜ Not Started | |
| Clone & install Volatility3 | | ⬜ Not Started | |
| Create test VM | | ⬜ Not Started | |
| Generate test memory dump | | ⬜ Not Started | |
| Download Windows symbols | | ⬜ Not Started | |
| Test baseline Volatility3 | | ⬜ Not Started | |
| Study existing plugins | | ⬜ Not Started | |
| Team kickoff meeting | | ⬜ Not Started | Date: ______ |

**Blockers/Issues:**
- 
- 

**Week 1 Retrospective:**
What went well:
- 

What to improve:
- 

---

### Week 2: DRIVER_OBJECT Analysis
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Implement _find_driver_object() | | ⬜ Not Started | |
| Parse MajorFunction table | | ⬜ Not Started | |
| Extract IOCTL handler addresses | | ⬜ Not Started | |
| Build memory reading utilities | | ⬜ Not Started | |
| Error handling for paged memory | | ⬜ Not Started | |
| Test with clean memory dump | | ⬜ Not Started | |
| Document findings | | ⬜ Not Started | |
| Team check-in | | ⬜ Not Started | Date: ______ |

**Test Results:**
- Memory dump used: _______________
- Drivers enumerated: _____
- IOCTL handlers found: _____
- Success rate: _____%

**Blockers/Issues:**
- 
- 

**Week 2 Retrospective:**
What went well:
- 

What to improve:
- 

---

### Week 3: Disassembly Integration
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Integrate Capstone engine | | ⬜ Not Started | |
| Extract handler code bytes | | ⬜ Not Started | |
| Implement disassembly pipeline | | ⬜ Not Started | |
| Format output for analysis | | ⬜ Not Started | |
| Handle disassembly errors | | ⬜ Not Started | |
| Test with 3 different drivers | | ⬜ Not Started | |
| Phase 1 integration testing | | ⬜ Not Started | |
| Phase 1 demo preparation | | ⬜ Not Started | |

**Disassembly Quality:**
- Driver 1: _____ instructions disassembled
- Driver 2: _____ instructions disassembled  
- Driver 3: _____ instructions disassembled
- Accuracy (vs IDA): _____%

**Phase 1 Demo:**
- Date: ______________
- Status: ⬜ Success ⬜ Needs Work
- Feedback:
  - 
  - 

**Blockers/Issues:**
- 
- 

**Week 3 Retrospective:**
What went well:
- 

What to improve:
- 

---

## Phase 2: Capability Analysis (Weeks 4-6)

### Week 4: Pattern Matching Foundation
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Build pattern matcher module | | ⬜ Not Started | |
| Detect 5 core dangerous APIs | | ⬜ Not Started | |
| Implement basic scoring | | ⬜ Not Started | |
| Start confidence framework | | ⬜ Not Started | |
| Test with known BYOVD sample | | ⬜ Not Started | |
| Document API signatures | | ⬜ Not Started | |
| Team check-in | | ⬜ Not Started | Date: ______ |

**API Detection Results:**
- MmMapIoSpace: ⬜ Detected ⬜ Not Detected
- ZwOpenSection: ⬜ Detected ⬜ Not Detected
- ZwTerminateProcess: ⬜ Detected ⬜ Not Detected
- PsLookupProcessByProcessId: ⬜ Detected ⬜ Not Detected
- MSR read/write: ⬜ Detected ⬜ Not Detected

**Blockers/Issues:**
- 
- 

---

### Week 5: Advanced Pattern Recognition
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Expand to 15+ APIs | | ⬜ Not Started | |
| Implement opcode patterns | | ⬜ Not Started | |
| Call chain detection | | ⬜ Not Started | |
| Context awareness | | ⬜ Not Started | |
| Test with 4 BYOVD samples | | ⬜ Not Started | |
| Measure precision/recall | | ⬜ Not Started | |
| Team check-in | | ⬜ Not Started | Date: ______ |

**Testing Metrics:**
- True Positives: _____
- False Positives: _____
- Precision: _____%
- Recall: _____%

**Blockers/Issues:**
- 
- 

---

### Week 6: Confidence & Explainability
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Complete confidence framework | | ⬜ Not Started | |
| Implement "because" tags | | ⬜ Not Started | |
| Weighted scoring system | | ⬜ Not Started | |
| Finalize output format | | ⬜ Not Started | |
| Test with IOCTL abuse PoCs | | ⬜ Not Started | |
| Phase 2 integration testing | | ⬜ Not Started | |
| Mid-project demo | | ⬜ Not Started | Date: ______ |

**Phase 2 Demo:**
- Status: ⬜ Success ⬜ Needs Work
- Feedback:
  - 
  - 

**Blockers/Issues:**
- 
- 

---

## Phase 3: Anti-Forensic Detection (Weeks 7-8)

### Week 7: Memory Carving & Cross-Validation
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Implement PE carving | | ⬜ Not Started | |
| Build cross-validation logic | | ⬜ Not Started | |
| Detect discrepancies | | ⬜ Not Started | |
| Basic DKOM detection | | ⬜ Not Started | |
| Create simulated DKOM test | | ⬜ Not Started | |
| Team check-in | | ⬜ Not Started | Date: ______ |

**DKOM Test Results:**
- Hidden drivers detected: _____ / _____
- False positives: _____
- Detection accuracy: _____%

**Blockers/Issues:**
- 
- 

---

### Week 8: Advanced DKOM & Integration
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Enhanced DKOM techniques | | ⬜ Not Started | |
| Anti-forensic risk scoring | | ⬜ Not Started | |
| Integrate into main pipeline | | ⬜ Not Started | |
| Phase 3 testing | | ⬜ Not Started | |
| Documentation | | ⬜ Not Started | |
| Team check-in | | ⬜ Not Started | Date: ______ |

**Blockers/Issues:**
- 
- 

---

## Phase 4: Integration & Testing (Week 9)

### Week 9: Final Integration
| Task | Assigned To | Status | Notes |
|------|-------------|--------|-------|
| Full pipeline integration | | ⬜ Not Started | |
| Run all 10 test dumps | | ⬜ Not Started | |
| Calculate final metrics | | ⬜ Not Started | |
| Write user guide | | ⬜ Not Started | |
| Technical documentation | | ⬜ Not Started | |
| Prepare presentation | | ⬜ Not Started | |
| Practice demo | | ⬜ Not Started | |
| Final submission | | ⬜ Not Started | Date: ______ |

---

## Final Test Results

| Dump | Type | Expected | Actual | Pass/Fail |
|------|------|----------|--------|-----------|
| 1 | TfSysMon.sys | HIGH risk | | ⬜ |
| 2 | iqvw64.sys | CRITICAL risk | | ⬜ |
| 3 | HWiNFO64.sys | HIGH risk | | ⬜ |
| 4 | Unknown BYOVD | Capabilities inferred | | ⬜ |
| 5 | Clean baseline | LOW risk, no FP | | ⬜ |
| 6 | Clean baseline | LOW risk, no FP | | ⬜ |
| 7 | Clean baseline | LOW risk, no FP | | ⬜ |
| 8 | IOCTL abuse | Correct classification | | ⬜ |
| 9 | IOCTL abuse | Correct classification | | ⬜ |
| 10 | DKOM scenario | Hidden driver found | | ⬜ |

**Overall Metrics:**
- Capability Detection Precision: _____%
- Capability Detection Recall: _____%
- DKOM True Positive Rate: _____%
- DKOM False Positive Rate: _____%
- Average analysis time: _____ seconds
- Analyst time saved vs manual: _____%

---

## Project Completion Checklist

- [ ] All phases complete
- [ ] All tests passed
- [ ] Documentation complete
- [ ] Code commented and clean
- [ ] Demo successful
- [ ] Presentation ready
- [ ] Project submitted

---

## Lessons Learned

**Technical Learnings:**
- 
- 
- 

**Team Collaboration:**
- 
- 
- 

**What Went Well:**
- 
- 
- 

**What Could Be Improved:**
- 
- 
- 

**Recommendations for Future Work:**
- 
- 
- 

---

**Status Key:**
- ⬜ Not Started
- 🟡 In Progress  
- ✅ Complete
- ⚠️ Blocked

**Last Updated:** _______________
