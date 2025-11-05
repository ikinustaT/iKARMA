# iKARMA Project Roadmap

## Overview
9-week development cycle aligned with academic semester timeline
Target: Functional forensic tool for BYOVD detection from memory dumps

---

## Phase 1: Foundation Development (Weeks 1-3)

### Week 1: Environment Setup & Architecture
**Goal**: Development environment ready, team aligned on architecture

**Milestones:**
- [ ] All team members have Volatility3 installed and working
- [ ] Can successfully analyze test memory dump with base plugins
- [ ] Project structure created and version controlled
- [ ] Initial plugin template functional

**Deliverables:**
- Working development environment (each team member)
- Initial Git repository with project structure
- Documentation: SETUP.md completed
- First team meeting: assign responsibilities

**Critical Path:**
- Day 1-2: Individual environment setup
- Day 3-4: Create base plugin structure
- Day 5-7: Team sync, test environment, plan Week 2

---

### Week 2: DRIVER_OBJECT Analysis Engine
**Goal**: Extract IOCTL handlers from memory dumps

**Milestones:**
- [ ] DRIVER_OBJECT enumeration working
- [ ] MajorFunction table parsing implemented
- [ ] IOCTL handler addresses extracted
- [ ] Memory reading with error handling

**Deliverables:**
- Enhanced driver_analysis.py plugin
- Can list all drivers with IOCTL handlers
- Test results from 1 clean memory dump
- Documentation of findings/challenges

**Technical Tasks:**
1. Implement `_find_driver_object()` method
   - Research DRIVER_OBJECT structure location
   - Parse PsLoadedModuleList or alternative enumeration
   - Handle kernel versions (Win 7/8/10/11)

2. Extract MajorFunction[] array
   - Parse all 28 function pointers
   - Validate pointer sanity checks
   - Focus on index 0x0E (IRP_MJ_DEVICE_CONTROL)

3. Memory utilities
   - Robust read functions
   - Handle paged-out memory
   - Log failures appropriately

**Testing:**
- Verify against known drivers (null.sys, beep.sys)
- Cross-check with IoctlHunter results
- Ensure no crashes on corrupted memory

---

### Week 3: Disassembly Integration
**Goal**: Disassemble IOCTL handler code from memory

**Milestones:**
- [ ] Capstone fully integrated
- [ ] Extract 64-128 bytes from handlers
- [ ] Disassemble to readable instructions
- [ ] Store results in structured format

**Deliverables:**
- Complete disassembly pipeline
- Output shows instruction listings
- Phase 1 demo ready
- Prepare for Phase 2 capability detection

**Technical Tasks:**
1. Capstone wrapper
   - Configure for x64 Windows
   - Enable detailed instruction info
   - Handle disassembly errors

2. Code extraction
   - Read handler code from memory
   - Handle partial/corrupted code
   - Determine optimal byte count (64-128)

3. Output formatting
   - Human-readable disassembly
   - Structured for later analysis
   - Export to JSON for Phase 2

**Testing:**
- Compare disassembly against IDA Pro
- Verify instruction accuracy
- Test with 3 different drivers

---

## Phase 2: Capability Analysis Engine (Weeks 4-6)

### Week 4: Pattern Matching Foundation
**Goal**: Detect dangerous API calls in disassembled code

**Milestones:**
- [ ] Pattern matching engine built
- [ ] Detect 5 core dangerous APIs
- [ ] Basic scoring algorithm
- [ ] Confidence framework started

**Deliverables:**
- Pattern matcher module (core/pattern_matcher.py)
- API signature database
- Basic capability scoring
- Test results on known BYOVD samples

**Technical Tasks:**
1. API signature detection
   - String matching for API names
   - Import table analysis
   - Indirect call detection

2. Core patterns (start with 5):
   - MmMapIoSpace (arbitrary memory)
   - ZwOpenSection ("PhysicalMemory")
   - ZwTerminateProcess
   - PsLookupProcessByProcessId + EPROCESS manipulation
   - MSR read/write (rdmsr/wrmsr)

3. Scoring algorithm v1
   - Base risk scores per API
   - Additive scoring model
   - Thresholds (Low/Medium/High/Critical)

**Testing:**
- Test with TfSysMon.sys (known BYOVD)
- Validate pattern matches
- Check false positive rate on benign drivers

---

### Week 5: Advanced Pattern Recognition
**Goal**: Expand detection, add opcode analysis

**Milestones:**
- [ ] 15+ dangerous APIs detected
- [ ] Opcode pattern matching
- [ ] Call chain detection
- [ ] Context awareness

**Deliverables:**
- Expanded pattern database
- Opcode analysis engine
- Call chain tracker
- Improved accuracy metrics

**Technical Tasks:**
1. Expand API coverage
   - Add all APIs from DANGEROUS_APIS.md
   - Create API categories
   - Weight by danger level

2. Opcode patterns
   - Recognize common instruction sequences
   - Detect IOCTL parameter parsing
   - Identify validation (or lack thereof)

3. Call chains
   - Track multi-step attacks
   - Example: Open → Map → Write sequence
   - Increase score for chained capabilities

**Testing:**
- Test against 4 known BYOVD samples
- Compare results with POPKORN methodology
- Measure precision/recall

---

### Week 6: Confidence & Explainability
**Goal**: Confidence scoring and "because" tags

**Milestones:**
- [ ] Confidence framework complete
- [ ] "Because" tag generation
- [ ] Weighted scoring system
- [ ] Output format finalized

**Deliverables:**
- Confidence scoring module
- Explainable output format
- Phase 2 complete and tested
- Mid-project demo

**Technical Tasks:**
1. Confidence system
   - Factors: API clarity, string refs, indirect calls
   - Scale: 0.0-1.0
   - Combine with risk scores

2. "Because" tags
   - Natural language explanations
   - Cite specific evidence (addresses, instructions)
   - Forensically useful format

3. Weighted scoring
   - Risk × Confidence = Final Score
   - Normalization across drivers
   - Ranking algorithm

**Testing:**
- Evaluate explainability with forensic analyst feedback
- Verify confidence correlates with accuracy
- Test with 2 IOCTL abuse PoCs

---

## Phase 3: Anti-Forensic Detection (Weeks 7-8)

### Week 7: Memory Carving & PE Reconstruction
**Goal**: Independent driver discovery via memory carving

**Milestones:**
- [ ] PE header carving working
- [ ] Independent driver list created
- [ ] Cross-view validation logic
- [ ] Discrepancy detection

**Deliverables:**
- Memory carver module (detection/memory_carver.py)
- PE reconstruction algorithm
- Cross-validation report
- DKOM detection v1

**Technical Tasks:**
1. Memory carving
   - Scan for PE magic bytes (MZ, PE)
   - Extract PE headers
   - Reconstruct basic file info

2. Driver list comparison
   - Volatility3's PsLoadedModuleList (official)
   - Carved drivers (independent)
   - Identify discrepancies

3. DKOM detection
   - Drivers carved but not in list (hidden)
   - Size mismatches
   - Header tampering

**Testing:**
- Create simulated DKOM scenario
- Unlink driver from PsLoadedModuleList
- Verify iKARMA detects it

---

### Week 8: DKOM Analysis & Risk Integration
**Goal**: Comprehensive anti-forensic detection

**Milestones:**
- [ ] Multiple DKOM techniques detected
- [ ] Anti-forensic risk scoring
- [ ] Integrated into main pipeline
- [ ] Phase 3 complete

**Deliverables:**
- Complete DKOM detector
- Anti-forensic scoring integrated
- Detection report format
- Phase 3 testing complete

**Technical Tasks:**
1. Enhanced DKOM detection
   - Process hiding (EPROCESS unlink)
   - Driver hiding (KLDR_DATA_TABLE_ENTRY)
   - Memory scrubbing indicators
   - Timestamp manipulation

2. Risk integration
   - Combine capability + DKOM scores
   - Aggravating factors (hidden + dangerous)
   - Prioritize for analyst review

3. Reporting
   - Separate anti-forensic findings
   - Visual indicators for tampered drivers
   - Confidence in DKOM detection

**Testing:**
- Test all DKOM detection methods
- False positive rate on benign systems
- Validate against research papers (Palutke et al.)

---

## Phase 4: Integration & Testing (Week 9)

### Week 9: Final Integration & Evaluation
**Goal**: Complete, tested, demo-ready tool

**Milestones:**
- [ ] All components integrated
- [ ] Comprehensive testing complete
- [ ] Documentation finalized
- [ ] Demo prepared

**Deliverables:**
- Final iKARMA tool (v1.0)
- Complete test results
- User guide
- Project presentation

**Technical Tasks:**
1. Pipeline integration
   - Ensure all modules work together
   - Optimize performance
   - Error handling throughout

2. Comprehensive testing
   - Run all 10 test memory dumps
   - Document results in spreadsheet
   - Calculate metrics (precision, recall, TPR, FPR)

3. Documentation
   - User guide for forensic analysts
   - Technical documentation
   - Known limitations

4. Demo preparation
   - Create compelling demo scenario
   - Prepare slides
   - Practice presentation

**Testing Evaluation:**

| Test Case | Type | Expected Result |
|-----------|------|----------------|
| Dump 1 | TfSysMon.sys | HIGH risk, arbitrary memory access detected |
| Dump 2 | iqvw64.sys | CRITICAL risk, physical memory access |
| Dump 3 | HWiNFO64.sys | HIGH risk, MSR manipulation |
| Dump 4 | Unknown BYOVD | Capabilities inferred correctly |
| Dump 5-7 | Clean baselines | LOW risk, false positive check |
| Dump 8-9 | IOCTL abuse | Correct capability classification |
| Dump 10 | DKOM scenario | Hidden driver detected |

**Metrics to Collect:**
- True Positive Rate (capability detection)
- False Positive Rate (benign drivers flagged)
- DKOM detection accuracy
- Time per analysis (performance)
- Analyst time saved vs manual analysis

---

## Risk Management

### Technical Risks
1. **Memory dumps unavailable**: Create own using VMs
2. **Volatility3 API changes**: Pin to specific version
3. **Pattern matching accuracy**: Iterative refinement with testing
4. **Performance issues**: Optimize hot paths, profile code

### Schedule Risks
1. **Behind schedule**: Prioritize core features, defer enhancements
2. **Team member unavailable**: Cross-training, documentation
3. **Scope creep**: Strict adherence to defined phases

### Mitigation Strategies
- Weekly team meetings
- Daily stand-ups if falling behind
- Early and frequent testing
- Maintain "MVP" vs "nice-to-have" lists

---

## Success Criteria

**Minimum Viable Product (MVP):**
- ✓ Analyze memory dump
- ✓ Extract IOCTL handlers
- ✓ Detect 10+ dangerous APIs
- ✓ Provide risk scoring
- ✓ Detect basic DKOM

**Stretch Goals:**
- Advanced call chain analysis
- YARA rule integration
- Automated report generation
- Web UI for analysis

**Academic Success:**
- Working demonstration
- Test results documented
- Research-backed methodology
- Contribution to forensics field

---

## Post-Project (Optional)

If time and interest permit:
- Open source release on GitHub
- Submit to Volatility3 plugin repository
- Present at security conference
- Publish research paper
- Extend to Linux kernel drivers

---

**Remember**: Perfection is the enemy of progress. Deliver a working Phase 1, then iterate. Good luck! 🎯
