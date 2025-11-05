# iKARMA Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         iKARMA SYSTEM                           │
│                IOCTL Kernel Artifact Risk Mapping & Analysis     │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────┐
                    │   Memory Dump       │
                    │   (.dmp, .raw)      │
                    └─────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                      PHASE 1: FOUNDATION                         │
│                        (Weeks 1-3)                               │
└──────────────────────────────────────────────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌───────────┐      ┌───────────┐     ┌────────────┐
       │Volatility3│      │ DRIVER    │     │  IOCTL     │
       │  Parser   │─────→│ OBJECT    │────→│  Handler   │
       │           │      │ Extractor │     │  Locator   │
       └───────────┘      └───────────┘     └────────────┘
                                                    │
                                                    ▼
                                             ┌────────────┐
                                             │  Capstone  │
                                             │Disassembler│
                                             └────────────┘
                                                    │
                                                    ▼
                                          [Handler Code: ASM]

┌──────────────────────────────────────────────────────────────────┐
│                   PHASE 2: CAPABILITY ANALYSIS                   │
│                        (Weeks 4-6)                               │
└──────────────────────────────────────────────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌───────────┐      ┌───────────┐     ┌────────────┐
       │  Pattern  │      │    API    │     │   Opcode   │
       │  Matcher  │─────→│ Detection │────→│  Analysis  │
       │           │      │           │     │            │
       └───────────┘      └───────────┘     └────────────┘
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 ▼
                          ┌────────────┐
                          │   Scoring  │
                          │   Engine   │
                          └────────────┘
                                 │
                                 ▼
                          ┌────────────┐
                          │ Confidence │
                          │ Calculator │
                          └────────────┘
                                 │
                                 ▼
                    [Risk Score + Because Tags]

┌──────────────────────────────────────────────────────────────────┐
│                PHASE 3: ANTI-FORENSIC DETECTION                  │
│                        (Weeks 7-8)                               │
└──────────────────────────────────────────────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌───────────┐      ┌───────────┐     ┌────────────┐
       │  Memory   │      │    PE     │     │   DKOM     │
       │  Carver   │─────→│Reconstruct│────→│  Detector  │
       │           │      │           │     │            │
       └───────────┘      └───────────┘     └────────────┘
                                 │
                                 ▼
                          ┌────────────┐
                          │Cross-View  │
                          │ Validator  │
                          └────────────┘
                                 │
                                 ▼
                    [Hidden Drivers Detected]

┌──────────────────────────────────────────────────────────────────┐
│                   PHASE 4: FINAL OUTPUT                          │
│                        (Week 9)                                  │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────┐
                    │  Report Generator   │
                    │   - Risk Rankings   │
                    │   - Capabilities    │
                    │   - DKOM Findings   │
                    │   - Evidence        │
                    └─────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────┐
                    │  FINAL REPORT       │
                    │  (for Analyst)      │
                    └─────────────────────┘
```

## Data Flow Detail

### Phase 1: Foundation
```
Memory Dump
    │
    ├─→ Volatility3 Framework
    │       │
    │       └─→ Parse _KLDR_DATA_TABLE_ENTRY (PsLoadedModuleList)
    │               │
    │               └─→ Extract Driver Metadata
    │                       │
    │                       ├─→ Driver Name
    │                       ├─→ Base Address
    │                       ├─→ Size
    │                       └─→ Load Order
    │
    └─→ Driver Analysis Plugin
            │
            ├─→ Find DRIVER_OBJECT Structure
            │       │
            │       └─→ Parse MajorFunction[28]
            │               │
            │               └─→ Extract MajorFunction[0x0E] (IOCTL Handler)
            │
            └─→ Read Handler Code from Memory
                    │
                    └─→ Capstone Disassembly
                            │
                            └─→ Instruction List (ASM)
```

### Phase 2: Capability Analysis
```
Disassembled Instructions
    │
    ├─→ Pattern Matcher
    │       │
    │       ├─→ String Matching (API Names)
    │       │       │
    │       │       └─→ "MmMapIoSpace"
    │       │       └─→ "ZwOpenSection"
    │       │       └─→ "ZwTerminateProcess"
    │       │
    │       └─→ Opcode Pattern Detection
    │               │
    │               └─→ Call + Mov patterns
    │               └─→ IOCTL buffer parsing
    │
    ├─→ Capability Classifier
    │       │
    │       ├─→ Arbitrary Memory R/W
    │       ├─→ Physical Memory Access
    │       ├─→ Process Manipulation
    │       ├─→ Callback Tampering
    │       └─→ MSR Manipulation
    │
    └─→ Risk Scorer
            │
            ├─→ Base Score (by capability)
            ├─→ Modifiers (context, validation)
            └─→ Confidence (0.0-1.0)
                    │
                    └─→ Final Risk: CRITICAL/HIGH/MEDIUM/LOW
```

### Phase 3: Anti-Forensic Detection
```
Memory Dump
    │
    ├─→ Official Driver List (Volatility3)
    │       │
    │       └─→ PsLoadedModuleList Enumeration
    │
    └─→ Independent Memory Carver
            │
            ├─→ Scan for PE Magic Bytes (MZ, PE)
            ├─→ Extract PE Headers
            └─→ Reconstruct Driver List
                    │
                    └─→ Cross-View Validator
                            │
                            ├─→ Compare Lists
                            │       │
                            │       ├─→ In carved, not in official? → HIDDEN
                            │       ├─→ Size mismatch? → TAMPERED
                            │       └─→ Header anomalies? → SUSPICIOUS
                            │
                            └─→ DKOM Detection Report
```

## Module Dependencies

```
ikarma/
│
├── plugins/
│   └── driver_analysis.py ──┬──→ Volatility3 Framework
│                             ├──→ Capstone Engine
│                             ├──→ core.disassembler
│                             └──→ core.pattern_matcher
│
├── core/
│   ├── disassembler.py ─────────→ Capstone
│   ├── pattern_matcher.py ──────→ core.api_signatures
│   ├── confidence.py
│   └── scorer.py ───────────────→ core.pattern_matcher
│
├── detection/
│   ├── memory_carver.py ────────→ pefile
│   └── dkom_detector.py ────────→ detection.memory_carver
│
└── utils/
    └── helpers.py
```

## Execution Flow (Runtime)

```
1. User runs: vol3 -f memory.dmp windows.driver_analysis
        │
        ▼
2. Plugin loads and initializes
        │
        ├─→ Load Volatility3 context
        ├─→ Initialize Capstone
        └─→ Load configuration
        │
        ▼
3. _generator() method executes
        │
        ├─→ Enumerate drivers (Phase 1)
        │       │
        │       └─→ For each driver:
        │               ├─→ Find DRIVER_OBJECT
        │               ├─→ Extract IOCTL handler
        │               └─→ Disassemble code
        │
        ├─→ Analyze capabilities (Phase 2)
        │       │
        │       └─→ For each driver:
        │               ├─→ Pattern matching
        │               ├─→ API detection
        │               └─→ Risk scoring
        │
        └─→ Check for DKOM (Phase 3)
                │
                └─→ Cross-validate with carved drivers
        │
        ▼
4. Format output
        │
        └─→ TreeGrid renderer
                │
                ├─→ Driver Name
                ├─→ IOCTL Handler Address
                ├─→ Detected Capabilities
                ├─→ Risk Score
                └─→ "Because" tags
        │
        ▼
5. Display to user
```

## Key Interfaces

### Phase 1 Interface
```
Input:  Memory dump + Volatility3 context
Output: List of (driver_name, ioctl_handler, disassembly)
```

### Phase 2 Interface
```
Input:  Disassembled instructions
Output: (risk_score, confidence, capabilities[], because_tags[])
```

### Phase 3 Interface
```
Input:  Official driver list + Memory dump
Output: (hidden_drivers[], tampered_drivers[], dkom_confidence)
```

## Testing Architecture

```
Test Suite
    │
    ├─→ Unit Tests
    │       │
    │       ├─→ test_driver_enumeration()
    │       ├─→ test_ioctl_extraction()
    │       ├─→ test_disassembly()
    │       ├─→ test_pattern_matching()
    │       └─→ test_dkom_detection()
    │
    ├─→ Integration Tests
    │       │
    │       ├─→ test_full_pipeline()
    │       ├─→ test_known_byovd_samples()
    │       └─→ test_clean_baselines()
    │
    └─→ Test Data
            │
            ├─→ 4 BYOVD samples
            ├─→ 3 Clean baselines
            ├─→ 2 IOCTL abuse PoCs
            └─→ 1 DKOM scenario
```

## Technology Stack

```
┌──────────────────────────────────────┐
│         Python 3.8+                  │
└──────────────────────────────────────┘
             │
             ├─→ Volatility3 (memory forensics)
             ├─→ Capstone (disassembly)
             ├─→ pefile (PE parsing)
             ├─→ yara-python (pattern matching - optional)
             └─→ pytest (testing)
```

---

This architecture ensures:
- ✅ Modular design (easy to test/extend)
- ✅ Clear separation of concerns
- ✅ Iterative development (phase by phase)
- ✅ Maintainable codebase
- ✅ Forensically sound methodology
