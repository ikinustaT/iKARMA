# iKARMA: IOCTL Kernel Artifact Risk Mapping & Analysis

A forensic tool for analyzing memory dumps to infer kernel driver capabilities and detect BYOVD (Bring Your Own Vulnerable Driver) attacks.

## Project Overview

iKARMA performs IOCTL Capability Fingerprinting to identify potentially dangerous kernel driver behaviors from volatile memory artifacts, without relying on signatures or complete driver binaries.

### Core Capabilities
- **IOCTL Handler Analysis**: Extract and disassemble driver dispatch handlers from memory
- **Capability Inference**: Detect dangerous patterns (arbitrary R/W, physical memory access, process manipulation)
- **Anti-Forensic Detection**: Identify DKOM manipulation and memory tampering
- **Confidence Scoring**: Provide explainable risk assessments with "because" tags

## Development Phases

### Phase 1: Foundation (Weeks 1-3) - CURRENT
- [ ] Set up Volatility3 development environment
- [ ] Create base plugin architecture
- [ ] Implement DRIVER_OBJECT parsing extensions
- [ ] Integrate Capstone disassembly engine
- [ ] Build baseline memory processing pipeline

### Phase 2: Capability Analysis (Weeks 4-6)
- [ ] Pattern matching engine for dangerous APIs
- [ ] Opcode analysis algorithms
- [ ] Weighted scoring system
- [ ] Confidence framework
- [ ] Iterative testing with known samples

### Phase 3: Anti-Forensic Detection (Weeks 7-8)
- [ ] Memory carving algorithms for PE reconstruction
- [ ] Cross-view validation logic
- [ ] DKOM detection implementation
- [ ] Risk scoring integration

### Phase 4: Integration & Testing (Week 9)
- [ ] Full pipeline integration
- [ ] Explainable output generation
- [ ] Comprehensive testing with 10 sample dumps
- [ ] Performance optimization

## Quick Start

### Prerequisites
```bash
# Python 3.8+
python3 --version

# Install Volatility3
pip install volatility3

# Install Capstone disassembly engine
pip install capstone

# Additional dependencies
pip install pefile yara-python
```

### Project Structure
```
ikarma/
├── plugins/              # Volatility3 custom plugins
│   ├── driver_analysis.py
│   ├── ioctl_extractor.py
│   └── capability_scorer.py
├── core/                 # Core analysis engines
│   ├── disassembler.py
│   ├── pattern_matcher.py
│   └── confidence.py
├── detection/           # Anti-forensic detection
│   ├── dkom_detector.py
│   └── memory_carver.py
├── tests/               # Test suite
│   └── test_data/      # Sample memory dumps
└── utils/              # Helper utilities
```

## Development Environment Setup

1. Clone Volatility3 repository for plugin development
2. Set up Python virtual environment
3. Install all dependencies
4. Configure test memory dumps directory
5. Set up IDE with debugging support

## Testing Strategy

### Test Samples (10 memory dumps)
- 4 Known BYOVD samples (TfSysMon.sys, iqvw64.sys, HWiNFO64.sys, etc.)
- 3 Clean baseline systems
- 2 Drivers with known IOCTL abuse (with public PoCs)
- 1 Simulated DKOM scenario

### Metrics
- Capability detection precision
- DKOM detection accuracy (TPR/FPR)
- Triage effectiveness (time reduction vs manual analysis)
- Cross-validation accuracy

## Contributing
This is an academic project for ICT3215 Digital Forensics module.

## License
Academic project - TBD

## References
See project proposal document for full literature review and citations.
