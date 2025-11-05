# Phase 1 Development Guide: Foundation (Weeks 1-3)

## Objectives
- Set up Volatility3 plugin development environment
- Create base plugin architecture for DRIVER_OBJECT analysis
- Integrate Capstone disassembly engine
- Build baseline memory processing pipeline

## Week 1: Environment Setup & Volatility3 Integration

### Tasks

#### 1. Development Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or venv\Scripts\activate on Windows

# Install core dependencies
pip install volatility3
pip install capstone
pip install pefile
pip install yara-python
```

#### 2. Understand Volatility3 Plugin Architecture
- Read: https://volatility3.readthedocs.io/en/latest/
- Study existing plugins in volatility3/framework/plugins/windows/
- Key plugins to examine:
  - `modules.py` - Driver enumeration
  - `driverscan.py` - Driver scanning
  - `callbacks.py` - Callback analysis

#### 3. Create Base Plugin Template
Location: `ikarma/plugins/driver_analysis.py`

Key components:
- Inherit from `volatility3.framework.plugins.PluginInterface`
- Implement `_generator()` method for output
- Use `volatility3.framework.renderers.TreeGrid` for results
- Access memory context and symbol tables

## Week 2: DRIVER_OBJECT Analysis Extension

### Tasks

#### 1. Enhance Driver Enumeration
Build on Volatility3's `PsLoadedModuleList` parsing to extract:
- Driver base address and size
- Driver name and path
- MajorFunction dispatch table (28 function pointers)
- Focus on IRP_MJ_DEVICE_CONTROL (0x0E) for IOCTL handlers

#### 2. MajorFunction[] Resolution
Create algorithm to:
- Parse DRIVER_OBJECT structure from memory
- Extract all 28 MajorFunction pointers
- Validate pointers are within driver memory regions
- Handle NULL or invalid pointers gracefully

#### 3. Memory Reading Utilities
Develop robust memory reading functions:
- Handle page faults and unmapped regions
- Implement retry logic for partial reads
- Log read failures for debugging

## Week 3: IOCTL Handler Extraction & Disassembly

### Tasks

#### 1. Capstone Integration
```python
from capstone import *

# Initialize for x64 Windows
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True  # Enable detailed disassembly

# Disassemble handler code
for instruction in md.disasm(code_bytes, address):
    print(f"0x{instruction.address:x}:\\t{instruction.mnemonic}\\t{instruction.op_str}")
```

#### 2. Handler Code Extraction
- Read 64-128 bytes from IOCTL dispatch handler address
- Handle cases where handler is paged out or corrupted
- Implement fallback strategies (e.g., read what's available)
- Store raw bytes for later analysis

#### 3. Basic Disassembly Pipeline
Create initial pipeline:
1. Enumerate all drivers via Volatility3
2. For each driver, extract IOCTL handler pointer
3. Read handler code bytes from memory
4. Disassemble using Capstone
5. Store results in structured format

## Deliverables for Phase 1

### 1. Working Volatility3 Plugin
- `driver_analysis.py` - Base plugin that extends driver enumeration
- Successfully enumerates drivers with MajorFunction tables
- Extracts and disassembles IOCTL handler code

### 2. Core Infrastructure
- Memory reading utilities with error handling
- Capstone disassembly wrapper
- Data structures for storing driver analysis results

### 3. Test Results
- Successfully analyze at least 1 clean baseline memory dump
- Verify IOCTL handlers are correctly extracted
- Confirm disassembly output is readable and accurate

## Testing Approach for Phase 1

### 1. Acquire Test Memory Dump
- Use a Windows 10/11 VM
- Load a simple driver (e.g., null.sys or custom test driver)
- Create memory dump using:
  - DumpIt
  - WinPMEM
  - VMware snapshot (.vmem)

### 2. Baseline Validation
Run existing Volatility3 plugins:
```bash
vol3 -f memory.dmp windows.modules
vol3 -f memory.dmp windows.driverscan
```

### 3. Test Custom Plugin
```bash
vol3 -f memory.dmp -p ikarma/plugins windows.driver_analysis
```

Verify output includes:
- Driver names and addresses
- MajorFunction table contents
- IOCTL handler addresses
- Disassembled handler code (first ~20 instructions)

## Common Challenges & Solutions

### Challenge 1: Symbol Resolution
**Problem**: Volatility3 needs Windows symbols to parse structures
**Solution**: 
- Use ISF (Intermediate Symbol Format) files
- Download from: https://github.com/volatilityfoundation/volatility3#symbol-tables
- Place in volatility3/framework/symbols/windows/

### Challenge 2: Memory Access Errors
**Problem**: Handler code might be paged out or inaccessible
**Solution**:
- Wrap memory reads in try-except blocks
- Log failures and continue with other drivers
- Mark confidence as "low" when code is incomplete

### Challenge 3: Invalid Function Pointers
**Problem**: MajorFunction entries might point to invalid addresses
**Solution**:
- Validate pointers are within driver memory range
- Check for NULL pointers (0x0)
- Verify address is in kernel space (high addresses on x64)

## Resources

### Documentation
- Volatility3 Docs: https://volatility3.readthedocs.io/
- Capstone Docs: https://www.capstone-engine.org/lang_python.html
- Windows Driver Kit: https://learn.microsoft.com/en-us/windows-hardware/drivers/

### Sample Code
- Volatility3 GitHub: https://github.com/volatilityfoundation/volatility3
- POPKORN (reference implementation): https://github.com/sefcom/POPKORN

### Research Papers
- DIFUZE paper (IOCTL interface analysis)
- POPKORN paper (Windows kernel driver analysis)

## Next Steps

After completing Phase 1:
1. Review disassembly output quality
2. Identify common instruction patterns in IOCTL handlers
3. Begin cataloging dangerous API calls (Phase 2 prep)
4. Document any unexpected challenges or findings

## Progress Tracking

- [ ] Environment fully configured
- [ ] Base plugin structure created
- [ ] MajorFunction table extraction working
- [ ] Capstone integration complete
- [ ] Successfully disassemble at least 5 drivers
- [ ] Code committed to version control
- [ ] Documentation updated
- [ ] Team sync on progress and blockers
