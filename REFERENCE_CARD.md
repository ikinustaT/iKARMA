# iKARMA Quick Reference Card

## Essential Commands

### Volatility3 Basics
```bash
# List processes
vol3 -f memory.dmp windows.pslist

# List all loaded drivers
vol3 -f memory.dmp windows.modules

# Scan for DRIVER_OBJECT structures
vol3 -f memory.dmp windows.driverscan

# Get system info
vol3 -f memory.dmp windows.info

# Verbose/debug mode
vol3 -vv -f memory.dmp [plugin]
```

### Run Your Plugin
```bash
# If symlinked to Volatility3 plugins directory
vol3 -f memory.dmp windows.driver_analysis

# With plugin path parameter
vol3 -f memory.dmp -p /path/to/ikarma/plugins windows.driver_analysis

# With options
vol3 -f memory.dmp windows.driver_analysis \
    --disassemble true \
    --handler_bytes 128
```

### Python Development
```bash
# Activate virtual environment
source venv/bin/activate         # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Install single package
pip install capstone

# Check installed packages
pip list | grep volatility
```

## File Locations Reference

```
Volatility3 Symbols:
  volatility3/volatility3/framework/symbols/windows/

Your Plugin:
  ikarma/plugins/driver_analysis.py

Memory Dumps:
  ikarma/tests/test_data/

Documentation:
  ikarma/docs/
```

## Common Code Patterns

### Access Memory Layer
```python
layer = self.context.layers[layer_name]
data = layer.read(address, size)
```

### Parse Windows Structure
```python
driver_obj = kernel.object(
    object_type="DRIVER_OBJECT",
    offset=address
)
```

### Disassemble with Capstone
```python
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code, addr):
    print(f"{insn.mnemonic} {insn.op_str}")
```

## Windows Structures Reference

### DRIVER_OBJECT
```
Offset  Field
+0x000  Type (short)
+0x002  Size (short)
+0x008  DeviceObject (ptr)
+0x010  Flags
+0x018  DriverStart (ptr)
+0x020  DriverSize
+0x028  DriverName (UNICODE_STRING)
+0x038  MajorFunction[28] (function pointers)
         [0x0E] = IRP_MJ_DEVICE_CONTROL (IOCTL)
```

### IRP Major Function Codes
```
0x00  IRP_MJ_CREATE
0x02  IRP_MJ_CLOSE
0x03  IRP_MJ_READ
0x04  IRP_MJ_WRITE
...
0x0E  IRP_MJ_DEVICE_CONTROL    ← IOCTL handler
...
```

## Dangerous APIs Quick List

### Critical Risk
- `MmMapIoSpace` - Physical memory mapping
- `ZwOpenSection("\\Device\\PhysicalMemory")`
- Token manipulation (EPROCESS+offset)
- `__readmsr` / `__writemsr`

### High Risk
- `ZwTerminateProcess`
- `PsLookupProcessByProcessId`
- `MmCopyVirtualMemory`
- `ObRegisterCallbacks` (malicious)

### Medium Risk
- `ZwLoadDriver`
- `PsCreateSystemThread`
- Callback unregistration

## Git Commands

```bash
# Initialize repository
git init
git add .
git commit -m "Initial commit"

# Daily workflow
git status
git add plugins/driver_analysis.py
git commit -m "Implement IOCTL handler extraction"
git push

# Create branch for feature
git checkout -b phase1-driver-enum
```

## Testing Commands

```bash
# Create memory dump (Windows VM)
dumpit.exe                    # DumpIt
winpmem_mini.exe memory.raw   # WinPMEM

# Verify dump integrity
vol3 -f memory.dmp windows.info

# Test your plugin
vol3 -f memory.dmp windows.driver_analysis

# Compare with baseline
diff <(vol3 -f memory.dmp windows.modules) baseline.txt
```

## Debugging

```bash
# Python debugger
python3 -m pdb vol3.py -f memory.dmp windows.driver_analysis

# Print to stderr (appears in console)
import sys
print(f"Debug: {value}", file=sys.stderr)

# Volatility logging
import logging
vollog = logging.getLogger(__name__)
vollog.debug("Debug message")
vollog.info("Info message")
vollog.warning("Warning message")
```

## Performance Profiling

```bash
# Time execution
time vol3 -f memory.dmp windows.driver_analysis

# Python profiler
python3 -m cProfile -o profile.stats vol3.py -f memory.dmp windows.driver_analysis

# Analyze profile
python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"
```

## Useful Paths

```bash
# Volatility3 source
/path/to/volatility3/

# Volatility3 plugins
/path/to/volatility3/volatility3/framework/plugins/windows/

# Symbol files (ISF)
/path/to/volatility3/volatility3/framework/symbols/windows/

# Your project
/path/to/ikarma/

# Test data
/path/to/ikarma/tests/test_data/
```

## Error Messages Reference

**"Symbol table not found"**
→ Download ISF file for your Windows version

**"Invalid address"**
→ Normal for paged memory, handle with try-except

**"No module named 'volatility3'"**
→ `pip install -e /path/to/volatility3`

**"Plugin not found"**
→ Use `-p` parameter or check symlink

**"Capstone not found"**
→ `pip install capstone`

## Environment Variables

```bash
# Python path (if needed)
export PYTHONPATH=/path/to/volatility3:$PYTHONPATH

# Volatility3 plugin path
export VOL3_PLUGINS=/path/to/ikarma/plugins
```

## Documentation Quick Links

- **Volatility3 Docs**: https://volatility3.readthedocs.io/
- **Capstone API**: https://www.capstone-engine.org/lang_python.html
- **Windows DDK**: https://learn.microsoft.com/en-us/windows-hardware/drivers/
- **Symbol Tables**: https://github.com/volatilityfoundation/volatility3#symbol-tables

## Phase 1 Checklist

- [ ] Environment setup complete
- [ ] Can run Volatility3 on test dump
- [ ] Plugin structure created
- [ ] _find_driver_object() implemented
- [ ] MajorFunction table parsing works
- [ ] IOCTL handler extraction works
- [ ] Capstone integration complete
- [ ] Disassembly working

## Team Communication

**Daily Standup Questions:**
1. What did you complete yesterday?
2. What will you work on today?
3. Any blockers?

**Weekly Review:**
1. What went well?
2. What needs improvement?
3. Are we on track?
4. Adjustments needed?

---

**Print this card and keep it handy! 📋**
