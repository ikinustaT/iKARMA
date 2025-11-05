# iKARMA Development Setup Instructions

## Step 1: Prerequisites

### Required Software
- Python 3.8 or higher
- Git
- Windows VM (for creating test memory dumps)
  - Windows 10 or 11
  - VMware Workstation/VirtualBox
  - At least 4GB RAM

### Recommended Tools
- Visual Studio Code or PyCharm
- Windows Debugging Tools (WinDbg)
- PE analysis tools (PE Explorer, CFF Explorer)

## Step 2: Clone Volatility3

Since you'll be creating custom plugins, you need access to Volatility3's source:

```bash
# Clone Volatility3 repository
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3

# Install in development mode
pip install -e .
```

## Step 3: Set Up iKARMA Project

```bash
# Navigate back to your project directory
cd ..

# Create Python virtual environment
python3 -m venv ikarma-env

# To enable script execution on Powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate virtual environment
# On Linux/Mac:
# source ikarma-env/bin/activate
# On Windows:
.\ikarma-env\bin\Activate.ps1

# Install dependencies
cd ikarma
pip install -r requirements.txt
```

## Step 4: Configure Volatility3 to Use Your Plugin

You have two options:

### Option A: Symlink Your Plugin (Recommended for Development)
```bash
# Create symlink in Volatility3 plugins directory
ln -s /path/to/ikarma/plugins/driver_analysis.py \
      /path/to/volatility3/volatility3/framework/plugins/windows/driver_analysis.py
```

### Option B: Use Plugin Path Parameter
```bash
# Run with -p parameter pointing to your plugins directory
vol3 -f memory.dmp -p /path/to/ikarma/plugins windows.driver_analysis
```

## Step 5: Download Windows Symbols

Volatility3 needs symbol files to parse Windows structures:

```bash
cd volatility3

# Download symbol packs for your target Windows versions
# Visit: https://github.com/volatilityfoundation/volatility3#symbol-tables

# Place ISF files in:
# volatility3/volatility3/framework/symbols/windows/
```

Common symbol files you'll need:
- `ntkrnlmp.pdb` (Windows 10/11 kernel)
- `ntoskrnl.pdb` (older Windows versions)

## Step 6: Create Test Memory Dump

### Using DumpIt (Easiest)
1. Download DumpIt from MagnetForensics
2. Run as Administrator in your Windows VM
3. Creates `memory.dmp` in current directory

### Using WinPMEM
```bash
# Download from: https://github.com/Velocidex/WinPmem
winpmem_mini.exe memory.raw
```

### Using VMware Snapshot
1. In VMware: VM → Snapshot → Take Snapshot
2. Locate `.vmem` file in VM directory
3. Use directly with Volatility3 (it's a raw memory dump)

## Step 7: Verify Setup

Test basic Volatility3 functionality:

```bash
# List running processes
vol3 -f memory.dmp windows.pslist

# List loaded modules/drivers
vol3 -f memory.dmp windows.modules

# Scan for drivers
vol3 -f memory.dmp windows.driverscan
```

If these work, your environment is ready!

## Step 8: Test Your Plugin

```bash
# Run your custom driver analysis plugin
vol3 -f memory.dmp windows.driver_analysis

# Enable verbose output for debugging
vol3 -vv -f memory.dmp windows.driver_analysis

# Disable disassembly if Capstone has issues
vol3 -f memory.dmp windows.driver_analysis --disassemble false
```

## Troubleshooting

### Issue: "No module named 'capstone'"
**Solution**: 
```bash
pip install capstone
```

### Issue: "Symbol table not found"
**Solution**: Download appropriate ISF file for your Windows version and place in symbols directory

### Issue: "Invalid address" errors
**Solution**: This is normal for some memory regions. The plugin should handle these gracefully with try-except blocks.

### Issue: Plugin not found
**Solution**: 
- Verify plugin is in correct directory
- Check file naming: must match class name
- Use `-p` parameter to specify plugin path

### Issue: "Architecture not supported"
**Solution**: Ensure your memory dump is x64 (64-bit Windows). x86 (32-bit) requires different Capstone configuration.

## Development Workflow

### 1. Edit Plugin
Make changes to `ikarma/plugins/driver_analysis.py`

### 2. Test Changes
```bash
vol3 -f memory.dmp windows.driver_analysis
```

### 3. Debug Issues
```bash
# Verbose output
vol3 -vv -f memory.dmp windows.driver_analysis

# Python debugging
python3 -m pdb vol3.py -f memory.dmp windows.driver_analysis
```

### 4. Run Tests (Phase 1+)
```bash
cd ikarma
pytest tests/
```

## Recommended Development Order

1. **Week 1**: 
   - Complete environment setup
   - Get existing Volatility3 plugins working
   - Study `modules.py` and `driverscan.py` source code
   - Familiarize yourself with Volatility3 API

2. **Week 2**:
   - Implement `_find_driver_object()` method
   - Test with clean memory dump
   - Verify IOCTL handler extraction works

3. **Week 3**:
   - Refine Capstone integration
   - Handle edge cases (paged out memory, invalid pointers)
   - Document findings and prepare for Phase 2

## Resources

### Documentation
- Volatility3 Docs: https://volatility3.readthedocs.io/
- Volatility3 GitHub: https://github.com/volatilityfoundation/volatility3
- Capstone Tutorial: https://www.capstone-engine.org/lang_python.html

### Windows Internals
- Windows Driver Kit Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/
- DRIVER_OBJECT Structure: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object
- IRP Major Function Codes: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes

### Reference Implementations
- Volatility3 example plugins
- POPKORN source code (if available)
- IoctlHunter source: https://github.com/Z4kSec/IoctlHunter

## Next Steps

Once setup is complete:
1. Read Phase 1 Guide (`docs/PHASE1_GUIDE.md`)
2. Study the starter plugin code (`plugins/driver_analysis.py`)
3. Create your first test memory dump
4. Start implementing the TODOs in the plugin
5. Document your progress and blockers

Good luck with iKARMA development! 🚀
