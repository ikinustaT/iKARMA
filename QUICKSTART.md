# iKARMA Quick Start Checklist

## Your First Week Action Items

### Day 1: Setup (2-3 hours)
- [X] Install Python 3.8+ on your system
- [X] Clone Volatility3: `git clone https://github.com/volatilityfoundation/volatility3.git`
- [X] Install Volatility3: `cd volatility3 && pip install -e .`
- [X] Install iKARMA dependencies: `cd ../ikarma && pip install -r requirements.txt`
- [X] Verify Volatility works: `vol -h`

### Day 2: Get Familiar (2-3 hours)
- [ ] Read: `docs/SETUP.md` - Complete setup instructions
- [ ] Read: `docs/PHASE1_GUIDE.md` - Your development roadmap
- [ ] Study: Volatility3 modules.py source code
- [ ] Study: Your starter plugin `plugins/driver_analysis.py`

### Day 3: Create Test Memory Dump (1-2 hours)
- [ ] Set up Windows 10/11 VM
- [ ] Download DumpIt or WinPMEM
- [ ] Create memory dump: `dumpit.exe` (as Administrator)
- [ ] Test with Volatility: `vol3 -f memory.dmp windows.pslist`
- [ ] Download Windows symbols (ISF files)

### Day 4-5: First Code (3-4 hours)
- [ ] Implement `_find_driver_object()` in driver_analysis.py
- [ ] Test your plugin: `vol3 -f memory.dmp windows.driver_analysis`
- [ ] Debug any errors
- [ ] Document what you learned

### Day 6-7: Team Sync
- [ ] Share your progress with team
- [ ] Divide remaining tasks
- [ ] Update project board/tracker
- [ ] Plan Week 2 goals

---

## Essential Files to Read (In Order)

1. **README.md** (5 min) - Project overview
2. **docs/SETUP.md** (15 min) - Detailed setup guide
3. **docs/PHASE1_GUIDE.md** (20 min) - Week-by-week Phase 1 plan
4. **plugins/driver_analysis.py** (30 min) - Starter code with TODOs
5. **docs/DANGEROUS_APIS.md** (skim for now) - Reference for Phase 2
6. **docs/ROADMAP.md** (skim) - Full 9-week plan

---

## Key Commands Reference

### Volatility3 Basics
```bash
# List processes
vol3 -f memory.dmp windows.pslist

# List modules/drivers
vol3 -f memory.dmp windows.modules

# Scan for drivers
vol3 -f memory.dmp windows.driverscan

# Verbose output (for debugging)
vol3 -vv -f memory.dmp windows.modules
```

### Your Custom Plugin
```bash
# Run your plugin (Option 1: if symlinked)
vol3 -f memory.dmp windows.driver_analysis

# Run your plugin (Option 2: with plugin path)
vol3 -f memory.dmp -p /path/to/ikarma/plugins windows.driver_analysis

# With options
vol3 -f memory.dmp windows.driver_analysis --disassemble true --handler_bytes 128

# Debug mode
vol3 -vv -f memory.dmp windows.driver_analysis
```

### Python Development
```bash
# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
pip install -r requirements.txt

# Run tests (Phase 1+)
pytest tests/

# Format code
black plugins/
```

---

## Common First-Week Problems & Solutions

### Problem: "No module named volatility3"
**Solution**: Install Volatility3 in development mode:
```bash
cd volatility3
pip install -e .
```

### Problem: "Symbol table not found"
**Solution**: Download ISF files for your Windows version:
- Visit: https://github.com/volatilityfoundation/volatility3#symbol-tables
- Place in: `volatility3/volatility3/framework/symbols/windows/`

### Problem: "Plugin not found"
**Solution**: Use `-p` parameter or symlink your plugin:
```bash
vol3 -f memory.dmp -p /path/to/ikarma/plugins windows.driver_analysis
```

### Problem: "Capstone not installed"
**Solution**: 
```bash
pip install capstone
```

### Problem: "Can't create memory dump"
**Solution**: 
- Run as Administrator
- Use DumpIt or WinPMEM (links in SETUP.md)
- Or use VMware snapshot (.vmem file)

---

## Week 1 Success Criteria

By end of Week 1, you should be able to:
- ✓ Run Volatility3 successfully on a test memory dump
- ✓ List drivers using `windows.modules`
- ✓ Understand basic plugin structure
- ✓ Have modified and tested your plugin at least once
- ✓ Know where to find help (documentation, team, instructor)

---

## Getting Help

### Documentation
- Volatility3: https://volatility3.readthedocs.io/
- Capstone: https://www.capstone-engine.org/
- Windows Internals: https://learn.microsoft.com/en-us/windows-hardware/drivers/

### Your Project Files
- Phase 1 Guide: `docs/PHASE1_GUIDE.md`
- Setup Guide: `docs/SETUP.md`
- Roadmap: `docs/ROADMAP.md`

### Team Communication
- Schedule regular check-ins
- Use version control (Git)
- Document blockers immediately
- Don't struggle alone - ask for help!

---

## Next Phase Preview

### Phase 2 (Weeks 4-6): Capability Detection
Once Phase 1 works, you'll add:
- Pattern matching for dangerous APIs
- Risk scoring algorithm
- Confidence framework
- "Because" tags for explanations

But don't worry about Phase 2 yet - focus on getting Phase 1 working first!

---

## Motivation

Remember: You're building something genuinely useful for the forensics community. BYOVD attacks are a real, growing threat. iKARMA addresses a gap that existing tools don't cover well. Your work matters! 🚀

**Good luck with development!**
