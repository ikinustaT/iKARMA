# iKARMA Development Package - Summary

## What You've Received

This package contains everything you need to start developing iKARMA, your digital forensics tool for detecting BYOVD (Bring Your Own Vulnerable Driver) attacks from memory dumps.

## 📁 Project Structure

```
ikarma/
├── README.md                      # Project overview
├── QUICKSTART.md                  # Start here! Week 1 action items
├── PROGRESS_TRACKER.md            # Track your development progress
├── requirements.txt               # Python dependencies
│
├── docs/
│   ├── SETUP.md                   # Detailed setup instructions
│   ├── PHASE1_GUIDE.md           # Week-by-week Phase 1 guide
│   ├── ROADMAP.md                # Complete 9-week development plan
│   └── DANGEROUS_APIS.md         # Reference for Phase 2 capability detection
│
├── plugins/
│   └── driver_analysis.py        # Starter Volatility3 plugin (with TODOs)
│
├── core/                          # Future: analysis engines
├── detection/                     # Future: anti-forensic detection
├── tests/                         # Future: test suite
└── utils/                         # Future: helper utilities
```

## 🎯 Where to Start

### Immediate Actions (This Week)
1. **Read QUICKSTART.md** - Your Week 1 checklist
2. **Read docs/SETUP.md** - Complete setup guide
3. **Install Volatility3** and dependencies
4. **Create a test memory dump** from a Windows VM
5. **Study plugins/driver_analysis.py** - Your starting code

### Understanding the Code
The `plugins/driver_analysis.py` file is a **starter template** with:
- ✅ Complete plugin structure (ready to run)
- ✅ Volatility3 integration framework
- ✅ Capstone disassembly setup
- ⚠️ TODOs for Phase 1 implementation (marked in comments)

**Key TODOs in the plugin:**
1. `_find_driver_object()` - Locate DRIVER_OBJECT structures
2. `_get_ioctl_handler()` - Extract IOCTL handler from MajorFunction array
3. `_analyze_handler()` - Enhanced disassembly analysis (Phase 2)
4. `_calculate_basic_risk()` - Risk scoring (Phase 2)

## 📚 Documentation Reading Order

### First Week (Essential)
1. **QUICKSTART.md** (5 min) - Action items
2. **docs/SETUP.md** (15 min) - Setup walkthrough
3. **docs/PHASE1_GUIDE.md** (20 min) - Phase 1 roadmap
4. **plugins/driver_analysis.py** (30 min) - Code review

### Later (Reference)
5. **docs/DANGEROUS_APIS.md** - When you start Phase 2
6. **docs/ROADMAP.md** - Full project timeline
7. **PROGRESS_TRACKER.md** - Use for tracking

## 🔧 Technical Architecture

### Phase 1: Foundation (Current Focus)
```
Memory Dump → Volatility3 → Your Plugin → DRIVER_OBJECT → IOCTL Handler → Capstone → Disassembly
```

**Your plugin extends Volatility3 by:**
- Parsing DRIVER_OBJECT structures
- Extracting MajorFunction dispatch tables
- Reading IOCTL handler code from memory
- Disassembling with Capstone

### Phase 2: Capability Analysis (Future)
```
Disassembly → Pattern Matcher → API Detection → Risk Scoring → Confidence → Output
```

### Phase 3: Anti-Forensic Detection (Future)
```
Memory → PE Carver → Independent Driver List → Cross-Validation → DKOM Detection
```

## 🎓 Learning Resources

### Volatility3 Development
- Official docs: https://volatility3.readthedocs.io/
- Plugin development: Read `modules.py` and `driverscan.py` in Volatility3 source
- Symbol tables: https://github.com/volatilityfoundation/volatility3#symbol-tables

### Windows Internals
- DRIVER_OBJECT structure: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object
- IRP Major Functions: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes
- Windows Driver Kit: https://learn.microsoft.com/en-us/windows-hardware/drivers/

### Capstone Disassembly
- Python bindings: https://www.capstone-engine.org/lang_python.html
- X86/X64 reference: https://www.capstone-engine.org/lang_python.html

### Research Papers (from your proposal)
- DIFUZE - IOCTL fuzzing methodology
- POPKORN - Windows driver capability analysis
- Your proposal references (14 papers total)

## ✅ Success Criteria

### Phase 1 Complete (Week 3)
- ✓ Can enumerate drivers from memory dump
- ✓ Extract IOCTL handler addresses
- ✓ Disassemble handler code with Capstone
- ✓ Output readable results

### Final Project Complete (Week 9)
- ✓ Detects dangerous capabilities (10+ APIs)
- ✓ Provides risk scoring with confidence
- ✓ Detects DKOM/anti-forensic techniques
- ✓ Works on 10 test memory dumps
- ✓ Generates explainable output

## 🚦 Development Phases at a Glance

| Phase | Weeks | Focus | Key Deliverable |
|-------|-------|-------|-----------------|
| **Phase 1** | 1-3 | Foundation | Working plugin with disassembly |
| **Phase 2** | 4-6 | Capability Analysis | Risk scoring with confidence |
| **Phase 3** | 7-8 | Anti-Forensic Detection | DKOM detection |
| **Phase 4** | 9 | Integration & Testing | Complete tool + demo |

## 🔍 What Makes iKARMA Unique

Based on your proposal, iKARMA fills a gap by:
1. **Memory-first approach** - No need for original driver binaries
2. **Capability inference** - Not signature-based detection
3. **Explainable results** - "Because" tags for forensic evidence
4. **Anti-forensic detection** - Detects DKOM tampering
5. **Confidence scoring** - Transparent about reliability

Existing tools (Volatility3, LOLDrivers, IoctlHunter) don't do all of this together.

## 💡 Pro Tips

### Development Best Practices
- **Start simple**: Get Phase 1 working before adding complexity
- **Test early, test often**: Don't wait until the end
- **Document as you go**: Future you will thank present you
- **Version control**: Commit working code frequently
- **Team communication**: Weekly syncs minimum

### Avoiding Common Pitfalls
- ❌ Don't try to implement everything at once
- ❌ Don't skip testing with real memory dumps
- ❌ Don't forget error handling (memory can be corrupted)
- ❌ Don't ignore Volatility3's existing code (learn from it)
- ✅ Do focus on Phase 1 first
- ✅ Do test with multiple Windows versions
- ✅ Do handle edge cases gracefully
- ✅ Do keep code readable and documented

## 🐛 Troubleshooting Quick Reference

**Problem: Plugin not found**
→ Use `-p` parameter: `vol3 -f dump.dmp -p /path/to/plugins windows.driver_analysis`

**Problem: Symbol errors**
→ Download ISF files for your Windows version

**Problem: Capstone not working**
→ `pip install capstone`

**Problem: Memory read errors**
→ Normal! Handle gracefully with try-except

**Problem: Disassembly looks wrong**
→ Verify you're using x64 mode for 64-bit dumps

See `docs/SETUP.md` for more troubleshooting.

## 📊 Project Timeline

```
Week 1-3:  Phase 1 - Get IOCTL handlers disassembling
Week 4-6:  Phase 2 - Detect dangerous APIs, add scoring
Week 7-8:  Phase 3 - DKOM detection, anti-forensics
Week 9:    Phase 4 - Testing, documentation, demo
```

You are here: **Week 1** 👈

## 🎯 Your Next Steps (In Order)

1. ✅ Read this summary
2. ⬜ Read QUICKSTART.md
3. ⬜ Set up development environment (SETUP.md)
4. ⬜ Create test memory dump
5. ⬜ Test baseline Volatility3
6. ⬜ Study plugins/driver_analysis.py
7. ⬜ Start implementing Phase 1 TODOs
8. ⬜ Update PROGRESS_TRACKER.md as you go

## 📞 Getting Help

**Documentation Issues?** Re-read relevant section, check comments in code

**Technical Blockers?** 
- Volatility3 GitHub issues
- Team members
- Instructor/TA
- Security forums (Stack Overflow, Reddit r/computerforensics)

**Schedule Concerns?**
- Refer to ROADMAP.md for priorities
- Focus on MVP first, stretch goals later

## 🎓 Academic Integrity Note

This is an **academic project** for your Digital Forensics module. The code and documentation provided are:
- ✅ Starter templates and guidance
- ✅ Educational resources
- ✅ Framework for your implementation
- ❌ NOT complete implementations (you must do the work)

All TODOs in the code must be implemented by your team.

## 🚀 Final Words

You have everything you need to succeed:
- Clear project structure
- Working starter code
- Detailed documentation
- Week-by-week guide
- Testing strategy
- Academic backing (proposal approved!)

**The hardest part is starting. You've already done that by reading this far.**

Now go build iKARMA! The forensics community is waiting for your contribution. 💪

---

**Questions? Start here:**
1. QUICKSTART.md - Week 1 checklist
2. docs/SETUP.md - Detailed setup
3. docs/PHASE1_GUIDE.md - Development roadmap

**Good luck! 🎯🔍🛡️**
