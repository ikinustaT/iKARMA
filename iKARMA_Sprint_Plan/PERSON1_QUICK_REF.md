# 🔧 PERSON 1: QUICK REFERENCE CARD

**Your Role:** Team Lead & Integration  
**Your Mission:** Transform working code into 2 production plugins + integrate everyone's work

---

## ⏰ THIS WEEK (Nov 15-21)

### Day 1-2: Refactor Scanner
```python
# Transform driver_analysis.py → byovd_scanner.py
# Add these features:
- Command-line options (--high-risk-only, --export-json)
- Call Person 2's API scanner (even if it returns mock data)
- Call Person 3's risk scorer
- Better output formatting
- Progress indicators
```

**Success Check:** Plugin runs and calls other modules ✅

### Day 3-4: Integration
- Debug interface between modules
- Test with Person 4's memory dumps
- Add JSON export
- Fix integration bugs

**Success Check:** Real API detections + real risk scores showing ✅

### Day 5-7: Build Capability Plugin
```python
# Create byovd_capability.py
# Deep-dive plugin for ONE driver
vol3 -f memory.vmem ikarma.byovd_capability --driver evil.sys

Output:
- Full disassembly (500+ instructions)
- All detected APIs with addresses
- Call chain analysis
```

**Success Check:** Second plugin working ✅

---

## 📋 NEXT WEEK (Nov 22-28)

- Day 8-9: Fix bugs, optimize performance
- Day 10-11: Demo preparation, script rehearsal
- Day 12-13: Final polish, submission prep
- Day 14: Buffer (emergency fixes only)

---

## 🆘 IF YOU'RE STUCK

**Problem:** Person 2's API scanner returns weird format  
**Solution:** Call Person 2 immediately, pair program to fix interface

**Problem:** Disassembly failing on some drivers  
**Solution:** Add try/except, log the error, skip that driver, continue

**Problem:** Performance too slow  
**Solution:** Add progress bar, process in batches, optimize hot loops

**Problem:** Behind schedule  
**Solution:** Drop capability plugin, focus on making scanner really good

---

## ✅ DAILY CHECKLIST

```
[ ] Pull latest code from team
[ ] Work 4 focused hours
[ ] Commit working code
[ ] Post daily standup update
[ ] Help someone if they're blocked
```

---

## 🎯 YOUR SUCCESS = TEAM SUCCESS

You're the glue. Keep everyone moving forward. Merge code daily. Don't let perfect be the enemy of good.

**Key Files:**
- `plugins/byovd_scanner.py` (your main work)
- `plugins/byovd_capability.py` (your stretch goal)
- `utils/memory_utils.py` (helper functions)
