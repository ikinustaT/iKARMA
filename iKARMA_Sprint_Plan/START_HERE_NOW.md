# 🚀 iKARMA EMERGENCY SPRINT - START HERE

**Created:** November 15, 2025  
**Deadline:** November 29, 2025 (14 days remaining)  
**Current Status:** Behind schedule, need immediate action

---

## ⚠️ READ THIS FIRST

**If you're feeling overwhelmed or don't know where to start:**

1. Read YOUR quick reference card (`PERSONX_QUICK_REF.md`)
2. Do the tasks for TODAY (Day 1-2)
3. Commit your code at end of day
4. Post a 3-sentence update in the group chat

**That's it. Don't overthink. Just start.**

---

## 📁 WHICH FILES TO READ

### **Everyone Should Read:**
- `EMERGENCY_2WEEK_SPRINT.md` ← Full detailed plan (30 min read)
- This file ← Quick overview (5 min read)

### **Your Personal File:**
- **Person 1:** `PERSON1_QUICK_REF.md`
- **Person 2:** `PERSON2_QUICK_REF.md`
- **Person 3:** `PERSON3_QUICK_REF.md`
- **Person 4:** `PERSON4_QUICK_REF.md`
- **Person 5:** `PERSON5_QUICK_REF.md`

**Time to read your file:** 10 minutes  
**Time to understand your tasks:** 20 minutes  
**Time to start coding:** NOW

---

## 🎯 THE BIG PICTURE

### What We're Building (3 Plugins):

```
1. ikarma.byovd_scanner
   → Fast triage of ALL drivers (2 minutes for 100 drivers)
   → Shows risk score + detected capabilities
   → Person 1 builds this

2. ikarma.byovd_capability
   → Deep analysis of ONE suspicious driver
   → Shows full disassembly + all APIs + call chains
   → Person 1 builds this

3. ikarma.byovd_validator
   → Detects anti-forensic techniques (DKOM)
   → Cross-view validation
   → Person 3 builds this
```

### Supporting Modules:

```
core/api_patterns.py       ← Person 2's API database
utils/api_scanner.py        ← Person 2's detection engine
core/risk_scorer.py         ← Person 3's scoring algorithm
core/confidence.py          ← Person 3's confidence framework
```

### Testing & Documentation:

```
tests/                      ← Person 4's test dumps + results
Final Report                ← Person 5's writing
Presentation                ← Person 5's slides
Demo Video                  ← Person 5's recording
```

---

## 📅 TIMELINE (SIMPLIFIED)

### **This Week (Nov 15-21): BUILD**
- Person 1: Build scanner + capability plugins
- Person 2: Implement API detection (20+ APIs)
- Person 3: Build risk scorer + validator plugin
- Person 4: Acquire 10 test memory dumps
- Person 5: Write methodology section

### **Next Week (Nov 22-28): POLISH**
- Days 22-23: Testing & bug fixing
- Days 24-25: Demo preparation
- Days 26-27: Final documentation
- Day 28: Buffer (emergency only)

### **Submission (Nov 29): DELIVER**
- Report (PDF)
- Presentation (PDF + PPTX)
- Demo Video (MP4)
- Source Code (ZIP)
- Poster (PDF) - if required

---

## 🔥 TODAY'S PRIORITIES (Day 1)

### Person 1:
```bash
cd plugins
cp driver_analysis.py byovd_scanner.py
# Edit byovd_scanner.py
# Add command-line options
# Wire up API scanner and risk scorer calls
```

### Person 2:
```bash
cd core
# Edit api_patterns.py
# Add 10 APIs with risk scores
cd ../utils
# Edit api_scanner.py
# Implement string matching detection
```

### Person 3:
```bash
cd core
# Edit risk_scorer.py
# Implement calculate_risk() function
# Edit confidence.py
# Implement calculate_confidence() function
```

### Person 4:
```bash
# Download WinPmem
# Create 2 VMs (clean Windows 10 + Windows 11)
# Take memory dumps
# Document in tests/TEST_INVENTORY.md
```

### Person 5:
```bash
# Create report document
# Write outline with all sections
# Start writing Introduction (2 pages)
# Create presentation skeleton (20 slides)
```

---

## 💬 DAILY COMMUNICATION

### Daily Standup (Same time every day - 15 minutes):

Each person answers:
1. What I did yesterday
2. What I'm doing today
3. Am I blocked? (if yes, who can help)

**Post in group chat or have quick call.**

### When to Ask for Help:

- Blocked for more than 2 hours → Ask in chat
- Blocked for more than 4 hours → Emergency team call
- Code not working → Share error, ask for pair programming

**DO NOT suffer in silence!**

---

## ✅ HOW TO KNOW YOU're ON TRACK

### End of Week 1 (Nov 21):
- [ ] Person 1: Scanner plugin working end-to-end
- [ ] Person 2: Detects 10+ APIs with 3 methods
- [ ] Person 3: Risk scorer working, validator started
- [ ] Person 4: 10 test dumps acquired
- [ ] Person 5: 50% of report written

### End of Week 2 (Nov 28):
- [ ] All 3 plugins working
- [ ] All testing complete with metrics
- [ ] Report 100% complete
- [ ] Presentation ready
- [ ] Demo video recorded

### Submission Day (Nov 29):
- [ ] Everything submitted on time
- [ ] Team celebrates 🎉

---

## 🆘 EMERGENCY CONTACT

### If You're Stuck:
1. Read your quick reference card again
2. Ask in group chat
3. Ask the LLM assistant (paste your specific question)

### If You're Behind Schedule:
1. Focus on CRITICAL tasks only (see priority levels in main document)
2. Skip NICE-TO-HAVE features
3. Ask team for help

### If You're Overwhelmed:
1. Take a 10-minute break
2. Re-read just YOUR quick reference card
3. Do ONE task from today's list
4. Post that you completed it
5. Do the next task

**One task at a time. You've got this.**

---

## 🎓 WHY THIS WILL SUCCEED

1. **Clear roles:** Everyone knows their job
2. **Realistic scope:** 3 plugins, not 10
3. **Daily progress:** Small wins every day
4. **Good communication:** Daily standups, immediate help when blocked
5. **Focus on completion:** 80% solution submitted > 100% solution never finished

**This is a 30% project. It's worth the effort.**

---

## 📊 WHAT MAKES THIS 30%-WORTHY

- **Technical depth:** 3 custom Volatility plugins with novel algorithms
- **Research quality:** Literature review, methodology, evaluation
- **Practical impact:** Real tool that saves analyst time
- **Professional presentation:** Complete documentation, polished demo
- **Novel contributions:** Multi-method detection, confidence framework, cross-view validation

**This is conference-quality work if you execute it.**

---

## 🚀 FINAL WORDS

You have:
- 14 days
- 5 people
- A clear plan
- All the tools you need

**The only thing that can stop you is:**
- Analysis paralysis (overthinking)
- Poor communication (suffering in silence)
- Scope creep (trying to build too much)

**The things that will make you succeed:**
- Starting NOW
- Doing your assigned tasks
- Asking for help when stuck
- Committing code daily
- Celebrating small wins

**You've already done the hard part** (driver enumeration, IOCTL extraction). Now you just need to build on top of it.

---

## 📝 IMMEDIATE ACTION ITEMS

**Right now, before you do anything else:**

1. [ ] Read your personal quick reference card (10 min)
2. [ ] Open the files you need to edit (5 min)
3. [ ] Do the first task from Day 1-2 section (2-4 hours)
4. [ ] Commit your work with a clear message (2 min)
5. [ ] Post "Day 1 complete: [what I did]" in group chat (1 min)

**Total time to get started: 10-15 minutes**  
**Total time for meaningful progress: 2-4 hours**

---

## 🎯 LET'S GO!

**Don't wait. Don't overthink. START NOW.**

Read your quick reference card → Do today's tasks → Commit code → Post update

Repeat for 14 days.

**You've got this.** 💪

---

*Questions? Confused? Stuck?*  
*Read the main plan: `EMERGENCY_2WEEK_SPRINT.md`*  
*Or ask in group chat immediately.*

**Last Updated:** November 15, 2025
