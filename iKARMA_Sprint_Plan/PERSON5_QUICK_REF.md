# 📝 PERSON 5: QUICK REFERENCE CARD

**Your Role:** Documentation Lead  
**Your Mission:** Complete report + presentation + demo video + all submission materials

---

## ⏰ THIS WEEK (Nov 15-21)

### Day 1-2: Create Skeletons

**Report Structure (Word/LaTeX):**
```
1. Abstract (150 words)
   - Problem, Solution, Results, Conclusion

2. Introduction (2 pages)
   - BYOVD threat overview
   - Memory forensics challenges
   - Project goals and scope

3. Literature Review (3 pages)
   - Existing tools (POPKORN, IoctlHunter, Vol3)
   - DKOM detection research
   - BYOVD attack papers
   - Gap analysis (what's missing)

4. Methodology (4 pages)
   - System architecture
   - Multi-method API detection
   - Risk scoring algorithm
   - Confidence framework
   - Cross-view validation

5. Implementation (3 pages)
   - Plugin architecture
   - Technical challenges
   - Solutions/workarounds

6. Results (3 pages)
   - Test methodology
   - Detection accuracy metrics
   - Performance benchmarks
   - Comparison to manual analysis

7. Discussion (2 pages)
   - Interpretation of results
   - Limitations
   - Threats to validity

8. Conclusion (1 page)
   - Summary of contributions
   - Future work

9. References (2 pages)
   - Minimum 10 citations
```

**Presentation Structure (15-20 slides):**
```
Slide 1: Title
Slide 2: The BYOVD Problem
Slide 3: Why Memory Forensics?
Slide 4: Project Goals
Slide 5: Related Work
Slide 6: System Architecture
Slide 7-9: Methodology (one slide per major component)
Slide 10-11: Implementation Highlights
Slide 12: LIVE DEMO
Slide 13-15: Results (metrics, graphs, comparison)
Slide 16: Discussion & Limitations
Slide 17: Contributions & Future Work
Slide 18: Conclusion
Slide 19: Questions?
Slide 20: Backup slides (technical details)
```

**Success Check:** Both skeletons created with all sections ✅

### Day 1-2: Start Writing

**Write Introduction & Literature Review:**
- Use existing project docs (PROJECT_SUMMARY.txt, START_HERE.md)
- Research papers to cite:
  - Brendmo & Meland (2023) - POPKORN
  - Palutke et al. (2020) - DKOM detection
  - Burgers et al. (2016) - BYOVD attacks
  - CrowdStrike/ESET threat reports
  - Volatility3 framework papers
- Search Google Scholar: "BYOVD attacks", "IOCTL analysis", "DKOM detection"

**Create Related Work Table:**
| Tool | Approach | Limitation | iKARMA Advantage |
|------|----------|-----------|------------------|
| POPKORN | Static binary analysis | Requires driver files | Memory-only analysis |
| IoctlHunter | IOCTL enumeration | No risk assessment | Automated scoring |
| Vol3 driverscan | Module enumeration | No capability analysis | Full risk profiling |
| DriverBuddy | Static patterns | Signature-based | Behavior-based inference |

**Success Check:** 5+ pages written ✅

### Day 3-4: Draft Methodology

**Work with Technical Team:**
- Interview Person 2: "How does API detection work?"
- Interview Person 3: "Explain the risk scoring formula"
- Interview Person 1: "What's the data flow?"

**Create Diagrams:**
1. System Architecture (boxes and arrows)
2. Data Flow (memory dump → results)
3. API Detection Process (flowchart)
4. Risk Scoring Algorithm (formula + example)

**Write Methodology Section:**
```markdown
### 4.1 Multi-Method API Detection

We employ three complementary detection methods:

**Method 1: String-Based Detection**
Searches disassembled instructions for API names. Fast but may 
produce false positives if API names appear in comments or strings.
Confidence: 0.8

**Method 2: Call Instruction Analysis**
Parses CALL instructions and resolves target addresses. High accuracy
for direct calls to known kernel APIs. Confidence: 0.95

**Method 3: Opcode Pattern Matching**
Identifies instruction sequences characteristic of dangerous operations.
Useful for detecting inline implementations. Confidence: 0.7

[Include example of each method with code snippets]
```

**Success Check:** Methodology section 80% complete ✅

### Day 5-7: Create Mock-up Results

**Before Person 4's real results are ready, create mock-ups:**

**Table 1: Detection Accuracy**
| Test Case | True Positive | False Positive | Detection Rate |
|-----------|---------------|----------------|----------------|
| Vulnerable Drivers | 4/4 | - | 100% |
| Benign Drivers | - | 1/10 | 90% Specificity |
| Overall | - | - | 95% Accuracy |

**Graph 1: Risk Score Distribution**
[Bar chart showing number of drivers at each risk level]

**Table 2: Performance Benchmarks**
| Metric | Value |
|--------|-------|
| Time per driver | 1.2 seconds |
| Memory usage | 250 MB |
| Throughput | 50 drivers/minute |

**Graph 2: Time Comparison**
[Bar chart: Manual Analysis (45 min) vs iKARMA (2 min)]

**Success Check:** All result sections have placeholders ✅

---

## 📋 NEXT WEEK (Nov 22-28)

### Day 8-9: Populate Real Results
- Get data from Person 4
- Replace mock-ups with real metrics
- Generate actual graphs in Excel/Python
- Write Results section analysis

### Day 10-11: Create Demo Materials

**Demo Video Script (5-7 minutes):**
```
[0:00-0:30] Introduction
"Hello, I'm presenting iKARMA, an automated tool for detecting 
vulnerable kernel drivers in memory dumps."

[0:30-1:30] Problem Explanation
"BYOVD attacks leverage legitimate but vulnerable drivers..."
[Show diagram of attack flow]

[1:30-4:00] Live Demo
"Let's analyze a memory dump from a suspected incident..."
[Screen recording showing commands]
vol3 -f suspicious.vmem ikarma.byovd_scanner
[Show output with high-risk driver]

"Now let's deep-dive on this suspicious driver..."
vol3 -f suspicious.vmem ikarma.byovd_capability --driver evil.sys
[Show detailed analysis]

"Finally, let's check for anti-forensic techniques..."
vol3 -f suspicious.vmem ikarma.byovd_validator
[Show DKOM detection]

[4:00-5:30] Results Summary
"Our testing showed 95% detection accuracy..."
[Show graphs]
"This reduces analyst time from hours to minutes..."

[5:30-6:00] Conclusion
"iKARMA provides automated, evidence-based detection..."

[6:00-7:00] Questions slide
```

**Record Demo:**
- Use OBS Studio or Camtasia
- Record in 1920x1080
- Clear audio narration
- Practice 3-4 times before final recording

### Day 12-13: Final Polish

**Report:**
- [ ] Proofread entire document
- [ ] Check all citations are formatted correctly
- [ ] Verify all figures are numbered and referenced
- [ ] Run Grammarly/spelling check
- [ ] Get 2 teammates to review
- [ ] Export to PDF

**Presentation:**
- [ ] Practice full presentation (15-20 min)
- [ ] Get teammate feedback
- [ ] Refine slide transitions
- [ ] Add speaker notes
- [ ] Export to PDF + keep editable version

**Demo Video:**
- [ ] Final edit (trim, transitions)
- [ ] Add title cards
- [ ] Verify audio quality
- [ ] Export in high quality (1080p, 30fps)
- [ ] Upload backup copy

**Poster (if required):**
- [ ] A1 size (594×841mm or 33×47 inches)
- [ ] Sections: Abstract, Methodology, Results, Conclusion
- [ ] Large fonts (title 72pt, headings 48pt, body 24pt)
- [ ] High-quality diagrams
- [ ] Get print quote from university print shop

### Day 14: Submission Package
```
submission/
├── iKARMA_Final_Report.pdf
├── iKARMA_Presentation.pdf
├── iKARMA_Presentation.pptx
├── iKARMA_Demo_Video.mp4
├── iKARMA_Poster.pdf (if required)
└── iKARMA_Source_Code.zip
    ├── plugins/
    ├── core/
    ├── utils/
    ├── tests/
    └── README.md
```

---

## 🆘 IF YOU'RE STUCK

**Problem:** Don't know what to write in Methodology  
**Solution:** Interview technical team, ask "how does X work?"

**Problem:** Can't find academic papers  
**Solution:** Google Scholar, IEEE Xplore, ACM Digital Library

**Problem:** Results section empty (no data yet)  
**Solution:** Create mock-ups, will replace with real data later

**Problem:** Demo video keeps messing up  
**Solution:** Record terminal commands first, add voiceover later

**Problem:** Report feels too short  
**Solution:** Add more detail to Methodology, expand Literature Review

**Problem:** Presentation too long  
**Solution:** Cut technical details (move to backup slides), focus on story

---

## ✅ DAILY CHECKLIST

```
[ ] Write 2-3 pages of report
[ ] Update 3-5 presentation slides
[ ] Check with technical team for updates
[ ] Collect screenshots/results as they become available
[ ] Post daily update
```

---

## 🎯 YOUR SUCCESS METRICS

**Report:**
- [ ] 20-25 pages total ✅
- [ ] 10+ citations ✅
- [ ] All sections complete ✅
- [ ] Professional quality ✅

**Presentation:**
- [ ] 15-20 slides ✅
- [ ] Clear narrative ✅
- [ ] Compelling visuals ✅
- [ ] 15-20 minute duration ✅

**Demo Video:**
- [ ] 5-7 minutes ✅
- [ ] High quality audio/video ✅
- [ ] Shows all 3 plugins ✅
- [ ] Clear and engaging ✅

**Key Files:**
- Report: `iKARMA_Final_Report.docx` → `.pdf`
- Presentation: `iKARMA_Presentation.pptx` → `.pdf`
- Demo: `iKARMA_Demo_Video.mp4`
- Poster: `iKARMA_Poster.pdf`

**Your Deliverables = The Team's Final Product!**
