# iKARMA Project Sprint Plan & Role Division

This document outlines a high-level strategy and division of labor to deliver a successful project within a compressed 2-week timeline.

### The Strategy: Prioritize the Minimum Viable Product (MVP)

Given the time constraint, we cannot build everything. We will focus on a "vertical slice" that proves the project's core value.

1.  **Finish Phase 1:** Reliably extract and disassemble IOCTL handlers from drivers in a memory image. This is the non-negotiable foundation.
2.  **Implement Core Phase 2:** Detect a small, critical set of dangerous APIs (5-10) and assign a risk score. This delivers on the "Risk Mapping" promise of the project.
3.  **Simplify Phase 3:** Address anti-forensics conceptually. A full implementation is too risky. A proof-of-concept script or a well-researched design document is sufficient for the presentation.
4.  **Parallelize Documentation:** The presentation, report, and video must be developed *alongside* the code, not after.

---

### Role Division & Responsibilities

Here is the breakdown of roles and tasks for the sprint.

#### **Person 1: Team Lead & Integrator**
This person owns the main `driver_analysis.py` plugin and is responsible for integrating everyone's work into a cohesive final product. They will manage the main branch and ensure the plugin is always in a runnable state.

*   **Core Tasks:** Solidify driver/IOCTL handler extraction, integrate API scanning and risk scoring modules, and manage final testing and output formatting.

#### **Person 2: API Hunter (Capability Analysis)**
This person focuses on finding dangerous functions within the disassembled code provided by the core plugin. They will own the pattern-matching logic.

*   **Core Tasks:** Research dangerous APIs, implement a pattern-matching engine in a separate module, and provide a list of found APIs for a given block of disassembly.

#### **Person 3: Risk Analyst (Scoring & Reporting)**
This person designs and implements the logic that makes sense of the findings from the API Hunter. They are responsible for quantifying the risk.

*   **Core Tasks:** Design a simple and effective risk-scoring model, implement it in a separate module, and generate human-readable "reasons" for the calculated score.

#### **Person 4: Research & Anti-Forensics**
This person tackles advanced topics in a time-boxed manner and acts as a support resource for the team. They will also be responsible for creating test cases.

*   **Core Tasks:** Research DKOM detection techniques and produce a proof-of-concept or design document. Find or create memory dumps with known vulnerable drivers for testing and demonstration.

#### **Person 5: Documentation & Presentation Lead**
This person is responsible for creating all final deliverables (report, presentation, video, poster) and will start on Day 1.

*   **Core Tasks:** Create and populate the report and presentation skeletons, storyboard the video, and work with the team to get mock-ups and, eventually, final results for the deliverables.
