# Person 4: Research & Anti-Forensics - 5-Day Plan

Your role is twofold: to tackle the advanced research topics in a time-boxed manner and to be the team's primary tester and support resource.

---

### **Day 1: DKOM Research**

*   **Task 1: Understand the Problem:** Research Direct Kernel Object Manipulation (DKOM). Focus on what it is and the most common techniques used by malware (e.g., hiding processes by unlinking from `EPROCESS` list).
*   **Task 2: Explore Volatility3 Capabilities:** Investigate how existing Volatility3 plugins detect DKOM. The `windows.pslist.PsList` plugin has checks for hidden processes. Study its source code to understand how it cross-references different kernel structures.
*   **Task 3: Outline a PoC:** Based on your research, write a one-page markdown document (`DKOM_PoC_Plan.md`) outlining a plan for a simple proof-of-concept. For example, a script that uses the `pslist` library functions to find processes that are in a `csrss.exe` handle table but not in the active process list.

### **Day 2: Test Case Acquisition**

*   **Task 1: Find Vulnerable Drivers:** Your team needs drivers to test against. Research known vulnerable drivers used in BYOVD attacks (e.g., gdrv.sys, dbk64.sys, rwevery.sys).
*   **Task 2: Acquire Samples:** Search for samples of these drivers on platforms like VirusTotal, MalShare, or the GitHub `malware-samples` repository. **Use extreme caution and a sandboxed environment (like a VM) for this task.**
*   **Task 3: Generate Memory Dumps:** Create a Windows Virtual Machine. Load one of the vulnerable drivers (if safe to do so) and take a memory dump using a tool like WinPmem or FTK Imager. Create another dump from a clean VM without the driver. You now have a "malicious" and a "benign" test case.

### **Day 3: DKOM Proof-of-Concept (Time-boxed)**

*   **Task 1: Implement the PoC (4 hours max):** Spend a maximum of half a day trying to implement the plan from Day 1. Write a standalone Python script that imports Volatility3 libraries and performs your chosen DKOM check.
*   **Task 2: Document Results:** Whether the PoC is fully successful or not, document the results. Include your code, the output, and an explanation of the challenges. This documentation is your deliverable for Phase 3. It's more valuable than a half-finished implementation.
*   **Task 3: Team Support:** Check in with the other team members. See if anyone is blocked on a technical problem you can help with.

### **Day 4: Testing the Main Plugin**

*   **Task 1: Get the Latest Code:** Pull the latest version of the `driver_analysis.py` plugin from Person 1.
*   **Task 2: Run Against Test Dumps:** Run the plugin against your "benign" and "malicious" memory dumps.
*   **Task 3: Analyze and Report:** Carefully analyze the output. Does it correctly identify the vulnerable driver? Is the risk score appropriate? Does it flag benign drivers incorrectly (false positives)? Document your findings and report them to the team. This is a critical feedback loop.

### **Day 5: Building the Test Suite**

*   **Task 1: Create More Test Cases:** If time permits, generate more memory dumps with different drivers or system states. The more diverse your test data, the more confident you can be in the tool.
*   **Task 2: Formalize Test Plan:** Create a `TEST_PLAN.md` document. For each memory dump, list the drivers you expect to be found and what the expected risk score or findings should be.
*   **Task 3: Final Demo Preparation:** Work with the team to choose the best "malicious" and "benign" drivers to use for the final video demo and presentation. Ensure the output for these specific drivers is as clear and compelling as possible.
