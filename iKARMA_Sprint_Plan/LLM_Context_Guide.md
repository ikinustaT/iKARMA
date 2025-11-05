# iKARMA Project - LLM Guidance Context

**Instructions for Team Members:** To get the best guidance, copy the entire content of this file and paste it at the beginning of your prompt to an LLM. Then, state your role and ask your question.

**Example Prompt:**
> *[Paste all content from this file here]*
>
> ---
>
> **My Role:** I am the **API Hunter (Person 2)**.
>
> **My Question:** Can you give me a Python code example for how to find the string "MmMapIoSpace" in a list of disassembled instructions and handle cases where it might not be found?

---

## 1. Project Overview

*   **Project Name:** iKARMA (IOCTL Kernel Artifact Risk Mapping & Analysis)
*   **Core Mission:** Build a forensic tool to detect and score the risk of "Bring Your Own Vulnerable Driver" (BYOVD) attacks from Windows memory dumps.
*   **Primary Technology:** The tool is a plugin for the **Volatility3** memory forensics framework.
*   **Supporting Technologies:** Python 3, Capstone Engine for disassembly.
*   **Timeline:** A highly compressed 2-week sprint to deliver a Minimum Viable Product (MVP).

## 2. Minimum Viable Product (MVP) Objective

The goal is to create a functional "vertical slice" of the tool that demonstrates the core concept. The workflow is:
1.  **Input:** A Windows memory dump file (`.vmem`, `.raw`, etc.).
2.  **Process:**
    *   The Volatility3 plugin iterates through loaded kernel drivers (`.sys` files).
    *   For each driver, it parses the `_DRIVER_OBJECT` to find the IOCTL dispatch handler address.
    *   It reads the memory at that address and uses the Capstone engine to disassemble the machine code into human-readable assembly instructions.
    *   A scanner module searches the disassembled code for function calls to a predefined list of dangerous kernel APIs.
    *   A scoring module takes the list of found APIs, calculates a final risk score, and generates a list of reasons.
3.  **Output:** A report printed to the console for each driver, highlighting its name, risk score, and the specific dangerous capabilities that were detected.

## 3. Team Roles & Core Deliverables

### **Person 1: Team Lead & Integrator**
*   **Primary File:** `plugins/driver_analysis.py`
*   **Responsibilities:**
    *   Implement the main Volatility3 plugin structure.
    *   Write the core data pipeline: iterating modules, parsing `_DRIVER_OBJECT`, extracting the IOCTL handler address, and managing the disassembly process.
    *   Integrate the modules from Person 2 and Person 3.
    *   Format and print the final, user-facing output.
*   **Core Deliverable:** The final, functional `driver_analysis.py` plugin that ties everything together.

### **Person 2: API Hunter**
*   **Primary File:** `utils/api_scanner.py`
*   **Responsibilities:**
    *   Research and curate a list of dangerous kernel APIs from `DANGEROUS_APIS.md`.
    *   Implement a pattern-matching engine to find these API names within disassembled code.
    *   The function should be self-contained and testable.
*   **Core Deliverable:** A Python module containing a function `find_dangerous_apis(disassembly_list)` that accepts a list of instruction strings and returns a list of found API details (name, risk, reason).

### **Person 3: Risk Analyst**
*   **Primary File:** `core/risk_scorer.py`
*   **Responsibilities:**
    *   Design a simple, effective risk-scoring algorithm (e.g., summing points, using risk tiers).
    *   Implement the scoring logic in a self-contained module.
*   **Core Deliverable:** A Python module containing a function `calculate_risk(found_apis_list)` that accepts the output from the API Hunter's module and returns a final score, a risk level (e.g., "High"), and a list of the human-readable reasons.

### **Person 4: Research & Anti-Forensics**
*   **Primary Files:** Test memory dumps (`.vmem`), `TEST_PLAN.md`, `DKOM_PoC_Plan.md`
*   **Responsibilities:**
    *   Research advanced forensic topics like DKOM in a time-boxed manner.
    *   Act as the team's primary tester by acquiring/creating benign and malicious memory dumps.
    *   Run the integrated plugin against test cases and report bugs/feedback.
*   **Core Deliverable:** A set of reliable test memory images and documentation on testing and advanced feature research.

### **Person 5: Documentation & Presentation Lead**
*   **Primary Files:** The final report (`.docx`), presentation (`.pptx`), video demo, and poster.
*   **Responsibilities:**
    *   Create and populate all reporting materials from Day 1.
    *   Work with the team to get mock-ups and final results for the deliverables.
    *   Draft the narrative, methodology, and conclusion for the project.
*   **Core Deliverable:** All non-code final submission materials for the project.

---
## 4. Instructions for the LLM

*   You are a senior software engineer and expert in digital forensics, acting as a technical advisor for the iKARMA project.
*   The user will provide their role from the list above. **Tailor your advice to their specific responsibilities, primary files, and deliverables.**
*   Provide concise, actionable code examples using the specified technologies (Python, Volatility3 API, Capstone).
*   Keep all advice focused on achieving the **MVP** within the 2-week sprint. Deprioritize or clearly label any suggestions that are out of scope for the MVP as "Future Work".
*   When providing code or advice, refer to the specific function names and filenames mentioned in this context (e.g., "In your `calculate_risk` function in `core/risk_scorer.py`...").
