# Person 2: API Hunter - 5-Day Plan

Your focus is to create a self-contained, reliable module that scans disassembled code and identifies a predefined list of dangerous API calls.

---

### **Day 1: Research & Signature Database Design**

*   **Task 1: Master the Target List:** Read `DANGEROUS_APIS.md` thoroughly. For each function, understand *why* it's a security risk.
*   **Task 2: Design the API Database:** In the `utils/api_scanner.py` file (created by Person 1), design a Python dictionary to hold your API signatures. It should store the API name, its base risk score, and a human-readable reason for why it's dangerous.
*   **Task 3: Populate the Database:** Populate your dictionary with the top 5-7 most critical APIs from your research (e.g., `MmMapIoSpace`, `ZwMapViewOfSection`, `KeStackAttachProcess`).

### **Day 2: Build the Scanner with Mock Data**

*   **Task 1: Create Mock Disassembly Data:** Create a list of strings in your module that mimics the output of the Capstone disassembler. Crucially, include lines that contain your target API names, often in comments (e.g., `call qword ptr [rip + 0x20b8] ; nt!MmMapIoSpace`).
*   **Task 2: Implement String-Matching Logic:** Write the code for your main function (`find_dangerous_apis`). It should loop through each instruction string and check if any of the keys (API names) from your signature dictionary are present.
*   **Task 3: Structure the Return Value:** When a match is found, create a dictionary containing the name, risk, and reason, and add it to a list of results that your function will return.

### **Day 3: Testing, Documentation, and Handoff**

*   **Task 1: Unit Test Your Module:** Create a `if __name__ == "__main__":` block at the bottom of your file. Call your main function with the mock data and print the results to prove your scanner works correctly.
*   **Task 2: Document Your Code:** Add comments and docstrings to your module, explaining how it works, what it expects as input, and what it returns.
*   **Task 3: Check-in and Sync:** Commit your completed `utils/api_scanner.py` to the repository. Inform Person 1 that the first version is ready for integration.

### **Day 4: Integration Support & Refinement**

*   **Task 1: Paired Debugging:** Work directly with Person 1. They will now be feeding your function *real* disassembly. It might not look exactly like your mock data. Be prepared to adjust your string-matching logic.
*   **Task 2: Refine Patterns:** If simple string matching isn't enough, refine your patterns. You don't need full regex yet, but you might need to make your checks more robust.
*   **Task 3: Expand API Database:** Once the integration is stable, add another 5-10 APIs to your signature dictionary.

### **Day 5: Advanced Research & Future-Proofing**

*   **Task 1: Research Obfuscation:** Spend a few hours researching how malware might try to hide these API calls (e.g., indirect calls via registers, dynamically resolved imports).
*   **Task 2: Document Limitations:** You don't have time to implement solutions for this, but you can document them. Add a `LIMITATIONS` section to your module's docstring explaining that the current implementation won't catch obfuscated calls. This is excellent content for the final report's "Future Work" section.
*   **Task 3: Final Review:** Do a final code review of your module. Ensure it's clean, well-documented, and robust for the core requirements.
