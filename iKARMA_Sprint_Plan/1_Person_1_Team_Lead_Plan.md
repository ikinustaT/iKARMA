# Person 1: Team Lead & Integrator - 5-Day Plan

Your focus is to build the main plugin's structure, get the core data pipeline working (Driver -> IOCTL Handler -> Disassembly), and integrate the modules from your teammates.

---

### **Day 1: Foundation & Driver Enumeration**

*   **Task 1: Environment Verification:** Follow `SETUP.md` precisely. Clone a fresh Volatility3 repo, install dependencies from `requirements.txt`, and run the standard `windows.pslist.PsList` plugin on a test memory image to confirm your setup is flawless.
*   **Task 2: Starter Code Deep Dive:** Read and add comments to every line of `plugins/driver_analysis.py`. Understand its entry points and where your new logic will hook in.
*   **Task 3: Implement Driver Enumeration:** Modify the `_generator` method to iterate through `self.context.modules`. Filter for kernel drivers (`.sys` files) and print a list of their names and base addresses.

### **Day 2: Locating IOCTL Handlers**

*   **Task 1: Parse `_DRIVER_OBJECT`:** For each driver found yesterday, write the code to locate and read its `_DRIVER_OBJECT` structure from memory.
*   **Task 2: Extract IOCTL Dispatch Address:** From the `_DRIVER_OBJECT`, access the `MajorFunction` array. Read the pointer at index `IRP_MJ_DEVICE_CONTROL` (14). This is the address of the IOCTL handler function. Print it for each driver.
*   **Task 3: Define the Analysis Pipeline:** Create empty placeholder functions in `driver_analysis.py` (`disassemble_function`, `analyze_for_apis`, `calculate_risk`) to structure the workflow.

### **Day 3: Disassembly & Interface Definition**

*   **Task 1: Implement Basic Disassembly:** Implement the `disassemble_function`. Use the `capstone` library to read and disassemble the first 4KB of memory from the IOCTL handler address. Print the first ~30 instructions for one driver to prove it works.
*   **Task 2: Create Interface Modules:** Create two new files: `utils/api_scanner.py` (for Person 2) and `core/risk_scorer.py` (for Person 3). In each, define the empty function signature you will call (e.g., `find_dangerous_apis(disassembly)`).
*   **Task 3: Communicate Interfaces:** Check in all new code. Announce to Person 2 and 3 that their modules are ready and that their job is to fill in the functions you have defined.

### **Day 4: Integration of API Scanner**

*   **Task 1: Import and Call:** In `driver_analysis.py`, import the `find_dangerous_apis` function from Person 2's module.
*   **Task 2: Integration:** Pass your disassembled code to this function and print the results it returns.
*   **Task 3: Debugging:** The real disassembly data may be different from Person 2's mock data. Work with them to debug any issues and get the integration working smoothly.

### **Day 5: Integration of Risk Scorer & Output Formatting**

*   **Task 1: Import and Call:** Import the `calculate_risk` function from Person 3's module.
*   **Task 2: Integration:** Pass the list of found APIs (from Person 2's module) to the risk scorer.
*   **Task 3: Final Output:** Structure the final console output. Use the score and reasons from Person 3's module to print a clean, readable report for each driver, like the mock-up in the presentation.
