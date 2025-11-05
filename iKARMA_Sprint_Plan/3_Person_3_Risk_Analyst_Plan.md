# Person 3: Risk Analyst - 5-Day Plan

Your focus is to design and implement a module that takes the raw findings from the API Hunter and translates them into a quantifiable risk score with clear, human-readable justifications.

---

### **Day 1: Model Design & Scaffolding**

*   **Task 1: Design the Risk-Scoring Model:** Decide on the scoring logic. Start simple: the total risk is the sum of the risk points of all found APIs. Define risk tiers (e.g., 0-30: Low, 31-70: Medium, 71+: High).
*   **Task 2: Sync with API Hunter:** Talk to Person 2 to get their initial list of APIs and their base risk points. Ensure your models are aligned.
*   **Task 3: Create the Module:** In the `core/risk_scorer.py` file (created by Person 1), define the function signature you will implement, e.g., `calculate_risk(found_apis_list)`.

### **Day 2: Implementation with Mock Data**

*   **Task 1: Create Mock Input Data:** Your function will receive a list of dictionaries from Person 2's module. Create a mock version of this list for testing.
    ```python
    MOCK_FOUND_APIS = [
        {'name': 'MmMapIoSpace', 'risk': 90, 'reason': '...'},
        {'name': 'KeStackAttachProcess', 'risk': 75, 'reason': '...'}
    ]
    ```
*   **Task 2: Implement the Scoring Logic:** Write the code for your `calculate_risk` function. It should iterate through the input list, sum the `'risk'` values, and determine the risk tier.
*   **Task 3: Structure the Return Value:** Your function should return a tuple or dictionary containing the final score, the risk tier (e.g., "High"), and a list of the "reason" strings for the report.

### **Day 3: Testing, Refinement, and Documentation**

*   **Task 1: Unit Test Your Module:** Create a `if __name__ == "__main__":` block. Call your `calculate_risk` function with different sets of mock data (e.g., no APIs found, one API, multiple APIs) and print the results to verify your logic is correct.
*   **Task 2: Refine "Reason" Strings:** Review the reason strings provided by Person 2. Edit them to be clear, concise, and impactful for the final report.
*   **Task 3: Document Your Code:** Add docstrings and comments to your module explaining the scoring model and the function's inputs and outputs. Check in your completed module.

### **Day 4: Prepare for Integration**

*   **Task 1: Sync with Team Lead:** Talk to Person 1. Explain how your module works and what data it expects. Be ready to assist with integration tomorrow.
*   **Task 2: Consider Advanced Scoring (Conceptual):** Think about how the model could be improved. Could certain combinations of APIs result in a higher score (e.g., `KeStackAttachProcess` + `ZwMapViewOfSection` is more dangerous than either alone)? You don't need to implement this, but document it for the "Future Work" section of the report.
*   **Task 3: Sync with Documentation Lead:** Provide Person 5 with a clear explanation of your scoring model (the tiers, the logic) so they can accurately write about it in the report and presentation.

### **Day 5: Integration Support & Finalization**

*   **Task 1: Paired Integration:** Work with Person 1 as they integrate your module into the main plugin. Help debug any issues.
*   **Task 2: Output Formatting:** Advise Person 1 on how the final output should be presented to the user to be most effective. The goal is a clean, clear report for each driver.
*   **Task 3: Final Review:** Do a final review of your module. Ensure it is robust and well-documented. Confirm with Person 1 that the integrated output matches your expectations.
