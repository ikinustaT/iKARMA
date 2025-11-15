# 🎯 PERSON 2: QUICK REFERENCE CARD

**Your Role:** API Hunter  
**Your Mission:** Detect 20+ dangerous APIs using 3 different methods

---

## ⏰ THIS WEEK (Nov 15-21)

### Day 1-2: Build API Database
```python
# File: core/api_patterns.py
API_DATABASE = {
    'MEMORY_ACCESS': {
        'MmMapIoSpace': {
            'risk': 9,
            'capability': 'Map arbitrary physical memory',
            'detection_methods': ['string', 'call', 'import']
        },
        'MmCopyMemory': { ... },
        # Add 8 more memory APIs
    },
    'PROCESS_MANIPULATION': {
        'PsLookupProcessByProcessId': { ... },
        # Add 5 more process APIs
    },
    'KERNEL_OBJECTS': {
        'ObReferenceObjectByHandle': { ... },
        # Add 5 more kernel APIs
    }
}
```

**Success Check:** 20+ APIs documented ✅

### Day 1-2: Implement Detection
```python
# File: utils/api_scanner.py
def find_dangerous_apis(disassembly_lines):
    findings = []
    
    # Method 1: String matching (fast)
    for line in disassembly_lines:
        for api_name in API_DATABASE:
            if api_name in line:
                findings.append({
                    'name': api_name,
                    'method': 'string',
                    'confidence': 0.8,
                    'address': extract_address(line)
                })
    
    # Method 2: Call instruction analysis
    findings.extend(detect_call_instructions(disassembly_lines))
    
    # Method 3: String references
    findings.extend(detect_string_refs(disassembly_lines))
    
    return deduplicate(findings)
```

**Success Check:** Function returns list of found APIs ✅

### Day 3-4: Test & Refine
- Test with Person 1's integrated plugin
- Fix any bugs in detection logic
- Adjust confidence scores based on results

**Success Check:** 90%+ detection rate on test cases ✅

### Day 5-7: Add Opcode Analysis
```python
# Detect vulnerability patterns
def detect_unsafe_dereference(instructions):
    """
    Find: mov rax, [user_buffer]
          mov [rax], data        <- NO validation!
    """
    for i in range(len(instructions) - 1):
        if is_pointer_load(instructions[i]):
            if is_dereference(instructions[i+1]):
                if not has_validation_between(i, i+1):
                    return {
                        'pattern': 'unsafe_dereference',
                        'risk': 8,
                        'confidence': 0.7
                    }
```

**Success Check:** Detects 3 vulnerability patterns ✅

---

## 📋 NEXT WEEK (Nov 22-28)

- Day 8-9: Help Person 4 test, fix false positives
- Day 10-11: Document all APIs
- Day 12-13: Final refinements
- Day 14: Buffer

---

## 🆘 IF YOU'RE STUCK

**Problem:** Too many false positives  
**Solution:** Increase confidence threshold, add context checks

**Problem:** Missing APIs that should be found  
**Solution:** Add more detection patterns, check disassembly format

**Problem:** Don't understand an API's risk level  
**Solution:** Research on MSDN, check LOLDrivers database, ask team

**Problem:** Opcode analysis too complex  
**Solution:** Start simple (just detect 1 pattern), expand later

---

## ✅ DAILY CHECKLIST

```
[ ] Add 3-5 APIs to database
[ ] Test detection on sample disassembly
[ ] Update confidence scores
[ ] Commit code with clear message
[ ] Post daily update
```

---

## 🎯 YOUR SUCCESS METRICS

- 20+ APIs in database ✅
- 3 detection methods working ✅
- 90%+ detection rate ✅
- <10% false positive rate ✅

**Key Files:**
- `core/api_patterns.py` (your database)
- `utils/api_scanner.py` (your detection engine)
- `DETECTED_APIS.md` (your documentation)
