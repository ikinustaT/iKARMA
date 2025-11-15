# 📊 PERSON 3: QUICK REFERENCE CARD

**Your Role:** Risk Analyst  
**Your Mission:** Risk scoring + confidence framework + DKOM detection plugin

---

## ⏰ THIS WEEK (Nov 15-21)

### Day 1-2: Build Risk Scorer
```python
# File: core/risk_scorer.py
def calculate_risk(found_apis, driver_context):
    """
    Input: [
        {'name': 'MmMapIoSpace', 'risk': 9, 'confidence': 0.95},
        {'name': 'MmCopyMemory', 'risk': 8, 'confidence': 0.8}
    ]
    """
    
    # Base score
    base = sum(api['risk'] * api['confidence'] for api in found_apis)
    
    # Modifiers
    if has_dangerous_combination(found_apis):
        base *= 1.5
    
    if driver_context.get('no_validation'):
        base *= 1.3
    
    if driver_context.get('obfuscated'):
        base *= 1.2
    
    # Normalize to 0-100
    score = min(base, 100)
    
    return {
        'score': score,
        'level': score_to_level(score),  # Low/Medium/High/Critical
        'confidence': calculate_overall_confidence(found_apis),
        'reasons': generate_because_tags(found_apis)
    }

def score_to_level(score):
    if score < 40: return "Low"
    elif score < 70: return "Medium"
    elif score < 90: return "High"
    else: return "Critical"
```

**Success Check:** Function returns score + level + reasons ✅

### Day 1-2: Build Confidence Framework
```python
# File: core/confidence.py
def calculate_confidence(detection):
    """Assign confidence based on detection method"""
    
    base_confidence = {
        'direct_call': 0.95,      # call instruction to known address
        'import_table': 1.0,      # Listed in IAT
        'string_ref': 0.8,        # API name in strings + nearby call
        'opcode_pattern': 0.7,    # Pattern match
        'indirect_call': 0.5      # Register call (ambiguous)
    }
    
    confidence = base_confidence.get(detection['method'], 0.5)
    
    # Adjust for context
    if detection.get('obfuscated'):
        confidence *= 0.7
    
    if detection.get('multiple_methods'):
        confidence = min(confidence * 1.2, 1.0)
    
    return confidence
```

**Success Check:** Confidence values make sense ✅

### Day 3-4: Generate "Because" Tags
```python
def generate_because_tags(found_apis):
    """Create human-readable explanations"""
    reasons = []
    
    for api in found_apis:
        reason = f"{api['name']} detected: {api['capability']}"
        confidence = f"(confidence: {api['confidence']:.0%})"
        reasons.append(f"{reason} {confidence}")
    
    # Add combination warnings
    if has_combination(['MmMapIoSpace', 'MmCopyMemory']):
        reasons.append("⚠ Dangerous API combination: arbitrary memory read/write capability")
    
    return reasons
```

**Success Check:** Reasons are clear and forensically useful ✅

### Day 5-7: Build DKOM Validator Plugin
```python
# File: plugins/byovd_validator.py
class BYOVDValidator(interfaces.plugins.PluginInterface):
    """Detect hidden drivers using cross-view validation"""
    
    def detect_dkom(self, context, kernel):
        # View 1: Official list
        official = set(get_modules_from_psloadedmodulelist())
        
        # View 2: Pool scanning
        carved = set(scan_pools_for_drivers())
        
        # View 3: Object Manager
        objects = set(enumerate_driver_objects())
        
        # Find discrepancies
        hidden = carved - official
        inconsistent = official.symmetric_difference(objects)
        
        for driver in hidden:
            yield {
                'driver': driver.name,
                'dkom_type': 'List unlinking',
                'severity': 'Critical',
                'evidence': f'Found in pool scan but not in PsLoadedModuleList'
            }
```

**Success Check:** Plugin detects Person 4's DKOM scenario ✅

---

## 📋 NEXT WEEK (Nov 22-28)

- Day 8-9: Refine scoring based on test results
- Day 10-11: Polish validator output
- Day 12-13: Final testing
- Day 14: Buffer

---

## 🆘 IF YOU'RE STUCK

**Problem:** Risk scores seem too high/low  
**Solution:** Adjust thresholds, test with known good/bad drivers

**Problem:** "Because" tags are confusing  
**Solution:** Ask Person 5 for feedback, simplify language

**Problem:** DKOM detection too complex  
**Solution:** Start with just 1 method (list comparison), expand later

**Problem:** Don't know what cross-view validation means  
**Solution:** It means comparing the SAME data from DIFFERENT sources to find lies

---

## ✅ DAILY CHECKLIST

```
[ ] Test scoring on sample data
[ ] Refine confidence calculations
[ ] Update "because" tag generation
[ ] Work on validator plugin
[ ] Commit code
[ ] Post daily update
```

---

## 🎯 YOUR SUCCESS METRICS

- Risk scoring algorithm working ✅
- Confidence framework complete ✅
- "Because" tags clear and useful ✅
- Validator plugin detects DKOM ✅

**Key Files:**
- `core/risk_scorer.py` (your scoring engine)
- `core/confidence.py` (your confidence framework)
- `plugins/byovd_validator.py` (your DKOM plugin)
