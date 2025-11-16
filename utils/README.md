# iKARMA API Scanner

**Module:** `utils/api_scanner.py`
**Author:** Person 2 (API Hunter)
**Version:** 1.0
**Date:** 2025-11-16

## Quick Start

```python
from utils.api_scanner import find_dangerous_apis

# Get disassembly from Capstone (via driver_analysis.py)
disassembly_lines = [
    "0xfffff80012341016:\tcall\tqword ptr [rip + 0x20b8]\t; nt!MmMapIoSpace",
    "0xfffff8001234101d:\ttest\trax, rax",
    # ... more instructions
]

# Run comprehensive scan
findings = find_dangerous_apis(disassembly_lines)

# Examine results
for finding in findings:
    print(f"Found {finding['name']} at {finding['address']}")
    print(f"  Risk: {finding['risk']}/10")
    print(f"  Why dangerous: {finding['why_dangerous']}")
```

## Detection Methods

### 1. String Matching (`detect_string_match`)
Fast detection via API names in comments/imports.

**Use when:** You want high-confidence detections of known APIs

**Confidence:** 0.7-0.9

### 2. Call Pattern Analysis (`detect_call_patterns`)
Analyzes suspicious call instruction patterns.

**Use when:** You suspect obfuscated or indirect calls

**Confidence:** 0.5 (requires manual review)

### 3. String Reference Detection (`detect_string_references`)
Detects suspicious string constants like "PhysicalMemory".

**Use when:** You want to catch preparatory steps before API calls

**Confidence:** 0.85

## Output Format

Each finding is a dictionary:

```python
{
    'name': 'MmMapIoSpace',              # API name or pattern identifier
    'method': 'string',                  # Detection method used
    'confidence': 0.9,                   # Confidence score (0.0-1.0)
    'address': '0xfffff80012341016',     # Memory address
    'instruction': 'call qword ptr [...]', # Assembly instruction
    'category': 'MEMORY_ACCESS',         # API category
    'risk': 9,                           # Risk score (0-10)
    'why_dangerous': 'Allows raw...'     # Explanation
}
```

## API Database

The scanner uses `core/api_patterns.py` which contains:
- **18 dangerous APIs** across 5 categories
- **Risk scores** (0-10)
- **Detection patterns**
- **BYOVD usage explanations**

## Testing

Run built-in tests:

```bash
python utils/api_scanner.py
```

This runs comprehensive tests with mock disassembly data.

## Integration

The scanner is automatically integrated with `plugins/driver_analysis.py`:

```python
# In driver_analysis.py
def analyze_for_apis(self, disassembly_lines):
    from utils.api_scanner import find_dangerous_apis
    return find_dangerous_apis(disassembly_lines)
```

## Statistics

Get statistics about findings:

```python
from utils.api_scanner import get_scanner_statistics

stats = get_scanner_statistics(findings)
print(f"Total findings: {stats['total_findings']}")
print(f"Highest risk: {stats['highest_risk']}/10")
print(f"By category: {stats['by_category']}")
```

## Dependencies

- Python 3.8+
- `core/api_patterns.py` (API database)
- `re` module (standard library)

## Performance

- **String matching:** ~0.001s for 30 instructions
- **Call patterns:** ~0.002s for 30 instructions
- **String references:** ~0.001s for 30 instructions
- **Total:** ~0.005s per driver analysis

## Limitations

See [DETECTED_APIS.md](../DETECTED_APIS.md) for comprehensive limitations.

**Cannot detect:**
- Heavily obfuscated code
- Dynamically resolved APIs
- String obfuscation
- Syscall-based direct invocation

## Next Steps

Person 3 (Risk Analyst) will use these findings to:
1. Calculate aggregate risk scores
2. Apply confidence modifiers
3. Generate "because" explanations
4. Create final risk assessment

## Files

- `utils/api_scanner.py` - Main scanner implementation
- `core/api_patterns.py` - API signature database
- `DETECTED_APIS.md` - Comprehensive documentation
- `utils/README.md` - This file

---

**Status:** ✅ Phase 1 Complete
