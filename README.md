# iKARMA - Kernel Driver Analysis for Memory Forensics

**Production Release v2.0.0**

iKARMA is a specialized memory forensics tool designed to identify and analyze potentially dangerous kernel drivers in Windows memory dumps.

## Key Features

### v2.0.0 Highlights

- **Volatility3 Integration**: Full integration with Volatility3 for structured memory analysis with PE carving fallback
- **Cross-View Validation**: True DKOM detection by comparing PsLoadedModuleList vs DRIVER_OBJECT scan
- **Hook Detection**: MajorFunction table analysis to detect hooked handlers
- **Legitimacy Bonus**: Reduced risk scores for Microsoft/WHQL signed drivers
- **"Because" Tags**: Every finding includes forensic-defensible evidence strings
- **SIEM-Ready JSON**: Consistent schema for security orchestration integration

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Analyze a memory dump
ikarma analyze memory.dmp -o results.json

# List known vulnerable drivers
ikarma loldrivers --verbose
```

## Python API

```python
from ikarma import Analyzer

analyzer = Analyzer("memory.dmp")
analyzer.initialize()
result = analyzer.analyze()

for driver in result.drivers:
    if driver.risk_score >= 7.0:
        print(f"[{driver.risk_category}] {driver.name}: {driver.risk_score}")
        print(driver.generate_summary_because())

analyzer.export_json("results.json")
```

## License

MIT License
