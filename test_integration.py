"""
Integration Test: Person 1 (Disassembly) → Person 2 (API Scanner)

This simulates the actual data flow from Person 1's driver_analysis.py
to Person 2's api_scanner.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.api_scanner import find_dangerous_apis, get_scanner_statistics
from core.api_patterns import get_all_api_names


def test_integration():
    """
    Simulate Person 1's disassembly output format and test Person 2's scanner.
    """

    print("=" * 70)
    print("INTEGRATION TEST: Person 1 -> Person 2 -> Person 3")
    print("=" * 70)

    # ========================================================================
    # STEP 1: Simulate Person 1's disassembly output
    # ========================================================================
    print("\n[STEP 1] Simulating Person 1's disassembly output...")

    # This is the EXACT format that Person 1's disassemble_function() returns
    # Format: "0xaddress:\tmnemonic\top_str"
    person1_disassembly = [
        "0xfffff8001a2b1000:\tpush\trbp",
        "0xfffff8001a2b1001:\tmov\trbp, rsp",
        "0xfffff8001a2b1004:\tsub\trsp, 0x40",
        "0xfffff8001a2b1008:\tmov\trcx, qword ptr [rbp + 0x48]",  # User buffer
        "0xfffff8001a2b100c:\tmov\trdx, qword ptr [rcx]",  # Physical address from user
        "0xfffff8001a2b1010:\tmov\tr8d, 0x1000",  # Size
        "0xfffff8001a2b1016:\txor\tr9d, r9d",  # Cache type
        "0xfffff8001a2b1019:\tcall\tqword ptr [rip + 0x2fb8]",  # Import table call
        "0xfffff8001a2b101f:\t; nt!MmMapIoSpace",  # Capstone comment (this line is the API name)
        "0xfffff8001a2b1020:\ttest\trax, rax",
        "0xfffff8001a2b1022:\tjz\t0xfffff8001a2b1050",

        # Token theft pattern
        "0xfffff8001a2b1030:\tmov\trcx, qword ptr [rbp + 0x50]",  # PID from user
        "0xfffff8001a2b1034:\tcall\tqword ptr [rip + 0x3000]",
        "0xfffff8001a2b103a:\t; nt!PsLookupProcessByProcessId",
        "0xfffff8001a2b103b:\tmov\tqword ptr [rbp - 8], rax",  # Save EPROCESS
        "0xfffff8001a2b103f:\tadd\trax, 0x360",  # Token offset
        "0xfffff8001a2b1045:\tmov\trcx, qword ptr [rax]",

        # Process termination
        "0xfffff8001a2b1050:\tlea\trcx, qword ptr [rip + 0x5000]",
        "0xfffff8001a2b1057:\t; L\"MsMpEng.exe\"",  # Windows Defender string
        "0xfffff8001a2b1058:\tcall\tqword ptr [rip + 0x4000]",
        "0xfffff8001a2b105e:\t; wcscmp",
        "0xfffff8001a2b105f:\ttest\teax, eax",
        "0xfffff8001a2b1061:\tjnz\t0xfffff8001a2b1070",
        "0xfffff8001a2b1067:\tmov\trcx, qword ptr [rbp + 0x58]",  # Process handle
        "0xfffff8001a2b106b:\tcall\tqword ptr [rip + 0x5000]",
        "0xfffff8001a2b1071:\t; nt!ZwTerminateProcess",
    ]

    print(f"    Generated {len(person1_disassembly)} disassembly lines")
    print(f"    Format: '{person1_disassembly[0]}'")

    # ========================================================================
    # STEP 2: Call Person 2's API scanner
    # ========================================================================
    print("\n[STEP 2] Calling Person 2's API scanner...")

    api_findings = find_dangerous_apis(person1_disassembly)

    print(f"    Scanner returned {len(api_findings)} findings")

    # ========================================================================
    # STEP 3: Verify output format matches Person 3's expectations
    # ========================================================================
    print("\n[STEP 3] Verifying output format for Person 3...")

    required_keys = ['name', 'method', 'confidence', 'address', 'instruction',
                     'category', 'risk', 'why_dangerous']

    all_valid = True
    for finding in api_findings:
        for key in required_keys:
            if key not in finding:
                print(f"    [ERROR] Missing key '{key}' in finding: {finding}")
                all_valid = False

    if all_valid:
        print(f"    [OK] All {len(api_findings)} findings have required keys")

    # ========================================================================
    # STEP 4: Display findings (what Person 3 will see)
    # ========================================================================
    print("\n[STEP 4] Detailed findings (Person 3's input)...")
    print("-" * 70)

    for i, finding in enumerate(api_findings, 1):
        print(f"\n  Finding #{i}:")
        print(f"    API: {finding['name']}")
        print(f"    Risk: {finding['risk']}/10")
        print(f"    Confidence: {finding['confidence']:.2f}")
        print(f"    Method: {finding['method']}")
        print(f"    Category: {finding['category']}")
        print(f"    Address: {finding['address']}")
        print(f"    Why dangerous: {finding['why_dangerous'][:60]}...")

    # ========================================================================
    # STEP 5: Generate statistics (for Person 3's aggregation)
    # ========================================================================
    print("\n" + "-" * 70)
    print("[STEP 5] Statistics for Person 3's risk aggregation...")

    stats = get_scanner_statistics(api_findings)

    print(f"\n  Total findings: {stats['total_findings']}")
    print(f"  Unique APIs: {stats['unique_apis']}")
    print(f"  Highest risk: {stats['highest_risk']}/10")

    print(f"\n  By Category:")
    for category, count in stats['by_category'].items():
        print(f"    - {category}: {count}")

    print(f"\n  By Risk Level:")
    for level, count in stats['by_risk_level'].items():
        print(f"    - {level}: {count}")

    # ========================================================================
    # STEP 6: Simulate Person 3's risk calculation (placeholder)
    # ========================================================================
    print("\n" + "-" * 70)
    print("[STEP 6] Simulating Person 3's risk calculation...")

    # This is what Person 3 will implement in core/risk_scorer.py
    if api_findings:
        # Simple aggregation example
        total_risk = sum(f['risk'] for f in api_findings)
        avg_risk = total_risk / len(api_findings)
        max_risk = max(f['risk'] for f in api_findings)

        # Risk level determination
        if max_risk >= 9:
            risk_level = "CRITICAL"
        elif max_risk >= 7:
            risk_level = "HIGH"
        elif max_risk >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        print(f"\n  Aggregate Risk Score: {total_risk}")
        print(f"  Average Risk: {avg_risk:.2f}")
        print(f"  Maximum Risk: {max_risk}")
        print(f"  Risk Level: {risk_level}")

        print(f"\n  Reasons:")
        for finding in api_findings[:3]:  # Top 3
            print(f"    - Found {finding['name']} (risk: {finding['risk']}): {finding['why_dangerous'][:50]}...")

    # ========================================================================
    # FINAL VERDICT
    # ========================================================================
    print("\n" + "=" * 70)
    print("INTEGRATION TEST RESULTS")
    print("=" * 70)

    if len(api_findings) > 0 and all_valid:
        print("\n[SUCCESS] Integration test PASSED!")
        print(f"  [OK] Person 1's disassembly format: COMPATIBLE")
        print(f"  [OK] Person 2's scanner: WORKING")
        print(f"  [OK] Output format for Person 3: VALID")
        print(f"  [OK] Statistics generation: FUNCTIONAL")
        print(f"\n  Ready for Person 3 to implement risk_scorer.py")
    else:
        print("\n[FAILURE] Integration test FAILED!")
        print(f"  Findings count: {len(api_findings)}")
        print(f"  Format valid: {all_valid}")

    print("=" * 70)

    return api_findings, stats


if __name__ == "__main__":
    findings, stats = test_integration()
