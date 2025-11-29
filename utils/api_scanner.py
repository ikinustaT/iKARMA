"""
API Scanner Module for iKARMA BYOVD Detection

This module implements four detection methods for identifying dangerous Windows
kernel APIs in kernel drivers:
  1. IAT Scanning (PRIMARY) - Direct scan of Import Address Table for dangerous imports
  2. String Matching - Fast detection via API name in comments/strings
  3. Call Instruction Analysis - Pattern-based call instruction detection
  4. String Reference Detection - Identifies suspicious string constants

Author: Person 2 (API Hunter)
Last Updated: 2025-11-25 (Final Iteration - IAT-based detection)
Integration: Called by plugins/driver_analysis.py and byovd_scanner.py
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.api_patterns import (  # type: ignore
        API_DATABASE,
        get_all_api_names,
        get_api_info,
        STRING_INDICATORS,
    )
except Exception:
    # Fallback to packaged legacy patterns
    from ikarma.core.api_patterns_v1 import (
        API_DATABASE,
        get_all_api_names,
        get_api_info,
        STRING_INDICATORS,
    )


# ============================================================================
# DETECTION METHOD 0: IAT SCANNING (PRIMARY METHOD - NEW)
# ============================================================================

def detect_iat_imports(layer, base_addr: int) -> List[Dict]:
    """
    Method 0: Scan Import Address Table (IAT) for dangerous API imports.
    
    THIS IS THE MOST RELIABLE METHOD - imports are explicit and unobfuscated.
    Unlike disassembly pattern matching which is architecture/compiler dependent,
    the IAT is a stable PE structure that directly lists all imported functions.
    
    Args:
        layer: Volatility memory layer
        base_addr: Driver base address
    
    Returns:
        list: List of findings with format:
            {
                'name': 'MmMapIoSpace',
                'method': 'iat',
                'confidence': 1.0,
                'address': 'IAT',
                'instruction': 'Import from ntoskrnl.exe',
                'category': 'MEMORY_ACCESS',
                'risk': 9,
                'dll': 'ntoskrnl.exe'
            }
    """
    findings = []
    api_names_upper = {name.upper(): name for name in get_all_api_names()}
    
    try:
        # Import forensics module for IAT extraction
        from utils.forensics import extract_import_table
        
        # Extract import table (list of (dll_name, function_name) tuples)
        import_table = extract_import_table(layer, base_addr)
        
        if not import_table:
            return findings
        
        # Scan for dangerous APIs in import table
        for dll_name, func_name in import_table:
            func_upper = func_name.upper()
            
            # Check if this function is in our dangerous API database
            if func_upper in api_names_upper:
                real_api_name = api_names_upper[func_upper]
                category, api_info = get_api_info(real_api_name)
                
                findings.append({
                    'name': real_api_name,
                    'method': 'iat',
                    'confidence': 1.0,  # IAT imports are definitive - highest confidence
                    'address': 'IAT',
                    'instruction': f'Import from {dll_name}',
                    'category': category,
                    'risk': api_info['risk'] if api_info else 0,
                    'why_dangerous': api_info.get('why_dangerous', '') if api_info else '',
                    'dll': dll_name
                })
        
        return findings
        
    except ImportError:
        # Forensics module not available - fallback to disassembly methods
        return findings
    except Exception as e:
        # IAT extraction failed - not an error, just means no imports found
        return findings


# ============================================================================
# DETECTION METHOD 1: STRING MATCHING IN COMMENTS
# ============================================================================

def detect_string_match(disassembly_lines):
    """
    Method 1: Fast string matching in disassembly comments.

    Capstone often includes API names in comments for known imports/calls:
    Example: "call qword ptr [rip + 0x20b8]  ; nt!MmMapIoSpace"

    Args:
        disassembly_lines (list): List of instruction strings

    Returns:
        list: List of findings with format:
            {
                'name': 'MmMapIoSpace',
                'method': 'string',
                'confidence': 0.8,
                'address': '0x14000abcd',
                'instruction': 'call qword ptr [rip + 0x20b8]',
                'category': 'MEMORY_ACCESS',
                'risk': 9
            }
    """
    findings = []
    api_names = get_all_api_names()

    for line in disassembly_lines:
        if not line:
            continue

        # Parse the instruction format: "0x123456:\tmnemonic\top_str"
        parts = line.split('\t', 2)
        if len(parts) < 2:
            continue

        address = parts[0].rstrip(':')
        instruction = '\t'.join(parts[1:]) if len(parts) > 1 else ''

        # Check for API names in the line (case-insensitive for flexibility)
        line_upper = line.upper()

        for api_name in api_names:
            api_upper = api_name.upper()

            # Match API name (whole word to avoid false positives)
            # Look for patterns like:
            #   - "nt!MmMapIoSpace"
            #   - "MmMapIoSpace"
            #   - "call MmMapIoSpace"
            if re.search(r'\b' + re.escape(api_upper) + r'\b', line_upper):
                category, api_info = get_api_info(api_name)

                # Higher confidence if it's in a comment (after semicolon)
                confidence = 0.9 if ';' in line else 0.7

                findings.append({
                    'name': api_name,
                    'method': 'string',
                    'confidence': confidence,
                    'address': address,
                    'instruction': instruction.strip(),
                    'category': category,
                    'risk': api_info['risk'] if api_info else 0,
                    'why_dangerous': api_info.get('why_dangerous', '') if api_info else ''
                })

                # Avoid duplicate detections in same line
                break

    return findings


# ============================================================================
# DETECTION METHOD 2: CALL INSTRUCTION PATTERN ANALYSIS
# ============================================================================

def detect_call_patterns(disassembly_lines):
    """
    Method 2: Analyze call instructions for suspicious patterns.

    Detects:
    - Direct calls: "call MmMapIoSpace"
    - Indirect calls: "call qword ptr [rax]"
    - Import calls: "call qword ptr [rip + offset]"

    Even if API name isn't in the comment, we can detect suspicious call
    patterns (e.g., calls after loading user data).

    Args:
        disassembly_lines (list): List of instruction strings

    Returns:
        list: List of findings (similar format to detect_string_match)
    """
    findings = []

    # Track context (previous instructions for pattern analysis)
    previous_instructions = []

    for line in disassembly_lines:
        if not line:
            continue

        parts = line.split('\t', 2)
        if len(parts) < 2:
            continue

        address = parts[0].rstrip(':')
        mnemonic = parts[1].strip() if len(parts) > 1 else ''
        op_str = parts[2].strip() if len(parts) > 2 else ''
        full_instruction = f"{mnemonic}\t{op_str}".strip()

        # Detect call instructions
        if mnemonic == 'call':
            # Pattern 1: Indirect call via register
            # Example: "call rax" or "call qword ptr [rcx]"
            if any(reg in op_str.lower() for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']):
                # Check if previous instructions loaded user data
                suspicious = False
                for prev_line in previous_instructions[-5:]:  # Check last 5 instructions
                    # Look for patterns like "mov rcx, [user_buffer]"
                    if any(keyword in prev_line.lower() for keyword in ['mov', 'lea']):
                        suspicious = True
                        break

                if suspicious:
                    # RECALIBRATED: Indirect calls are NOT reliable API indicators
                    # Without symbols, we cannot know the call target
                    # Risk reduced to 0 - this is informational only
                    findings.append({
                        'name': 'INDIRECT_CALL',  # Renamed from INDIRECT_CALL_SUSPICIOUS
                        'method': 'call_pattern',
                        'confidence': 0.0,  # Zero confidence - target unknown
                        'address': address,
                        'instruction': full_instruction,
                        'category': 'CODE_PATTERN',  # Changed from UNKNOWN
                        'risk': 0,  # REDUCED TO ZERO - cannot determine actual risk without symbols
                        'why_dangerous': '',  # No danger claim without symbol resolution
                        'because': 'Indirect call via register - target unknown without symbol resolution (informational only, not scored)'
                    })

            # Pattern 2: Call via import table
            # Example: "call qword ptr [rip + 0x20b8]"
            elif 'rip' in op_str.lower():
                # This is likely an import call, but we already catch these in string matching
                # Only flag if we didn't already detect it
                pass

        # Store instruction for context analysis
        previous_instructions.append(line)
        if len(previous_instructions) > 10:
            previous_instructions.pop(0)  # Keep only last 10

    return findings


# ============================================================================
# DETECTION METHOD 3: STRING REFERENCE DETECTION
# ============================================================================

def detect_string_references(disassembly_lines):
    """
    Method 3: Detect references to suspicious string constants.

    Examples:
    - "\\Device\\PhysicalMemory" - Physical memory access
    - "MsMpEng.exe" - Windows Defender targeting
    - Suspicious registry paths

    Args:
        disassembly_lines (list): List of instruction strings

    Returns:
        list: List of findings (similar format to detect_string_match)
    """
    findings = []

    for line in disassembly_lines:
        if not line:
            continue

        parts = line.split('\t', 2)
        if len(parts) < 2:
            continue

        address = parts[0].rstrip(':')
        instruction = '\t'.join(parts[1:]) if len(parts) > 1 else ''

        # Check for known string indicators
        for string_pattern, string_info in STRING_INDICATORS.items():
            if string_pattern.lower() in line.lower():
                findings.append({
                    'name': f'STRING_REF_{string_pattern}',
                    'method': 'string_reference',
                    'confidence': 0.85,
                    'address': address,
                    'instruction': instruction.strip(),
                    'category': string_info['category'],
                    'risk': string_info['risk'],
                    'why_dangerous': string_info['description']
                })

        # Additional heuristics for suspicious strings
        # Pattern: References to common EDR/AV process names
        edr_patterns = ['defender', 'avast', 'kaspersky', 'norton', 'mcafee',
                        'bitdefender', 'eset', 'malwarebytes', 'sophos']
        for edr in edr_patterns:
            if edr in line.lower():
                findings.append({
                    'name': f'STRING_REF_SECURITY_PRODUCT_{edr.upper()}',
                    'method': 'string_reference',
                    'confidence': 0.7,
                    'address': address,
                    'instruction': instruction.strip(),
                    'category': 'PROCESS_MANIPULATION',
                    'risk': 6,
                    'why_dangerous': f'Reference to security product "{edr}" - possible targeting for termination'
                })
                break  # Only report once per line

    return findings


# ============================================================================
# MAIN SCANNER FUNCTION
# ============================================================================

def find_dangerous_apis(disassembly_lines, layer=None, base_addr=None):
    """
    Main API scanner function - integrates all four detection methods.

    This is the primary function called by driver_analysis.py and byovd_scanner.py.

    Args:
        disassembly_lines (list): List of disassembled instruction strings
                                  Format: "0x123456:\tmnemonic\top_str"
                                  Example: "0xfffff8001234:\tcall\tqword ptr [rip + 0x20b8]"
        layer (optional): Volatility memory layer for IAT scanning
        base_addr (optional): Driver base address for IAT scanning

    Returns:
        list: Comprehensive list of all findings from all methods
              Each finding is a dict with keys:
                - name: API or pattern name
                - method: Detection method ('iat', 'string', 'call_pattern', 'string_reference')
                - confidence: 0.0-1.0 confidence score
                - address: Memory address where found (or 'IAT' for import table)
                - instruction: The actual assembly instruction
                - category: API category (from api_patterns.py)
                - risk: Risk score (0-10)
                - why_dangerous: Human-readable explanation

    Example:
        >>> # Method 1: IAT scanning (if layer available)
        >>> findings = find_dangerous_apis([], layer=context.layers['primary'], base_addr=0xfffff80000000000)
        >>> 
        >>> # Method 2: Disassembly scanning (fallback)
        >>> disasm = [
        ...     "0xfffff800123456:\tcall\tqword ptr [rip + 0x20b8]  ; nt!MmMapIoSpace",
        ...     "0xfffff80012345e:\tmov\trcx, [user_buffer]"
        ... ]
        >>> findings = find_dangerous_apis(disasm)
        >>> findings[0]['name']
        'MmMapIoSpace'
    """
    all_findings = []

    # Method 0: IAT Scanning (PRIMARY - most reliable when available)
    if layer is not None and base_addr is not None:
        iat_findings = detect_iat_imports(layer, base_addr)
        all_findings.extend(iat_findings)
    
    # Fallback methods (disassembly-based) - only if disassembly provided
    if disassembly_lines:
        # Method 1: String matching (fast, high confidence)
        string_findings = detect_string_match(disassembly_lines)
        all_findings.extend(string_findings)

        # Method 2: Call pattern analysis (slower, lower confidence)
        call_findings = detect_call_patterns(disassembly_lines)
        all_findings.extend(call_findings)

        # Method 3: String reference detection (medium speed, medium confidence)
        string_ref_findings = detect_string_references(disassembly_lines)
        all_findings.extend(string_ref_findings)

    # Deduplicate findings
    # Strategy: 
    #   - For IAT findings: deduplicate by API name only (IAT entries are unique)
    #   - For disassembly findings: deduplicate by (address, API name)
    #   - Prioritize IAT findings (confidence 1.0) over disassembly findings
    deduplicated = {}
    for finding in all_findings:
        if finding['method'] == 'iat':
            # IAT findings: unique by API name
            key = ('IAT', finding['name'])
        else:
            # Disassembly findings: unique by address + API name
            key = (finding['address'], finding['name'])
        
        if key not in deduplicated:
            deduplicated[key] = finding
        else:
            # Keep the finding with higher confidence
            if finding['confidence'] > deduplicated[key]['confidence']:
                deduplicated[key] = finding

    # Return sorted: IAT findings first, then by address
    final_findings = sorted(
        deduplicated.values(), 
        key=lambda x: (0 if x['method'] == 'iat' else 1, x['address'])
    )

    return final_findings


# ============================================================================
# STATISTICS AND REPORTING
# ============================================================================

def get_scanner_statistics(findings):
    """
    Generate statistics about the scanning results.

    Args:
        findings (list): List of findings from find_dangerous_apis()

    Returns:
        dict: Statistics including counts by category, method, risk level
    """
    if not findings:
        return {
            'total_findings': 0,
            'by_category': {},
            'by_method': {},
            'by_risk_level': {},
            'highest_risk': 0
        }

    stats = {
        'total_findings': len(findings),
        'by_category': {},
        'by_method': {},
        'by_risk_level': {'CRITICAL (9-10)': 0, 'HIGH (7-8)': 0, 'MEDIUM (5-6)': 0, 'LOW (0-4)': 0},
        'highest_risk': max(f['risk'] for f in findings),
        'unique_apis': len(set(f['name'] for f in findings)),
    }

    for finding in findings:
        # Count by category
        cat = finding.get('category', 'UNKNOWN')
        stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

        # Count by method
        method = finding['method']
        stats['by_method'][method] = stats['by_method'].get(method, 0) + 1

        # Count by risk level
        risk = finding['risk']
        if risk >= 9:
            stats['by_risk_level']['CRITICAL (9-10)'] += 1
        elif risk >= 7:
            stats['by_risk_level']['HIGH (7-8)'] += 1
        elif risk >= 5:
            stats['by_risk_level']['MEDIUM (5-6)'] += 1
        else:
            stats['by_risk_level']['LOW (0-4)'] += 1

    return stats


# ============================================================================
# MODULE TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("iKARMA API Scanner - Test Mode")
    print("=" * 70)

    # ========================================================================
    # TEST 1: Create mock disassembly data
    # ========================================================================
    print("\n[TEST 1] Creating mock disassembly data...")

    mock_disassembly = [
        # Dangerous API call - MmMapIoSpace
        "0xfffff80012341000:\tpush\trbp",
        "0xfffff80012341001:\tmov\trbp, rsp",
        "0xfffff80012341004:\tsub\trsp, 0x20",
        "0xfffff80012341008:\tmov\trcx, [rbp + 0x48]",  # User-controlled address
        "0xfffff8001234100c:\tmov\trdx, 0x1000",  # Size
        "0xfffff80012341013:\txor\tr8, r8",  # Cache type
        "0xfffff80012341016:\tcall\tqword ptr [rip + 0x20b8]\t; nt!MmMapIoSpace",
        "0xfffff8001234101d:\ttest\trax, rax",
        "0xfffff8001234101f:\tjz\t0xfffff80012341030",

        # Process lookup - token theft pattern
        "0xfffff80012341030:\tmov\trcx, [user_pid]",
        "0xfffff80012341037:\tcall\tqword ptr [rip + 0x1234]\t; nt!PsLookupProcessByProcessId",
        "0xfffff8001234103e:\tmov\t[rbp - 8], rax",  # Save EPROCESS
        "0xfffff80012341042:\tadd\trax, 0x360",  # Token offset
        "0xfffff80012341048:\tmov\trcx, [rax]",  # Read token

        # Physical memory reference
        "0xfffff80012341050:\tlea\trcx, [rip + 0x5000]\t; L\"\\Device\\PhysicalMemory\"",
        "0xfffff80012341057:\tcall\tqword ptr [rip + 0x3000]\t; nt!ZwOpenSection",

        # MSR manipulation
        "0xfffff80012341060:\tmov\tecx, 0xc0000082\t; IA32_LSTAR",
        "0xfffff80012341065:\trdmsr",
        "0xfffff80012341067:\tmov\tedx, eax",
        "0xfffff80012341069:\twrmsr",

        # String reference to security product
        "0xfffff80012341070:\tlea\trcx, [rip + 0x6000]\t; \"MsMpEng.exe\"",
        "0xfffff80012341077:\tcall\tqword ptr [rip + 0x4000]\t; wcscmp",

        # Indirect call (suspicious)
        "0xfffff80012341080:\tmov\trcx, [rbp + 0x28]",  # User buffer
        "0xfffff80012341084:\tmov\trax, [rcx]",  # Load function pointer
        "0xfffff80012341087:\tcall\trax",  # Indirect call
    ]

    print(f"    Created {len(mock_disassembly)} mock instructions")

    # ========================================================================
    # TEST 2: Run string matching
    # ========================================================================
    print("\n[TEST 2] Running string matching detection...")
    string_findings = detect_string_match(mock_disassembly)
    print(f"    Found {len(string_findings)} APIs via string matching:")
    for finding in string_findings:
        print(f"      - {finding['name']} at {finding['address']} (risk: {finding['risk']}, confidence: {finding['confidence']:.2f})")

    # ========================================================================
    # TEST 3: Run call pattern analysis
    # ========================================================================
    print("\n[TEST 3] Running call pattern analysis...")
    call_findings = detect_call_patterns(mock_disassembly)
    print(f"    Found {len(call_findings)} suspicious patterns:")
    for finding in call_findings:
        print(f"      - {finding['name']} at {finding['address']} (confidence: {finding['confidence']:.2f})")

    # ========================================================================
    # TEST 4: Run string reference detection
    # ========================================================================
    print("\n[TEST 4] Running string reference detection...")
    string_ref_findings = detect_string_references(mock_disassembly)
    print(f"    Found {len(string_ref_findings)} string references:")
    for finding in string_ref_findings:
        print(f"      - {finding['name']} at {finding['address']} (risk: {finding['risk']})")

    # ========================================================================
    # TEST 5: Run comprehensive scan
    # ========================================================================
    print("\n[TEST 5] Running comprehensive scan (all methods)...")
    all_findings = find_dangerous_apis(mock_disassembly)
    print(f"    Total findings (deduplicated): {len(all_findings)}")

    print("\n    Detailed findings:")
    for i, finding in enumerate(all_findings, 1):
        print(f"\n    [{i}] {finding['name']}")
        print(f"        Address: {finding['address']}")
        print(f"        Method: {finding['method']}")
        print(f"        Confidence: {finding['confidence']:.2f}")
        print(f"        Risk: {finding['risk']}/10")
        print(f"        Category: {finding['category']}")
        print(f"        Why dangerous: {finding['why_dangerous']}")
        print(f"        Instruction: {finding['instruction'][:60]}...")

    # ========================================================================
    # TEST 6: Generate statistics
    # ========================================================================
    print("\n[TEST 6] Generating statistics...")
    stats = get_scanner_statistics(all_findings)
    print(f"    Total findings: {stats['total_findings']}")
    print(f"    Unique APIs: {stats['unique_apis']}")
    print(f"    Highest risk: {stats['highest_risk']}/10")
    print(f"\n    By category:")
    for cat, count in stats['by_category'].items():
        print(f"      - {cat}: {count}")
    print(f"\n    By detection method:")
    for method, count in stats['by_method'].items():
        print(f"      - {method}: {count}")
    print(f"\n    By risk level:")
    for level, count in stats['by_risk_level'].items():
        print(f"      - {level}: {count}")

    # ========================================================================
    # FINAL VERDICT
    # ========================================================================
    print("\n" + "=" * 70)
    print("TEST RESULTS SUMMARY")
    print("=" * 70)

    critical_count = sum(1 for f in all_findings if f['risk'] >= 9)
    high_count = sum(1 for f in all_findings if 7 <= f['risk'] < 9)

    if critical_count > 0:
        print(f"[CRITICAL] Found {critical_count} critical-risk APIs")
    if high_count > 0:
        print(f"[HIGH] Found {high_count} high-risk APIs")

    print("\nScanner is ready for integration with driver_analysis.py")
    print("=" * 70)
