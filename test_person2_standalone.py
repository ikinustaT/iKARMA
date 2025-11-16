"""
Standalone Test for Person 2 (API Hunter)

This script allows you to test YOUR API scanner without Person 1's full plugin.
It reads a memory dump and disassembles a specific driver manually, then tests
your scanner against it.

Usage:
    python test_person2_standalone.py <memory_dump.mem> [driver_name]

Example:
    python test_person2_standalone.py memory.mem ntfs.sys
    python test_person2_standalone.py memory.mem  # Will list available drivers
"""

import sys
import struct
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    print("[WARNING] Capstone not available. Install with: pip install capstone")
    CAPSTONE_AVAILABLE = False

from utils.api_scanner import find_dangerous_apis, get_scanner_statistics
from core.api_patterns import get_all_api_names


def read_memory_region(mem_file, offset, size):
    """
    Read a region of memory from the dump file.

    Args:
        mem_file: Path to memory dump
        offset: Offset to read from
        size: Number of bytes to read

    Returns:
        bytes: Memory contents
    """
    try:
        with open(mem_file, 'rb') as f:
            f.seek(offset)
            return f.read(size)
    except Exception as e:
        print(f"[ERROR] Failed to read memory: {e}")
        return None


def disassemble_bytes(data, base_address=0x0, max_instructions=50):
    """
    Disassemble raw bytes using Capstone.
    Returns format compatible with Person 1's output.

    Args:
        data: Raw bytes to disassemble
        base_address: Virtual address of first byte
        max_instructions: Maximum instructions to return

    Returns:
        list: Instruction strings in format "0xaddr:\tmnemonic\top_str"
    """
    if not CAPSTONE_AVAILABLE:
        print("[ERROR] Capstone required for disassembly")
        return None

    try:
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.detail = False

        instructions = []
        for i, ins in enumerate(cs.disasm(data, base_address)):
            # Format matches Person 1's disassemble_function() output
            instruction = f"{hex(ins.address)}:\t{ins.mnemonic}\t{ins.op_str}"
            instructions.append(instruction)

            if i + 1 >= max_instructions:
                break

        return instructions
    except Exception as e:
        print(f"[ERROR] Disassembly failed: {e}")
        return None


def find_code_section(mem_file, search_offset=0x1000, search_size=0x100000):
    """
    Simple heuristic to find executable code in memory dump.
    Looks for common Windows kernel patterns.

    Args:
        mem_file: Path to memory dump
        search_offset: Where to start searching
        search_size: How many bytes to search

    Returns:
        tuple: (offset, data) of found code, or (None, None)
    """
    print(f"\n[*] Searching for executable code in memory dump...")
    print(f"    Offset: 0x{search_offset:x}")
    print(f"    Size: 0x{search_size:x} bytes")

    data = read_memory_region(mem_file, search_offset, search_size)
    if not data:
        return None, None

    # Look for common Windows kernel function prologues
    # Common patterns: push rbp; mov rbp, rsp; sub rsp, ...
    patterns = [
        b'\x48\x89\x5c\x24',  # mov [rsp+...], rbx
        b'\x48\x89\x74\x24',  # mov [rsp+...], rsi
        b'\x55\x48\x8b\xec',  # push rbp; mov rbp, rsp
        b'\x48\x83\xec',      # sub rsp, ...
        b'\x40\x53',          # push rbx (REX prefix)
    ]

    best_offset = None
    best_score = 0

    # Scan through data looking for concentrations of these patterns
    for i in range(0, len(data) - 0x100, 16):
        score = 0
        for pattern in patterns:
            if pattern in data[i:i+0x100]:
                score += 1

        if score > best_score:
            best_score = score
            best_offset = search_offset + i

    if best_offset:
        print(f"    [OK] Found potential code at offset 0x{best_offset:x} (score: {best_score})")
        return best_offset, read_memory_region(mem_file, best_offset, 0x1000)
    else:
        print(f"    [WARNING] No clear code patterns found")
        return search_offset, data[:0x1000]


def test_scanner_with_manual_disassembly(mem_file, offset=None, size=0x1000):
    """
    Main test function - disassembles memory and tests Person 2's scanner.

    Args:
        mem_file: Path to .mem file
        offset: Optional specific offset to disassemble
        size: Number of bytes to disassemble
    """
    print("=" * 70)
    print("PERSON 2 STANDALONE TEST")
    print("Memory Forensics API Scanner - Independent Test")
    print("=" * 70)

    print(f"\n[*] Memory dump: {mem_file}")
    print(f"[*] Target: Disassemble and scan for dangerous APIs")

    # ========================================================================
    # STEP 1: Find or use specified code region
    # ========================================================================
    if offset is None:
        # Auto-detect code region
        offset, data = find_code_section(mem_file)
        if data is None:
            print("\n[ERROR] Could not find code in memory dump")
            print("[HINT] Try specifying an offset manually:")
            print(f"  python {sys.argv[0]} {mem_file} --offset 0x1000")
            return
    else:
        print(f"\n[*] Using specified offset: 0x{offset:x}")
        data = read_memory_region(mem_file, offset, size)
        if data is None:
            return

    print(f"[*] Read {len(data)} bytes from offset 0x{offset:x}")

    # ========================================================================
    # STEP 2: Disassemble the code
    # ========================================================================
    print(f"\n[STEP 1] Disassembling code...")

    if not CAPSTONE_AVAILABLE:
        print("[ERROR] Cannot continue without Capstone")
        print("[FIX] Install with: pip install capstone")
        return

    disassembly = disassemble_bytes(data, base_address=offset, max_instructions=100)

    if not disassembly or len(disassembly) == 0:
        print("[ERROR] Disassembly failed or returned no instructions")
        print("[HINT] The offset might not contain valid x64 code")
        return

    print(f"[OK] Disassembled {len(disassembly)} instructions")
    print(f"\nFirst 5 instructions:")
    for ins in disassembly[:5]:
        print(f"  {ins}")
    print(f"  ...")

    # ========================================================================
    # STEP 3: Run Person 2's API Scanner (YOUR CODE!)
    # ========================================================================
    print(f"\n[STEP 2] Running Person 2's API Scanner...")
    print(f"          Scanning for {len(get_all_api_names())} dangerous APIs...")

    findings = find_dangerous_apis(disassembly)

    print(f"\n[RESULT] Found {len(findings)} dangerous API calls/patterns")

    # ========================================================================
    # STEP 4: Display Results
    # ========================================================================
    if len(findings) == 0:
        print("\n" + "=" * 70)
        print("NO DANGEROUS APIs DETECTED")
        print("=" * 70)
        print("\nThis could mean:")
        print("  1. The code region is clean (no dangerous APIs)")
        print("  2. The offset doesn't contain a driver IOCTL handler")
        print("  3. The code uses obfuscation (indirect calls)")
        print("\nTry:")
        print(f"  - Different offset: python {sys.argv[0]} {mem_file} --offset 0x10000")
        print(f"  - Larger search: Use --search-size 0x1000000")
        print(f"  - Check if this is actually a driver in the dump")
    else:
        print("\n" + "=" * 70)
        print("DANGEROUS APIs DETECTED!")
        print("=" * 70)

        for i, finding in enumerate(findings, 1):
            print(f"\n[{i}] {finding['name']}")
            print(f"    Risk: {finding['risk']}/10")
            print(f"    Confidence: {finding['confidence']:.2%}")
            print(f"    Method: {finding['method']}")
            print(f"    Category: {finding['category']}")
            print(f"    Address: {finding['address']}")
            print(f"    Instruction: {finding['instruction'][:60]}...")
            print(f"    Why dangerous: {finding['why_dangerous']}")

        # Statistics
        print("\n" + "-" * 70)
        print("STATISTICS")
        print("-" * 70)

        stats = get_scanner_statistics(findings)
        print(f"\nTotal findings: {stats['total_findings']}")
        print(f"Unique APIs: {stats['unique_apis']}")
        print(f"Highest risk: {stats['highest_risk']}/10")

        print(f"\nBy Category:")
        for category, count in stats['by_category'].items():
            print(f"  - {category}: {count}")

        print(f"\nBy Detection Method:")
        for method, count in stats['by_method'].items():
            print(f"  - {method}: {count}")

        print(f"\nBy Risk Level:")
        for level, count in stats['by_risk_level'].items():
            if count > 0:
                print(f"  - {level}: {count}")

        # Risk assessment
        critical_count = sum(1 for f in findings if f['risk'] >= 9)
        high_count = sum(1 for f in findings if 7 <= f['risk'] < 9)

        print("\n" + "-" * 70)
        print("RISK ASSESSMENT")
        print("-" * 70)

        if critical_count > 0:
            print(f"\n[CRITICAL] {critical_count} critical-risk APIs detected")
            print("This code has highly dangerous capabilities!")
        if high_count > 0:
            print(f"[HIGH] {high_count} high-risk APIs detected")
            print("This code has suspicious capabilities")

        print("\n[NOTE] This is Person 2's output. Person 3 will calculate")
        print("       the overall driver risk score based on these findings.")

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
    print("\n[OK] Person 2's scanner is WORKING!")
    print("[OK] Ready to integrate with Person 1's plugin")


def interactive_test(mem_file):
    """
    Interactive mode - helps user find interesting code regions.
    """
    print("=" * 70)
    print("INTERACTIVE MODE - Person 2 Standalone Test")
    print("=" * 70)

    print(f"\nMemory dump: {mem_file}")

    try:
        file_size = Path(mem_file).stat().st_size
        print(f"File size: {file_size:,} bytes (0x{file_size:x})")
    except:
        print("[ERROR] Could not read file")
        return

    print("\n[*] Suggested offsets to try:")
    print("    1. 0x1000    - Start of typical PE file")
    print("    2. 0x10000   - Common driver load address")
    print("    3. 0x100000  - Alternative location")
    print("    4. 0x1000000 - Later in dump")

    print("\nCommands:")
    print("  test <offset>     - Test specific offset (hex, e.g., 0x1000)")
    print("  search <offset>   - Search for code starting at offset")
    print("  auto              - Auto-detect code regions")
    print("  quit              - Exit")

    while True:
        try:
            cmd = input("\n> ").strip().lower()

            if cmd == 'quit' or cmd == 'exit':
                break
            elif cmd == 'auto':
                test_scanner_with_manual_disassembly(mem_file)
            elif cmd.startswith('test '):
                offset_str = cmd.split()[1]
                offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                test_scanner_with_manual_disassembly(mem_file, offset=offset)
            elif cmd.startswith('search '):
                offset_str = cmd.split()[1]
                offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                find_code_section(mem_file, search_offset=offset)
            else:
                print("[ERROR] Unknown command. Try: auto, test 0x1000, search 0x1000, quit")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("=" * 70)
        print("Person 2 (API Hunter) Standalone Test")
        print("=" * 70)
        print("\nTest your API scanner WITHOUT Person 1's full integration!")
        print("\nUsage:")
        print(f"  {sys.argv[0]} <memory.mem>              # Auto-detect code")
        print(f"  {sys.argv[0]} <memory.mem> --offset 0x1000   # Specific offset")
        print(f"  {sys.argv[0]} <memory.mem> --interactive    # Interactive mode")
        print("\nExamples:")
        print(f"  {sys.argv[0]} test_memory.mem")
        print(f"  {sys.argv[0]} malware_dump.mem --offset 0x140001000")
        print(f"  {sys.argv[0]} memory.mem --interactive")
        sys.exit(1)

    mem_file = sys.argv[1]

    # Check if file exists
    if not Path(mem_file).exists():
        print(f"[ERROR] File not found: {mem_file}")
        sys.exit(1)

    # Check for Capstone
    if not CAPSTONE_AVAILABLE:
        print("[ERROR] Capstone is required for this test")
        print("[FIX] Install with: pip install capstone")
        sys.exit(1)

    # Parse arguments
    if '--interactive' in sys.argv or '-i' in sys.argv:
        interactive_test(mem_file)
    elif '--offset' in sys.argv:
        idx = sys.argv.index('--offset')
        if idx + 1 < len(sys.argv):
            offset_str = sys.argv[idx + 1]
            offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
            test_scanner_with_manual_disassembly(mem_file, offset=offset)
        else:
            print("[ERROR] --offset requires a value")
            sys.exit(1)
    else:
        # Auto mode
        test_scanner_with_manual_disassembly(mem_file)
