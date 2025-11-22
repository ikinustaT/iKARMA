"""
Forensic Evidence Integrity Verification Module

This module provides cryptographic hashing and integrity verification for memory
dumps to ensure chain of custody and evidence admissibility in legal proceedings.

Complies with:
- NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response)
- ISO/IEC 27037:2012 (Guidelines for digital evidence handling)
- ACPO Principles (Association of Chief Police Officers Digital Evidence)

Author: iKARMA Forensic Team
Version: 1.0
Date: 2025-11-23
"""

import hashlib
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple
import logging

vollog = logging.getLogger(__name__)


class ForensicIntegrityError(Exception):
    """Raised when evidence integrity verification fails."""
    pass


def calculate_file_hashes(file_path: str, algorithms: Optional[list] = None) -> Dict[str, str]:
    """
    Calculate cryptographic hashes of a file for integrity verification.

    Uses industry-standard hashing algorithms (MD5, SHA1, SHA256) to create
    a digital fingerprint of the evidence file. These hashes can be used to
    verify the file was not modified during analysis.

    Args:
        file_path: Absolute path to the file to hash
        algorithms: List of hash algorithms to use.
                   Default: ['md5', 'sha1', 'sha256']

    Returns:
        Dictionary mapping algorithm names to hex digest strings:
        {
            'md5': '5d41402abc4b2a76b9719d911017c592',
            'sha1': 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
            'sha256': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
            'file_size': 4567890,
            'timestamp': '2025-11-23T10:30:45.123456Z'
        }

    Raises:
        FileNotFoundError: If file_path does not exist
        PermissionError: If file cannot be read
        ForensicIntegrityError: If hashing fails

    Example:
        >>> hashes = calculate_file_hashes('memory.dmp')
        >>> print(f"SHA256: {hashes['sha256']}")
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256']

    # Validate file exists and is readable
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    if not file_path.is_file():
        raise ForensicIntegrityError(f"Path is not a file: {file_path}")

    # Initialize hash objects
    hash_objects = {}
    for algo in algorithms:
        try:
            hash_objects[algo] = hashlib.new(algo)
        except ValueError:
            vollog.warning(f"Unsupported hash algorithm: {algo}")
            continue

    if not hash_objects:
        raise ForensicIntegrityError("No valid hash algorithms specified")

    # Calculate hashes in chunks to handle large files efficiently
    chunk_size = 8192  # 8KB chunks
    file_size = file_path.stat().st_size

    vollog.info(f"Calculating integrity hashes for: {file_path.name} ({file_size:,} bytes)")

    try:
        with open(file_path, 'rb') as f:
            chunks_processed = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Update all hash objects
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)

                chunks_processed += 1

                # Progress logging for large files
                if chunks_processed % 10000 == 0:
                    bytes_processed = chunks_processed * chunk_size
                    percent = (bytes_processed / file_size) * 100 if file_size > 0 else 0
                    vollog.debug(f"Hashing progress: {percent:.1f}%")

    except IOError as e:
        raise ForensicIntegrityError(f"Failed to read file during hashing: {e}")

    # Collect results
    results = {}
    for algo, hash_obj in hash_objects.items():
        results[algo] = hash_obj.hexdigest()

    # Add metadata
    results['file_size'] = file_size
    results['timestamp'] = datetime.now(timezone.utc).isoformat()

    vollog.info(f"Integrity hashes calculated successfully")
    vollog.debug(f"  MD5:    {results.get('md5', 'N/A')}")
    vollog.debug(f"  SHA1:   {results.get('sha1', 'N/A')}")
    vollog.debug(f"  SHA256: {results.get('sha256', 'N/A')}")

    return results


def verify_file_integrity(file_path: str, expected_hashes: Dict[str, str]) -> Tuple[bool, Dict]:
    """
    Verify file integrity by comparing current hashes to expected values.

    This function is critical for maintaining chain of custody. It ensures
    that the evidence file was not modified between initial acquisition and
    current analysis.

    Args:
        file_path: Path to file to verify
        expected_hashes: Dictionary of expected hash values from initial acquisition

    Returns:
        Tuple of (verification_passed: bool, verification_details: dict)

        verification_details contains:
        {
            'verified': True/False,
            'mismatches': [],  # List of algorithms that didn't match
            'current_hashes': {...},
            'expected_hashes': {...},
            'timestamp': '...'
        }

    Example:
        >>> original = calculate_file_hashes('evidence.dmp')
        >>> # ... time passes ...
        >>> verified, details = verify_file_integrity('evidence.dmp', original)
        >>> if not verified:
        >>>     raise ForensicIntegrityError("Evidence tampering detected!")
    """
    vollog.info(f"Verifying integrity of: {file_path}")

    # Calculate current hashes
    algorithms = [k for k in expected_hashes.keys()
                  if k not in ['file_size', 'timestamp']]

    try:
        current_hashes = calculate_file_hashes(file_path, algorithms=algorithms)
    except Exception as e:
        return False, {
            'verified': False,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    # Compare hashes
    mismatches = []
    for algo in algorithms:
        if algo not in expected_hashes:
            continue

        expected = expected_hashes[algo]
        current = current_hashes.get(algo)

        if expected != current:
            mismatches.append({
                'algorithm': algo,
                'expected': expected,
                'current': current
            })
            vollog.error(f"Hash mismatch for {algo}!")
            vollog.error(f"  Expected: {expected}")
            vollog.error(f"  Current:  {current}")

    # Check file size
    if 'file_size' in expected_hashes:
        expected_size = expected_hashes['file_size']
        current_size = current_hashes['file_size']
        if expected_size != current_size:
            mismatches.append({
                'algorithm': 'file_size',
                'expected': expected_size,
                'current': current_size
            })
            vollog.error(f"File size mismatch!")
            vollog.error(f"  Expected: {expected_size:,} bytes")
            vollog.error(f"  Current:  {current_size:,} bytes")

    verified = len(mismatches) == 0

    if verified:
        vollog.info("Integrity verification PASSED - Evidence is authentic")
    else:
        vollog.error(f"Integrity verification FAILED - {len(mismatches)} mismatches detected")
        vollog.error("POTENTIAL EVIDENCE TAMPERING - DO NOT PROCEED WITH ANALYSIS")

    return verified, {
        'verified': verified,
        'mismatches': mismatches,
        'current_hashes': current_hashes,
        'expected_hashes': expected_hashes,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


def create_integrity_record(file_path: str,
                           output_path: Optional[str] = None,
                           metadata: Optional[Dict] = None) -> str:
    """
    Create a forensic integrity record file for evidence documentation.

    This creates a JSON file containing cryptographic hashes and metadata
    about the evidence file. This record should be maintained throughout
    the investigation and included in final reports.

    Args:
        file_path: Path to evidence file
        output_path: Optional path for integrity record file.
                    Default: {file_path}.integrity.json
        metadata: Optional additional metadata (case ID, analyst, etc.)

    Returns:
        Path to created integrity record file

    Example:
        >>> record_path = create_integrity_record(
        ...     'memory.dmp',
        ...     metadata={'case_id': 'IR-2025-001', 'analyst': 'John Doe'}
        ... )
    """
    file_path = Path(file_path)

    if output_path is None:
        output_path = file_path.with_suffix(file_path.suffix + '.integrity.json')
    else:
        output_path = Path(output_path)

    vollog.info(f"Creating integrity record for: {file_path.name}")

    # Calculate hashes
    hashes = calculate_file_hashes(str(file_path))

    # Build integrity record
    record = {
        'integrity_record_version': '1.0',
        'evidence_file': {
            'path': str(file_path.absolute()),
            'filename': file_path.name,
            'size_bytes': hashes['file_size'],
            'acquisition_timestamp': hashes['timestamp']
        },
        'cryptographic_hashes': {
            'md5': hashes.get('md5'),
            'sha1': hashes.get('sha1'),
            'sha256': hashes.get('sha256')
        },
        'metadata': metadata or {},
        'verification_instructions': (
            'To verify integrity: python -m utils.forensic_integrity --verify '
            f'{file_path.name} {output_path.name}'
        )
    }

    # Write integrity record
    try:
        with open(output_path, 'w') as f:
            json.dump(record, f, indent=2, sort_keys=True)
        vollog.info(f"Integrity record created: {output_path}")
    except IOError as e:
        raise ForensicIntegrityError(f"Failed to write integrity record: {e}")

    return str(output_path)


def load_integrity_record(record_path: str) -> Dict:
    """
    Load a forensic integrity record from JSON file.

    Args:
        record_path: Path to .integrity.json file

    Returns:
        Dictionary containing integrity record data

    Raises:
        FileNotFoundError: If record file doesn't exist
        ForensicIntegrityError: If record file is invalid
    """
    record_path = Path(record_path)

    if not record_path.exists():
        raise FileNotFoundError(f"Integrity record not found: {record_path}")

    try:
        with open(record_path, 'r') as f:
            record = json.load(f)
    except json.JSONDecodeError as e:
        raise ForensicIntegrityError(f"Invalid integrity record format: {e}")
    except IOError as e:
        raise ForensicIntegrityError(f"Failed to read integrity record: {e}")

    # Validate required fields
    required_fields = ['evidence_file', 'cryptographic_hashes']
    for field in required_fields:
        if field not in record:
            raise ForensicIntegrityError(f"Integrity record missing required field: {field}")

    return record


# Command-line interface for standalone use
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Forensic Evidence Integrity Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Create integrity record for evidence file
  python -m utils.forensic_integrity --create memory.dmp

  # Verify file integrity against record
  python -m utils.forensic_integrity --verify memory.dmp memory.dmp.integrity.json

  # Calculate hashes only
  python -m utils.forensic_integrity --hash memory.dmp
        '''
    )

    parser.add_argument('--create', metavar='FILE',
                       help='Create integrity record for file')
    parser.add_argument('--verify', nargs=2, metavar=('FILE', 'RECORD'),
                       help='Verify file integrity against record')
    parser.add_argument('--hash', metavar='FILE',
                       help='Calculate and display file hashes')
    parser.add_argument('--case-id', help='Case ID for metadata')
    parser.add_argument('--analyst', help='Analyst name for metadata')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='[%(levelname)s] %(message)s'
    )

    # Execute requested operation
    try:
        if args.create:
            metadata = {}
            if args.case_id:
                metadata['case_id'] = args.case_id
            if args.analyst:
                metadata['analyst'] = args.analyst

            record_path = create_integrity_record(args.create, metadata=metadata)
            print(f"\n[SUCCESS] Integrity record created: {record_path}")
            print(f"\nNext steps:")
            print(f"  1. Preserve this integrity record with case files")
            print(f"  2. Before analysis, verify: python -m utils.forensic_integrity "
                  f"--verify {args.create} {record_path}")

        elif args.verify:
            file_path, record_path = args.verify

            # Load expected hashes
            record = load_integrity_record(record_path)
            expected_hashes = record['cryptographic_hashes']
            expected_hashes['file_size'] = record['evidence_file']['size_bytes']

            # Verify
            verified, details = verify_file_integrity(file_path, expected_hashes)

            if verified:
                print("\n[SUCCESS] Evidence integrity VERIFIED")
                print("  File has not been modified since integrity record was created")
                print(f"  SHA256: {details['current_hashes']['sha256']}")
            else:
                print("\n[FAILURE] Evidence integrity verification FAILED")
                print("  WARNING: Possible evidence tampering detected!")
                print(f"\n  Mismatches found: {len(details['mismatches'])}")
                for mismatch in details['mismatches']:
                    print(f"    {mismatch['algorithm']}:")
                    print(f"      Expected: {mismatch['expected']}")
                    print(f"      Current:  {mismatch['current']}")
                print("\n  DO NOT PROCEED WITH ANALYSIS - CONSULT FORENSIC SUPERVISOR")
                exit(1)

        elif args.hash:
            hashes = calculate_file_hashes(args.hash)
            print(f"\nFile: {args.hash}")
            print(f"Size: {hashes['file_size']:,} bytes")
            print(f"MD5:    {hashes.get('md5')}")
            print(f"SHA1:   {hashes.get('sha1')}")
            print(f"SHA256: {hashes.get('sha256')}")
            print(f"Timestamp: {hashes['timestamp']}")

        else:
            parser.print_help()
            exit(1)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        exit(1)
