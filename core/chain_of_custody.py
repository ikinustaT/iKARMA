"""
Chain of Custody and Forensic Audit Trail Module

This module implements chain of custody procedures and audit trail logging
to ensure legal admissibility of digital forensic evidence and analysis results.

Complies with:
- NIST SP 800-86 Section 3.1.3 (Examination) and 3.1.5 (Reporting)
- ISO/IEC 27037:2012 Section 7 (Documentation)
- ACPO Principle 3 (Audit trail of all processes)
- Federal Rules of Evidence (FRE) 901 (Authentication)

Author: iKARMA Forensic Team
Version: 1.0
Date: 2025-11-23
"""

import json
import logging
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

vollog = logging.getLogger(__name__)


# Version information for tool versioning
IKARMA_VERSION = "1.0.0"
MODULE_VERSION = "1.0"


@dataclass
class AnalystInfo:
    """Information about the forensic analyst conducting the investigation."""
    name: str
    id: str  # Badge number, employee ID, or unique identifier
    organization: Optional[str] = None
    certification: Optional[str] = None  # e.g., "EnCE", "GCFA", "CFCE"
    contact: Optional[str] = None

    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class CaseInfo:
    """Information about the forensic case or investigation."""
    case_id: str
    case_name: Optional[str] = None
    incident_date: Optional[str] = None
    evidence_number: Optional[str] = None
    description: Optional[str] = None
    investigation_type: Optional[str] = None  # e.g., "Incident Response", "Criminal", "Civil"

    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class EnvironmentInfo:
    """Information about the analysis environment."""
    hostname: str
    platform: str
    python_version: str
    tool_version: str
    volatility_version: Optional[str] = None
    capstone_version: Optional[str] = None
    working_directory: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AnalysisRecord:
    """Complete record of a forensic analysis session."""
    session_id: str
    start_timestamp: str
    case_info: CaseInfo
    analyst_info: AnalystInfo
    evidence_file: str
    evidence_hashes: Dict[str, str]
    command_line: str
    environment: EnvironmentInfo
    end_timestamp: Optional[str] = None
    status: str = "in_progress"  # "in_progress", "completed", "failed"
    audit_trail: List[Dict] = field(default_factory=list)
    results_summary: Optional[Dict] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = {
            'session_id': self.session_id,
            'start_timestamp': self.start_timestamp,
            'case_info': self.case_info.to_dict(),
            'analyst_info': self.analyst_info.to_dict(),
            'evidence_file': self.evidence_file,
            'evidence_hashes': self.evidence_hashes,
            'command_line': self.command_line,
            'environment': self.environment.to_dict(),
            'end_timestamp': self.end_timestamp,
            'status': self.status,
            'audit_trail': self.audit_trail,
            'results_summary': self.results_summary,
            'notes': self.notes
        }
        return data


class ChainOfCustody:
    """
    Manages chain of custody documentation and audit trail for forensic analysis.

    This class provides methods to:
    1. Initialize a forensic analysis session with case/analyst information
    2. Log all analysis actions to an audit trail
    3. Record evidence hashes for integrity verification
    4. Generate legally-admissible analysis reports
    5. Maintain complete documentation for court proceedings

    Example:
        >>> custody = ChainOfCustody(
        ...     case_id="IR-2025-001",
        ...     analyst_name="John Doe",
        ...     analyst_id="12345"
        ... )
        >>> custody.start_analysis(
        ...     evidence_file="memory.dmp",
        ...     evidence_hashes={'sha256': '...'}
        ... )
        >>> custody.log_action("driver_enumeration", "Found 150 kernel drivers")
        >>> custody.complete_analysis(results={'drivers_analyzed': 150})
        >>> custody.save_record("case_IR-2025-001_analysis.json")
    """

    def __init__(self,
                 case_id: str,
                 analyst_name: str,
                 analyst_id: str,
                 case_name: Optional[str] = None,
                 analyst_org: Optional[str] = None,
                 analyst_cert: Optional[str] = None,
                 investigation_type: Optional[str] = None):
        """
        Initialize chain of custody tracker.

        Args:
            case_id: Unique case identifier (e.g., "IR-2025-001")
            analyst_name: Full name of forensic analyst
            analyst_id: Analyst's unique ID (badge, employee number)
            case_name: Optional case name/title
            analyst_org: Optional analyst organization
            analyst_cert: Optional analyst certifications (e.g., "EnCE, GCFA")
            investigation_type: Optional type (e.g., "Incident Response")
        """
        self.case_info = CaseInfo(
            case_id=case_id,
            case_name=case_name,
            investigation_type=investigation_type
        )

        self.analyst_info = AnalystInfo(
            name=analyst_name,
            id=analyst_id,
            organization=analyst_org,
            certification=analyst_cert
        )

        self.session_id = None
        self.record = None

        vollog.info(f"Chain of Custody initialized for case: {case_id}")
        vollog.info(f"Analyst: {analyst_name} (ID: {analyst_id})")

    def start_analysis(self,
                      evidence_file: str,
                      evidence_hashes: Dict[str, str],
                      command_line: Optional[str] = None) -> str:
        """
        Start a new analysis session and begin audit trail.

        Args:
            evidence_file: Path to evidence file being analyzed
            evidence_hashes: Dictionary of cryptographic hashes (md5, sha1, sha256)
            command_line: Optional command line used to start analysis

        Returns:
            Session ID (UUID format)

        Example:
            >>> session_id = custody.start_analysis(
            ...     evidence_file="/evidence/memory.dmp",
            ...     evidence_hashes={'sha256': 'abc123...', 'md5': 'def456...'},
            ...     command_line="vol3 -f memory.dmp windows.driver_analysis"
            ... )
        """
        import uuid

        # Generate unique session ID
        self.session_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc).isoformat()

        # Get command line if not provided
        if command_line is None:
            command_line = ' '.join(sys.argv)

        # Collect environment information
        environment = self._collect_environment_info()

        # Create analysis record
        self.record = AnalysisRecord(
            session_id=self.session_id,
            start_timestamp=start_time,
            case_info=self.case_info,
            analyst_info=self.analyst_info,
            evidence_file=evidence_file,
            evidence_hashes=evidence_hashes,
            command_line=command_line,
            environment=environment
        )

        # Log session start
        self.log_action(
            action="session_start",
            description=f"Analysis session started for evidence: {Path(evidence_file).name}",
            details={'evidence_sha256': evidence_hashes.get('sha256')}
        )

        vollog.info(f"Analysis session started: {self.session_id}")
        vollog.info(f"Evidence: {evidence_file}")
        vollog.info(f"SHA256: {evidence_hashes.get('sha256')}")

        return self.session_id

    def log_action(self,
                  action: str,
                  description: str,
                  details: Optional[Dict] = None,
                  severity: str = "info"):
        """
        Log an action to the forensic audit trail.

        Args:
            action: Action type (e.g., "driver_enumeration", "api_detection")
            description: Human-readable description of action
            details: Optional dictionary with additional details
            severity: Severity level ("debug", "info", "warning", "error")

        Example:
            >>> custody.log_action(
            ...     action="dangerous_api_detected",
            ...     description="Found MmMapIoSpace in driver rtcore64.sys",
            ...     details={'api': 'MmMapIoSpace', 'risk': 9, 'driver': 'rtcore64.sys'},
            ...     severity="warning"
            ... )
        """
        if self.record is None:
            vollog.warning("Attempted to log action before starting analysis session")
            return

        audit_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'description': description,
            'severity': severity
        }

        if details:
            audit_entry['details'] = details

        self.record.audit_trail.append(audit_entry)

        # Also log to volatility logger
        log_func = getattr(vollog, severity, vollog.info)
        log_func(f"[AUDIT] {action}: {description}")

    def add_note(self, note: str):
        """
        Add a note to the analysis record.

        Notes are analyst observations that may be relevant for reporting
        or court testimony.

        Args:
            note: Text note to add

        Example:
            >>> custody.add_note(
            ...     "Driver rtcore64.sys has custom IOCTL handler at 0x14000abcd. "
            ...     "This is unusual for a signed driver and warrants further investigation."
            ... )
        """
        if self.record is None:
            vollog.warning("Attempted to add note before starting analysis session")
            return

        timestamped_note = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'note': note
        }
        self.record.notes.append(timestamped_note)
        vollog.info(f"[NOTE] {note}")

    def complete_analysis(self,
                         results_summary: Optional[Dict] = None,
                         status: str = "completed"):
        """
        Mark analysis as complete and finalize audit trail.

        Args:
            results_summary: Optional dictionary summarizing analysis results
            status: Final status ("completed", "failed", "interrupted")

        Example:
            >>> custody.complete_analysis(
            ...     results_summary={
            ...         'total_drivers': 150,
            ...         'high_risk_drivers': 3,
            ...         'critical_findings': 1
            ...     },
            ...     status="completed"
            ... )
        """
        if self.record is None:
            vollog.error("Cannot complete analysis - no session started")
            return

        self.record.end_timestamp = datetime.now(timezone.utc).isoformat()
        self.record.status = status
        self.record.results_summary = results_summary

        self.log_action(
            action="session_complete",
            description=f"Analysis session completed with status: {status}",
            details=results_summary
        )

        # Calculate duration
        start = datetime.fromisoformat(self.record.start_timestamp)
        end = datetime.fromisoformat(self.record.end_timestamp)
        duration = (end - start).total_seconds()

        vollog.info(f"Analysis session completed: {self.session_id}")
        vollog.info(f"Duration: {duration:.2f} seconds")
        vollog.info(f"Status: {status}")

    def save_record(self, output_path: str):
        """
        Save the complete chain of custody record to a JSON file.

        This file should be preserved with case files and can be used as
        evidence documentation in legal proceedings.

        Args:
            output_path: Path where JSON record should be saved

        Raises:
            ValueError: If analysis session not started
            IOError: If file cannot be written

        Example:
            >>> custody.save_record("case_IR-2025-001_session_abc123.json")
        """
        if self.record is None:
            raise ValueError("Cannot save record - no analysis session started")

        output_path = Path(output_path)

        try:
            with open(output_path, 'w') as f:
                json.dump(self.record.to_dict(), f, indent=2, sort_keys=True)

            vollog.info(f"Chain of custody record saved: {output_path}")
            vollog.info(f"  Session ID: {self.session_id}")
            vollog.info(f"  Audit trail entries: {len(self.record.audit_trail)}")
            vollog.info(f"  Notes: {len(self.record.notes)}")

        except IOError as e:
            vollog.error(f"Failed to save chain of custody record: {e}")
            raise

    def _collect_environment_info(self) -> EnvironmentInfo:
        """
        Collect information about the analysis environment.

        Returns:
            EnvironmentInfo dataclass with system details
        """
        # Get Volatility version if available
        volatility_version = None
        try:
            import volatility3
            volatility_version = volatility3.__version__
        except (ImportError, AttributeError):
            pass

        # Get Capstone version if available
        capstone_version = None
        try:
            import capstone
            capstone_version = capstone.__version__
        except (ImportError, AttributeError):
            pass

        return EnvironmentInfo(
            hostname=platform.node(),
            platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
            python_version=sys.version.split()[0],
            tool_version=IKARMA_VERSION,
            volatility_version=volatility_version,
            capstone_version=capstone_version,
            working_directory=str(Path.cwd())
        )

    @staticmethod
    def load_record(record_path: str) -> Dict:
        """
        Load a previously saved chain of custody record.

        Args:
            record_path: Path to JSON record file

        Returns:
            Dictionary containing record data

        Raises:
            FileNotFoundError: If record file doesn't exist
            json.JSONDecodeError: If file is not valid JSON
        """
        record_path = Path(record_path)

        if not record_path.exists():
            raise FileNotFoundError(f"Chain of custody record not found: {record_path}")

        with open(record_path, 'r') as f:
            record = json.load(f)

        vollog.info(f"Loaded chain of custody record: {record_path}")
        vollog.info(f"  Case ID: {record['case_info']['case_id']}")
        vollog.info(f"  Session ID: {record['session_id']}")
        vollog.info(f"  Analyst: {record['analyst_info']['name']}")

        return record


# Command-line interface for testing and standalone use
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Chain of Custody Management Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Create a chain of custody record
  python -m core.chain_of_custody --case-id IR-2025-001 --analyst "John Doe" --analyst-id 12345

  # Load and display a record
  python -m core.chain_of_custody --load case_record.json
        '''
    )

    parser.add_argument('--case-id', help='Case identifier')
    parser.add_argument('--analyst', help='Analyst name')
    parser.add_argument('--analyst-id', help='Analyst ID')
    parser.add_argument('--case-name', help='Optional case name')
    parser.add_argument('--load', metavar='FILE', help='Load and display record')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='[%(levelname)s] %(message)s'
    )

    if args.load:
        # Load and display record
        try:
            record = ChainOfCustody.load_record(args.load)
            print(json.dumps(record, indent=2))
        except Exception as e:
            print(f"Error loading record: {e}")
            exit(1)

    elif args.case_id and args.analyst and args.analyst_id:
        # Create example record
        custody = ChainOfCustody(
            case_id=args.case_id,
            analyst_name=args.analyst,
            analyst_id=args.analyst_id,
            case_name=args.case_name
        )

        # Simulate an analysis session
        custody.start_analysis(
            evidence_file="/path/to/evidence.dmp",
            evidence_hashes={'sha256': 'example_hash_123456789abcdef'}
        )

        custody.log_action("example_action", "This is an example audit trail entry")
        custody.add_note("This is an example note")
        custody.complete_analysis(results_summary={'example': 'results'})

        output_file = f"example_record_{args.case_id}.json"
        custody.save_record(output_file)

        print(f"\n[SUCCESS] Example record created: {output_file}")

    else:
        parser.print_help()
