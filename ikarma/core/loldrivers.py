"""
iKARMA LOLDrivers Matcher - Production Release

Matches drivers against the LOLDrivers database of known
vulnerable and abusable drivers.

Database sources:
- https://www.loldrivers.io/
- Embedded subset of known dangerous drivers
- Custom additions via configuration
"""

import logging
import hashlib
import json
from typing import Dict, Any, Optional, List
from pathlib import Path

from ikarma.core.driver import DriverInfo

logger = logging.getLogger(__name__)


# =============================================================================
# EMBEDDED LOLDRIVERS DATABASE (SUBSET)
# =============================================================================

# This is a subset of known vulnerable drivers from LOLDrivers
# Full database should be loaded from external file or API
EMBEDDED_LOLDRIVERS = [
    {
        "name": "RTCore64.sys",
        "hashes": {
            "md5": "2f9fb7c5a0b8e2e25df2c30f5e0aa9bc",
            "sha256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862f9c1c3aa6ffafa",
        },
        "description": "MSI Afterburner driver - arbitrary physical memory access",
        "cves": ["CVE-2019-16098"],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_READ", "PHYSICAL_MEMORY_WRITE"],
    },
    {
        "name": "dbutil_2_3.sys",
        "hashes": {
            "md5": "c996d7971c49252c582171d9380360f2",
            "sha256": "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
        },
        "description": "Dell BIOS driver - arbitrary kernel memory access",
        "cves": ["CVE-2021-21551"],
        "category": "vulnerable_driver",
        "capabilities": ["ARBITRARY_READ", "ARBITRARY_WRITE"],
    },
    {
        "name": "gdrv.sys",
        "hashes": {
            "md5": "9ab9f3b75a2eb87fafb1b7361be9dfb3",
            "sha256": "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427",
        },
        "description": "GIGABYTE driver - physical memory access",
        "cves": ["CVE-2018-19320"],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_READ", "PHYSICAL_MEMORY_WRITE", "MSR_READ", "MSR_WRITE"],
    },
    {
        "name": "asio64.sys",
        "hashes": {
            "md5": "b7b6d1339e89d9b2e66d9f6d13b7a2ed",
        },
        "description": "ASUS AI Suite driver - arbitrary memory access",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_MAP"],
    },
    {
        "name": "winring0x64.sys",
        "hashes": {
            "md5": "0c0195c48b6b8582fa6f6373032118da",
        },
        "description": "WinRing0 - direct hardware access driver",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PORT_IO_READ", "PORT_IO_WRITE", "MSR_READ", "MSR_WRITE"],
    },
    {
        "name": "cpuz141.sys",
        "aliases": ["cpuz.sys", "cpuz_x64.sys"],
        "hashes": {
            "md5": "2f045e2d6b68d3a71c0d7c90ced47c58",
        },
        "description": "CPU-Z driver - hardware access primitives",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PHYSICAL_MEMORY_READ", "MSR_READ"],
    },
    {
        "name": "aswarpot.sys",
        "hashes": {
            "md5": "a657b72e694f7c7b5d02de81ae14e7ab",
        },
        "description": "Avast anti-rootkit driver - abused for process termination",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PROCESS_TERMINATE"],
    },
    {
        "name": "procexp152.sys",
        "hashes": {},
        "description": "Process Explorer driver - process handle duplication",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PROCESS_HANDLE_DUP"],
    },
    {
        "name": "zemana.sys",
        "aliases": ["zam64.sys"],
        "hashes": {},
        "description": "Zemana AntiMalware driver - abused for callback removal",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["CALLBACK_REMOVAL"],
    },
    {
        "name": "ene.sys",
        "hashes": {
            "md5": "175f35ad2814d85cd7e7d09d90be49c7",
        },
        "description": "ENE Technology driver - physical memory access",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_MAP"],
    },
    {
        "name": "phymemx64.sys",
        "aliases": ["phymem.sys"],
        "hashes": {},
        "description": "Physical memory access driver",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_READ", "PHYSICAL_MEMORY_WRITE"],
    },
    {
        "name": "rwdrv.sys",
        "hashes": {},
        "description": "RWEverything driver - direct hardware access",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PORT_IO_READ", "PORT_IO_WRITE", "PHYSICAL_MEMORY_MAP"],
    },
    {
        "name": "inpoutx64.sys",
        "aliases": ["inpout32.sys"],
        "hashes": {},
        "description": "InpOut32 - direct I/O port access",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PORT_IO_READ", "PORT_IO_WRITE"],
    },
    {
        "name": "winio.sys",
        "aliases": ["winio64.sys"],
        "hashes": {},
        "description": "WinIO - direct I/O and memory access",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PORT_IO_READ", "PORT_IO_WRITE", "PHYSICAL_MEMORY_MAP"],
    },
    {
        "name": "speedfan.sys",
        "hashes": {},
        "description": "SpeedFan driver - hardware access",
        "cves": [],
        "category": "abusable_driver",
        "capabilities": ["PORT_IO_READ", "PORT_IO_WRITE", "MSR_READ"],
    },
    {
        "name": "amifldrv64.sys",
        "hashes": {},
        "description": "AMI BIOS flash driver - SMM/BIOS access",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_MAP", "MSR_WRITE"],
    },
    {
        "name": "nvflash64.sys",
        "hashes": {},
        "description": "NVIDIA flash driver",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_MAP"],
    },
    {
        "name": "atillk64.sys",
        "hashes": {},
        "description": "AMD ATI driver - physical memory access",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_MAP"],
    },
    {
        "name": "bs_def64.sys",
        "hashes": {},
        "description": "Biostar driver",
        "cves": [],
        "category": "vulnerable_driver",
        "capabilities": ["PHYSICAL_MEMORY_MAP", "MSR_READ", "MSR_WRITE"],
    },
    {
        "name": "driver7.sys",
        "hashes": {},
        "description": "Malware commonly uses this name",
        "cves": [],
        "category": "suspicious_name",
        "capabilities": [],
    },
]


class LOLDriversMatcher:
    """
    Matches drivers against known vulnerable/abusable driver databases.
    
    Matching is performed by:
    1. Exact hash match (most reliable)
    2. Name match (including aliases)
    3. Partial name match (with lower confidence)
    """
    
    def __init__(self, database_path: Optional[str] = None):
        """
        Initialize the matcher.
        
        Args:
            database_path: Optional path to external LOLDrivers JSON database
        """
        self.database_path = database_path
        self.database: List[Dict[str, Any]] = []
        
        # Lookup tables for fast matching
        self._md5_lookup: Dict[str, Dict] = {}
        self._sha256_lookup: Dict[str, Dict] = {}
        self._name_lookup: Dict[str, Dict] = {}
        self._alias_lookup: Dict[str, Dict] = {}
    
    def load_database(self) -> bool:
        """
        Load the LOLDrivers database.
        
        Tries external database first, falls back to embedded.
        
        Returns:
            True if loaded successfully
        """
        loaded = False
        
        # Try external database
        if self.database_path:
            try:
                external = self._load_external_database(self.database_path)
                if external:
                    self.database.extend(external)
                    loaded = True
                    logger.info(f"Loaded {len(external)} entries from external database")
            except Exception as e:
                logger.warning(f"Failed to load external database: {e}")
        
        # Add embedded database
        self.database.extend(EMBEDDED_LOLDRIVERS)
        logger.info(f"Loaded {len(EMBEDDED_LOLDRIVERS)} entries from embedded database")
        
        # Build lookup tables
        self._build_lookup_tables()
        
        return True
    
    def _load_external_database(self, path: str) -> List[Dict[str, Any]]:
        """Load external JSON database."""
        db_path = Path(path)
        
        if not db_path.exists():
            return []
        
        with open(db_path, 'r') as f:
            data = json.load(f)
        
        # Handle different database formats
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and 'drivers' in data:
            return data['drivers']
        
        return []
    
    def _build_lookup_tables(self):
        """Build hash and name lookup tables for fast matching."""
        for entry in self.database:
            # Hash lookups
            hashes = entry.get('hashes', {})
            
            if hashes.get('md5'):
                self._md5_lookup[hashes['md5'].lower()] = entry
            
            if hashes.get('sha256'):
                self._sha256_lookup[hashes['sha256'].lower()] = entry
            
            # Name lookups
            name = entry.get('name', '').lower()
            if name:
                self._name_lookup[name] = entry
                
                # Without extension
                base_name = name.replace('.sys', '')
                self._name_lookup[base_name] = entry
            
            # Alias lookups
            for alias in entry.get('aliases', []):
                alias_lower = alias.lower()
                self._alias_lookup[alias_lower] = entry
                
                base_alias = alias_lower.replace('.sys', '')
                self._alias_lookup[base_alias] = entry
    
    def match_driver(self, driver: DriverInfo) -> Optional[Dict[str, Any]]:
        """
        Match a driver against the database.
        
        Args:
            driver: DriverInfo to match
            
        Returns:
            Matching database entry or None
        """
        # Priority 1: MD5 hash match (highest confidence)
        if driver.md5_hash:
            md5_lower = driver.md5_hash.lower()
            if md5_lower in self._md5_lookup:
                match = self._md5_lookup[md5_lower].copy()
                match['match_type'] = 'md5_hash'
                match['match_confidence'] = 0.99
                return match
        
        # Priority 2: SHA256 hash match
        if driver.sha256_hash:
            sha256_lower = driver.sha256_hash.lower()
            if sha256_lower in self._sha256_lookup:
                match = self._sha256_lookup[sha256_lower].copy()
                match['match_type'] = 'sha256_hash'
                match['match_confidence'] = 0.99
                return match
        
        # Priority 3: Exact name match
        name_lower = driver.name.lower()
        base_name = name_lower.replace('.sys', '')
        
        if name_lower in self._name_lookup:
            match = self._name_lookup[name_lower].copy()
            match['match_type'] = 'exact_name'
            match['match_confidence'] = 0.85
            return match
        
        if base_name in self._name_lookup:
            match = self._name_lookup[base_name].copy()
            match['match_type'] = 'base_name'
            match['match_confidence'] = 0.80
            return match
        
        # Priority 4: Alias match
        if name_lower in self._alias_lookup:
            match = self._alias_lookup[name_lower].copy()
            match['match_type'] = 'alias'
            match['match_confidence'] = 0.75
            return match
        
        if base_name in self._alias_lookup:
            match = self._alias_lookup[base_name].copy()
            match['match_type'] = 'alias'
            match['match_confidence'] = 0.70
            return match
        
        # Priority 5: Partial name match (lower confidence)
        for db_entry in self.database:
            db_name = db_entry.get('name', '').lower().replace('.sys', '')
            
            # Check if driver name contains known vulnerable driver name
            if db_name and len(db_name) >= 4:
                if db_name in base_name or base_name in db_name:
                    match = db_entry.copy()
                    match['match_type'] = 'partial_name'
                    match['match_confidence'] = 0.50
                    return match
        
        return None
    
    def get_driver_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get database entry by driver name."""
        name_lower = name.lower()
        
        if name_lower in self._name_lookup:
            return self._name_lookup[name_lower]
        
        if name_lower in self._alias_lookup:
            return self._alias_lookup[name_lower]
        
        return None
    
    def get_all_vulnerable_names(self) -> List[str]:
        """Get list of all known vulnerable driver names."""
        names = set()
        
        for entry in self.database:
            if entry.get('name'):
                names.add(entry['name'])
            
            for alias in entry.get('aliases', []):
                names.add(alias)
        
        return sorted(names)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        categories = {}
        
        for entry in self.database:
            cat = entry.get('category', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
        
        return {
            'total_entries': len(self.database),
            'entries_with_md5': len(self._md5_lookup),
            'entries_with_sha256': len(self._sha256_lookup),
            'unique_names': len(self._name_lookup),
            'categories': categories,
        }
