"""
System Thread Verification Module

Detects system threads executing code outside of valid driver modules.
This is a strong indicator of rootkits or hidden code execution.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ikarma.core.driver import DriverInfo, DriverCapability, CapabilityType, ConfidenceLevel

logger = logging.getLogger(__name__)

class ThreadVerifier:
    """Verifies system threads against loaded drivers."""
    
    def __init__(self):
        pass
        
    def verify_system_threads(
        self, 
        drivers: List[DriverInfo], 
        threads: List[Dict[str, Any]]
    ) -> List[DriverCapability]:
        """
        Verify that all system threads point to valid driver code.
        
        Args:
            drivers: List of loaded drivers
            threads: List of system threads (from MemoryParser.enumerate_threads)
            
        Returns:
            List of capabilities (anomalies found)
        """
        capabilities = []
        
        if not threads:
            return capabilities
            
        # Create quick lookup for driver ranges
        # Sort by base address for efficiency
        sorted_drivers = sorted(
            [d for d in drivers if d.base_address and d.size], 
            key=lambda x: x.base_address
        )
        
        for thread in threads:
            start_addr = thread.get('start_address', 0)
            tid = thread.get('tid', 0)
            
            if start_addr == 0:
                continue
                
            # Check if address is within any driver
            owning_driver = self._find_owning_driver(start_addr, sorted_drivers)
            
            if not owning_driver:
                # Thread start address is NOT in any known driver
                # This is highly suspicious
                
                # Check if it's in ntoskrnl (kernel itself)
                # Usually ntoskrnl is in the driver list, but let's be sure
                
                evidence = (
                    f"System thread (TID {tid}) start address {hex(start_addr)} "
                    "is not within any loaded driver module."
                )
                
                cap = DriverCapability(
                    capability_type=CapabilityType.HIDDEN_CODE_EXECUTION,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    description=f"System thread executing hidden code (TID {tid})",
                    evidence=evidence,
                    handler_address=start_addr,
                    risk_weight=9.5,
                    exploitability="high"
                )
                
                capabilities.append(cap)
            else:
                # Thread is valid, but check if it's a known bad driver?
                # That's handled by LOLDrivers check on the driver itself.
                pass
                
        return capabilities
        
    def _find_owning_driver(self, address: int, sorted_drivers: List[DriverInfo]) -> Optional[DriverInfo]:
        """Find driver containing the address."""
        # Binary search could be used here, but linear is fine for < 500 drivers
        for driver in sorted_drivers:
            if driver.base_address <= address < driver.base_address + driver.size:
                return driver
        return None
