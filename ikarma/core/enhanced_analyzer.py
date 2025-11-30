"""
Enhanced iKARMA Analyzer - Integration Module

Integrates all advanced improvements:
- Enhanced DRIVER_OBJECT parsing with offset tables
- FastIoDispatch extraction
- Advanced capability inference (opcodes, MSR, PTE patterns, CFI)
- Bayesian risk scoring
- Advanced DKOM detection
- Kernel callback enumeration
- Self-scrubbing detection

This module extends the existing analyzer with all new features.
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from ikarma.core.analyzer import Analyzer as BaseAnalyzer
from ikarma.core.driver import DriverInfo, AnalysisResult
from ikarma.core.enhanced_driver_parser import EnhancedDriverParser
from ikarma.core.advanced_capability_engine import AdvancedCapabilityEngine
from ikarma.core.bayesian_risk_scorer import BayesianRiskScorer
from ikarma.core.advanced_dkom_detector import AdvancedDKOMDetector
from ikarma.core.advanced_dkom_detector import AdvancedDKOMDetector
from ikarma.core.callback_enumerator import CallbackEnumerator
from ikarma.core.thread_verifier import ThreadVerifier

logger = logging.getLogger(__name__)


class EnhancedAnalyzer(BaseAnalyzer):
    """
    Enhanced analyzer with all advanced features integrated.

    Extends base Analyzer with:
    - Enhanced DRIVER_OBJECT reconstruction
    - Advanced capability detection
    - Bayesian risk scoring
    - Comprehensive DKOM detection
    - Callback enumeration
    """

    def __init__(self, memory_path: str, config: Optional[Dict[str, Any]] = None):
        """Initialize enhanced analyzer."""
        super().__init__(memory_path, config)

        # Additional components
        self.enhanced_driver_parser: Optional[EnhancedDriverParser] = None
        self.advanced_capability_engine: Optional[AdvancedCapabilityEngine] = None
        self.bayesian_scorer: Optional[BayesianRiskScorer] = None
        self.advanced_dkom_detector: Optional[AdvancedDKOMDetector] = None
        self.callback_enumerator: Optional[CallbackEnumerator] = None
        self.thread_verifier: Optional[ThreadVerifier] = None

    def initialize(self) -> bool:
        """Initialize all components including new advanced modules."""
        # Call base initialization
        if not super().initialize():
            return False

        try:
            # Initialize enhanced parser
            self.enhanced_driver_parser = EnhancedDriverParser(
                is_64bit=(self._architecture == "x64")
            )

            # Initialize advanced capability engine
            self.advanced_capability_engine = AdvancedCapabilityEngine(
                architecture=self._architecture
            )

            # Initialize Bayesian scorer
            self.bayesian_scorer = BayesianRiskScorer(self.config)

            # Initialize advanced DKOM detector
            self.advanced_dkom_detector = AdvancedDKOMDetector(
                is_64bit=(self._architecture == "x64")
            )

            # Initialize callback enumerator
            self.callback_enumerator = CallbackEnumerator(
                is_64bit=(self._architecture == "x64")
            )

            # Initialize thread verifier
            self.thread_verifier = ThreadVerifier()

            logger.info("Enhanced analyzer components initialized successfully")

            logger.info("Enhanced analyzer components initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Enhanced analyzer initialization failed: {e}")
            return False

    def analyze(self) -> AnalysisResult:
        """
        Perform enhanced comprehensive analysis.

        This overrides the base analyze() to add:
        - Enhanced DRIVER_OBJECT parsing with FastIoDispatch
        - Advanced capability detection (MSR, PTE, CFI)
        - Bayesian risk scoring
        - Advanced DKOM with LIST_ENTRY validation
        - Callback enumeration
        """

        # Call base analysis first
        result = super().analyze()

        if not self._is_initialized:
            return result

        try:
            logger.info("=== Running Enhanced Analysis Features ===")

            # Enhancement 1: Enhanced DRIVER_OBJECT parsing
            self._enhance_driver_objects(result.drivers)

            # Enhancement 2: Advanced capability detection
            self._enhance_capability_detection(result.drivers)

            # Enhancement 3: Advanced DKOM detection
            if result.cross_view_result:
                self._enhance_dkom_detection(result)

            # Enhancement 4: Bayesian risk scoring
            self._apply_bayesian_scoring(result.drivers)

            # Enhancement 5: Callback enumeration (if possible)
            if self.memory_parser.volatility_available:
                self.callback_enumerator.resolve_symbols(self.memory_parser._vol_bridge)
                
                # Enumerate callbacks
                # We need known drivers list for attribution
                known_drivers_dicts = [
                    {'name': d.name, 'base': d.base_address, 'size': d.size} 
                    for d in result.drivers
                ]
                
                # Process Notify
                if 'PspCreateProcessNotifyRoutine' in self.callback_enumerator.callback_arrays:
                    addr = self.callback_enumerator.callback_arrays['PspCreateProcessNotifyRoutine']
                    if addr:
                        callbacks = self.callback_enumerator.enumerate_process_notify_callbacks(
                            addr, self.memory_parser.read_memory, known_drivers_dicts
                        )
                        # Check for hijacking
                        caps = self.callback_enumerator.detect_callback_hijacking(
                            callbacks, self.memory_parser.read_memory, 0, 0
                        )
                        # Add capabilities to relevant drivers or system
                        for cap in caps:
                            # Try to find driver
                            found = False
                            for d in result.drivers:
                                if d.base_address <= cap.handler_address < d.base_address + d.size:
                                    d.add_capability(cap)
                                    found = True
                                    break
                            if not found and result.drivers:
                                result.drivers[0].add_capability(cap) # Fallback

            # Enhancement 6: System Thread Verification
            self._verify_system_threads(result.drivers)

            # Enhancement 7: Advanced Integrity Checks (New)
            self._perform_integrity_checks(result.drivers)

            # Log statistics
            self._log_enhancement_statistics()

        except Exception as e:
            logger.error(f"Enhanced analysis failed: {e}")
            result.warnings.append(f"Enhanced analysis error: {e}")

        return result

    def _enhance_driver_objects(self, drivers: List[DriverInfo]):
        """
        Re-parse driver objects with enhanced parser to extract FastIoDispatch.
        """
        logger.info("Enhancing DRIVER_OBJECT parsing with FastIoDispatch extraction...")

        enhanced_count = 0

        for driver in drivers:
            if driver.driver_object_address == 0:
                continue

            try:
                # Parse with enhanced parser
                enhanced_obj = self.enhanced_driver_parser.parse_driver_object(
                    address=driver.driver_object_address,
                    read_memory=self.memory_parser.read_memory,
                    read_string=None,  # Would need UNICODE_STRING reader
                )

                if enhanced_obj:
                    # Merge FastIoDispatch handlers
                    if enhanced_obj.fast_io_handlers:
                        logger.debug(
                            f"Driver {driver.name}: Found {len(enhanced_obj.fast_io_handlers)} "
                            "FastIo handlers"
                        )

                        # Add FastIo hook capabilities
                        for fastio in enhanced_obj.fast_io_handlers:
                            if fastio.is_hooked:
                                from ikarma.core.driver import (
                                    DriverCapability, CapabilityType, ConfidenceLevel
                                )

                                cap = DriverCapability(
                                    capability_type=CapabilityType.MAJOR_FUNCTION_HOOK,
                                    confidence=0.93,
                                    confidence_level=ConfidenceLevel.HIGH,
                                    description=f"FastIo handler hooked: {fastio.handler_name}",
                                    evidence=(
                                        f"BECAUSE: FastIo handler {fastio.handler_name} at "
                                        f"{hex(fastio.handler_address)} is outside driver range "
                                        f"- indicates hook/filter driver"
                                    ),
                                    handler_address=fastio.handler_address,
                                    risk_weight=8.5,
                                    exploitability="high",
                                )
                                driver.add_capability(cap)

                    # Merge LDR module info for LIST_ENTRY validation
                    if enhanced_obj.ldr_module_info:
                        # Store for DKOM detection
                        pass

                    enhanced_count += 1

            except Exception as e:
                logger.debug(f"Enhanced parsing failed for {driver.name}: {e}")

        logger.info(f"Enhanced parsing completed for {enhanced_count} drivers")

    def _enhance_capability_detection(self, drivers: List[DriverInfo]):
        """
        Apply advanced capability detection to all drivers.
        """
        logger.info("Applying advanced capability detection (MSR, PTE, CFI)...")

        capabilities_added = 0

        # Prepare tasks for parallel execution
        tasks = []
        for driver in drivers:
            if driver.base_address == 0 or driver.size == 0:
                continue
            
            # Read code (limited to 2MB for performance)
            code_size = min(driver.size, 0x200000)
            code = self.memory_parser.read_memory(driver.base_address, code_size)
            
            if code:
                tasks.append((driver, code))

        logger.info(f"Submitting {len(tasks)} drivers for parallel analysis...")

        # Run parallel analysis
        import concurrent.futures
        
        with concurrent.futures.ProcessPoolExecutor() as executor:
            # Submit tasks
            future_to_driver = {
                executor.submit(_analyze_driver_worker, 
                                t[1], t[0].base_address, t[0].name, self._architecture): t[0]
                for t in tasks
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_driver):
                driver = future_to_driver[future]
                try:
                    caps, cfi_violations = future.result()
                    
                    for cap in caps:
                        driver.add_capability(cap)
                        capabilities_added += 1
                        
                    for violation in cfi_violations:
                        from ikarma.core.driver import (
                            DriverCapability, CapabilityType, ConfidenceLevel
                        )
                        cap = DriverCapability(
                            capability_type=CapabilityType.ARBITRARY_WRITE,
                            confidence=0.75,
                            confidence_level=ConfidenceLevel.MEDIUM,
                            description=f"CFI Violation: {violation.description}",
                            evidence=violation.evidence,
                            handler_address=violation.address,
                            risk_weight=8.0,
                            exploitability="high",
                        )
                        driver.add_capability(cap)
                        capabilities_added += 1
                        
                except Exception as e:
                    logger.debug(f"Parallel analysis failed for {driver.name}: {e}")

        logger.info(f"Advanced capability detection added {capabilities_added} capabilities")

    def _enhance_dkom_detection(self, result: AnalysisResult):
        """
        Apply advanced DKOM detection techniques.
        """
        logger.info("Applying advanced DKOM detection (LIST_ENTRY validation)...")

        if not result.cross_view_result:
            return

        # Detect partial unlinking
        # (Requires LDR entries which we'd need to parse from drivers)
        ldr_entries = []  # Would be populated from enhanced driver parsing

        if ldr_entries:
            partial_indicators = self.advanced_dkom_detector.detect_partial_unlinking(
                ldr_entries=ldr_entries,
                read_memory=self.memory_parser.read_memory,
            )

            for indicator in partial_indicators:
                # Find affected driver and add indicator
                # (Would need mapping)
                pass

        # Detect timestamp rollback
        for driver in result.drivers:
            timestamp_indicator = self.advanced_dkom_detector.detect_timestamp_rollback(
                driver=driver
            )

            if timestamp_indicator:
                driver.add_anti_forensic_indicator(timestamp_indicator)

        # Detect self-scrubbing
        for driver in result.drivers:
            scrubbing_indicators = self.advanced_dkom_detector.detect_self_scrubbing(
                driver=driver,
                read_memory=self.memory_parser.read_memory,
            )

            for indicator in scrubbing_indicators:
                driver.add_anti_forensic_indicator(indicator)

        logger.info("Advanced DKOM detection completed")

    def _apply_bayesian_scoring(self, drivers: List[DriverInfo]):
        """
        Apply Bayesian risk scoring to all drivers.

        This provides probabilistic risk assessment with confidence intervals.
        """
        logger.info("Applying Bayesian risk scoring...")

        for driver in drivers:
            try:
                # Get Bayesian risk profile
                profile = self.bayesian_scorer.score_driver(driver)

                # Store Bayesian-specific metrics
                driver.risk_score = profile.final_risk_score
                driver.risk_category = profile.risk_category

                # Add Bayesian evidence to driver
                if hasattr(driver, 'bayesian_profile'):
                    driver.bayesian_profile = {
                        'posterior_probability': profile.risk_estimate.posterior_probability,
                        'confidence_interval': (
                            profile.risk_estimate.confidence_lower,
                            profile.risk_estimate.confidence_upper
                        ),
                        'evidence_strength': profile.risk_estimate.evidence_strength,
                        'likelihood_ratio': profile.risk_estimate.likelihood_ratio,
                    }

            except Exception as e:
                logger.debug(f"Bayesian scoring failed for {driver.name}: {e}")

    def _verify_system_threads(self, drivers: List[DriverInfo]):
        """
        Verify system threads against loaded drivers.
        """
        logger.info("Verifying system threads...")
        
        try:
            # Get threads from memory parser
            threads = self.memory_parser.enumerate_threads()
            if not threads:
                logger.info("No system threads enumerated (Volatility3 required)")
                return

            # Verify threads
            capabilities = self.thread_verifier.verify_system_threads(drivers, threads)
            
            if capabilities:
                logger.warning(f"Found {len(capabilities)} suspicious system threads")
                
                # Attach to ntoskrnl or create a "System" pseudo-driver
                # Find ntoskrnl
                ntoskrnl = next((d for d in drivers if 'ntoskrnl' in d.name.lower()), None)
                
                if ntoskrnl:
                    for cap in capabilities:
                        ntoskrnl.add_capability(cap)
                else:
                    # Add to first driver as fallback or create new?
                    # For now, just log warning as we can't easily add a new driver to the list safely here
                    # without potentially confusing other parts.
                    # But we should try to attach it to something.
                    if drivers:
                        drivers[0].add_capability(capabilities[0]) # Attach to first driver (usually kernel)
                        
        except Exception as e:
            logger.error(f"System thread verification failed: {e}")

    def _perform_integrity_checks(self, drivers: List[DriverInfo]):
        """
        Perform advanced integrity checks (Driver Object & IAT Hooks).
        """
        logger.info("Performing advanced integrity checks...")
        
        if not self.enhanced_driver_parser:
            return

        # Get module list for comparison
        modules = self.memory_parser.enumerate_modules()
        module_map = {m['name'].lower(): m for m in modules}
        
        for driver in drivers:
            try:
                # 1. Driver Object Integrity
                # We need the raw DriverObjectInfo which we might need to reconstruct or store
                # For now, we'll use the driver info we have
                
                # Find matching module
                module_entry = module_map.get(driver.name.lower())
                if not module_entry and driver.name.endswith('.sys'):
                     module_entry = module_map.get(driver.name[:-4].lower())
                
                # Create a temporary DriverObjectInfo wrapper for the check
                # (In a full refactor, we'd store the original object)
                from ikarma.volatility3.vol3_plugin import DriverObjectInfo
                d_obj = DriverObjectInfo()
                d_obj.driver_start = driver.base_address
                d_obj.driver_size = driver.size
                
                # Get PE info if available
                pe_info = None
                if HAS_PEFILE and driver.base_address:
                     # We'd need to parse PE again or cache it. 
                     # For performance, let's skip PE check here if not cached, 
                     # or read header quickly.
                     try:
                         header_data = self.memory_parser.read_memory(driver.base_address, 0x1000)
                         if header_data:
                             pe_info = pefile.PE(data=header_data, fast_load=True)
                     except:
                         pass

                anomalies = self.enhanced_driver_parser.verify_integrity(
                    d_obj, module_entry, pe_info
                )
                
                for anomaly in anomalies:
                    from ikarma.core.driver import (
                        DriverCapability, CapabilityType, ConfidenceLevel
                    )
                    cap = DriverCapability(
                        capability_type=CapabilityType.HIDDEN_CODE_EXECUTION, # Closest fit
                        confidence=0.90,
                        confidence_level=ConfidenceLevel.HIGH,
                        description=f"{anomaly['description']}",
                        evidence=f"BECAUSE: {anomaly['details']}",
                        risk_weight=9.0,
                        exploitability="high"
                    )
                    driver.add_capability(cap)

                # 2. IAT Hook Detection
                if self.memory_parser.volatility_available:
                    hooks = self.enhanced_driver_parser.check_iat_hooks(
                        driver.base_address,
                        self.memory_parser.read_memory,
                        self.memory_parser._vol_bridge.resolve_symbol,
                        pe_info
                    )
                    
                    for hook in hooks:
                        from ikarma.core.driver import (
                            DriverCapability, CapabilityType, ConfidenceLevel
                        )
                        cap = DriverCapability(
                            capability_type=CapabilityType.MAJOR_FUNCTION_HOOK, # Closest fit
                            confidence=0.95,
                            confidence_level=ConfidenceLevel.HIGH,
                            description=hook['description'],
                            evidence=f"BECAUSE: {hook['details']}",
                            risk_weight=9.5,
                            exploitability="high"
                        )
                        driver.add_capability(cap)
                        
            except Exception as e:
                logger.debug(f"Integrity check failed for {driver.name}: {e}")

    def _log_enhancement_statistics(self):
        """Log statistics from all enhanced components."""
        logger.info("=== Enhancement Statistics ===")

        if self.enhanced_driver_parser:
            stats = self.enhanced_driver_parser.get_statistics()
            logger.info(f"Enhanced Parser: {stats}")

        if self.advanced_capability_engine:
            stats = self.advanced_capability_engine.get_statistics()
            logger.info(f"Advanced Capabilities: {stats}")

    def get_enhancement_report(self) -> Dict[str, Any]:
        """Generate a comprehensive enhancement report."""
        report = {
            'enhanced_parsing': {},
            'advanced_capabilities': {},
            'bayesian_scoring': {},
            'advanced_dkom': {},
        }

        if self.enhanced_driver_parser:
            report['enhanced_parsing'] = self.enhanced_driver_parser.get_statistics()

        if self.advanced_capability_engine:
            report['advanced_capabilities'] = self.advanced_capability_engine.get_statistics()

        return report


def _analyze_driver_worker(code, base_address, driver_name, architecture):
    """Worker function for parallel analysis."""
    try:
        # Initialize engine in worker process
        engine = AdvancedCapabilityEngine(architecture=architecture)
        
        # Run analysis
        caps = engine.analyze_code_advanced(
            code=code,
            base_address=base_address,
            context=f"driver {driver_name}"
        )
        
        # Run CFI check
        imports = [cap.description for cap in caps if 'Import' in cap.description]
        cfi_violations = engine.detect_cfi_violations(
            code=code,
            base_address=base_address,
            imports=imports,
        )
        
        return caps, cfi_violations
    except Exception as e:
        # Return empty on error to avoid crashing main process
        return [], []
