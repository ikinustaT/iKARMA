"""
iKARMA Risk Scorer - Production Release

Provides comprehensive risk scoring for kernel drivers based on:
- Detected capabilities and their severity
- Anti-forensic indicators
- MajorFunction hook detection
- Digital signature status (legitimacy bonus)
- Known vulnerable driver matching
- Cross-view validation results

Every score includes a "Because" tag explaining the reasoning.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum

from ikarma.core.driver import (
    DriverInfo, DriverCapability, AntiForensicIndicator,
    CapabilityType, AntiForensicType, ConfidenceLevel,
)

logger = logging.getLogger(__name__)


# =============================================================================
# SCORING CONFIGURATION
# =============================================================================

# Capability weights - how dangerous each capability type is
CAPABILITY_WEIGHTS = {
    # Critical - immediate exploitation potential
    CapabilityType.ARBITRARY_WRITE: 10.0,
    CapabilityType.PHYSICAL_MEMORY_WRITE: 10.0,
    CapabilityType.MSR_WRITE: 9.5,
    CapabilityType.DSE_BYPASS: 9.5,
    CapabilityType.SHELLCODE_EXECUTION: 10.0,
    CapabilityType.CALLBACK_REMOVAL: 9.0,
    
    # High - significant security impact
    CapabilityType.PHYSICAL_MEMORY_MAP: 8.5,
    CapabilityType.PHYSICAL_MEMORY_READ: 8.0,
    CapabilityType.ARBITRARY_READ: 8.0,
    CapabilityType.PROCESS_TERMINATE: 7.5,
    CapabilityType.PROCESS_TOKEN_STEAL: 8.5,
    CapabilityType.APC_INJECTION: 8.5,
    CapabilityType.MAJOR_FUNCTION_HOOK: 9.0,
    CapabilityType.PPL_BYPASS: 9.0,
    
    # Medium - concerning but context-dependent
    CapabilityType.MSR_READ: 6.5,
    CapabilityType.CR_ACCESS: 7.0,
    CapabilityType.IDT_MANIPULATION: 7.5,
    CapabilityType.GDT_MANIPULATION: 7.0,
    CapabilityType.PORT_IO_READ: 5.5,
    CapabilityType.PORT_IO_WRITE: 6.5,
    CapabilityType.PCI_CONFIG_ACCESS: 6.0,
    
    # Lower - may have legitimate uses
    CapabilityType.PROCESS_HANDLE_DUP: 5.0,
    CapabilityType.EPROCESS_MANIPULATION: 6.5,
    CapabilityType.KERNEL_FILE_ACCESS: 4.5,
    CapabilityType.KERNEL_REGISTRY_ACCESS: 4.5,
    
    # Unknown
    CapabilityType.UNKNOWN: 3.0,
}

# Anti-forensic severity multipliers
ANTIFORENSIC_WEIGHTS = {
    AntiForensicType.DKOM_UNLINK: 9.5,
    AntiForensicType.DKOM_HIDDEN: 9.5,
    AntiForensicType.UNLINKED_FROM_MODULE_LIST: 9.0,
    AntiForensicType.PE_HEADER_WIPED: 8.0,
    AntiForensicType.IMPORT_TABLE_DESTROYED: 7.5,
    AntiForensicType.MEMORY_SCRUBBING: 7.0,
    AntiForensicType.CODE_OBFUSCATION: 6.0,
    AntiForensicType.TIMESTAMP_MANIPULATION: 5.0,
    AntiForensicType.SIZE_MISMATCH: 4.5,
    AntiForensicType.PE_HEADER_MODIFIED: 4.0,
    AntiForensicType.DRIVER_UNLOADED_REMNANT: 3.0,
    AntiForensicType.CARVED_ONLY: 2.0,
}

# Legitimacy bonuses - trusted signers get reduced scores
SIGNER_LEGITIMACY_BONUS = {
    "Microsoft Windows Hardware Compatibility Publisher": -2.0,
    "Microsoft Windows": -2.0,
    "Microsoft Corporation": -1.5,
    "NVIDIA Corporation": -1.0,
    "Intel Corporation": -1.0,
    "AMD": -1.0,
    "Realtek Semiconductor": -0.8,
    "VMware, Inc.": -0.8,
}

# Hook detection bonus (penalty for hooked drivers)
HOOK_PENALTY = 3.0


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class RiskFactor:
    """A single factor contributing to risk score."""
    
    name: str
    weight: float
    confidence: float
    because: str
    category: str  # capability, antiforensic, signature, hook, known_vuln
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "weight": round(self.weight, 2),
            "confidence": round(self.confidence, 2),
            "contribution": round(self.weight * self.confidence, 2),
            "because": self.because,
            "category": self.category,
        }


@dataclass
class RiskProfile:
    """Complete risk profile for a driver."""
    
    driver_name: str
    raw_score: float = 0.0
    legitimacy_bonus: float = 0.0
    final_score: float = 0.0
    score_confidence: float = 0.0
    risk_category: str = "unknown"
    
    factors: List[RiskFactor] = field(default_factory=list)
    because_summary: str = ""
    
    # Breakdown
    capability_score: float = 0.0
    antiforensic_score: float = 0.0
    signature_score: float = 0.0
    hook_score: float = 0.0
    known_vuln_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "driver_name": self.driver_name,
            "final_score": round(self.final_score, 2),
            "raw_score": round(self.raw_score, 2),
            "legitimacy_bonus": round(self.legitimacy_bonus, 2),
            "score_confidence": round(self.score_confidence, 2),
            "risk_category": self.risk_category,
            "breakdown": {
                "capability_score": round(self.capability_score, 2),
                "antiforensic_score": round(self.antiforensic_score, 2),
                "signature_score": round(self.signature_score, 2),
                "hook_score": round(self.hook_score, 2),
                "known_vuln_score": round(self.known_vuln_score, 2),
            },
            "factors": [f.to_dict() for f in self.factors],
            "because_summary": self.because_summary,
        }


# =============================================================================
# RISK SCORER CLASS
# =============================================================================

class RiskScorer:
    """
    Production-ready risk scorer for kernel drivers.
    
    Scoring methodology:
    1. Calculate raw capability score based on detected capabilities
    2. Add anti-forensic indicator scores
    3. Add hook detection penalties
    4. Add known vulnerability scores
    5. Apply legitimacy bonus for signed drivers
    6. Normalize to 0-10 scale
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the risk scorer."""
        self.config = config or {}
        
        # Configurable thresholds
        self.critical_threshold = self.config.get('critical_threshold', 8.0)
        self.high_threshold = self.config.get('high_threshold', 6.0)
        self.medium_threshold = self.config.get('medium_threshold', 4.0)
        
        # Maximum legitimacy bonus
        self.max_legitimacy_bonus = self.config.get('max_legitimacy_bonus', 3.0)
        
        # Whether to apply legitimacy bonus at all
        self.apply_legitimacy_bonus = self.config.get('apply_legitimacy_bonus', True)
    
    def score_driver(self, driver: DriverInfo) -> RiskProfile:
        """
        Calculate comprehensive risk score for a driver.
        
        Returns:
            RiskProfile with detailed scoring breakdown and "Because" tags
        """
        profile = RiskProfile(driver_name=driver.name)
        
        # Score capabilities
        cap_score, cap_factors = self._score_capabilities(driver)
        profile.capability_score = cap_score
        profile.factors.extend(cap_factors)
        
        # Score anti-forensic indicators
        af_score, af_factors = self._score_antiforensics(driver)
        profile.antiforensic_score = af_score
        profile.factors.extend(af_factors)
        
        # Score hooks
        hook_score, hook_factors = self._score_hooks(driver)
        profile.hook_score = hook_score
        profile.factors.extend(hook_factors)
        
        # Score known vulnerabilities
        vuln_score, vuln_factors = self._score_known_vulns(driver)
        profile.known_vuln_score = vuln_score
        profile.factors.extend(vuln_factors)
        
        # Calculate raw score
        total_score = cap_score + af_score + hook_score + vuln_score
        
        # Normalize to 0-10 scale
        profile.raw_score = min(10.0, total_score)
        
        # Apply legitimacy bonus
        if self.apply_legitimacy_bonus:
            profile.legitimacy_bonus = self._calculate_legitimacy_bonus(driver)
            sig_score, sig_factors = self._score_signature(driver)
            profile.signature_score = sig_score
            profile.factors.extend(sig_factors)
        
        # Final score
        profile.final_score = max(0.0, min(10.0, profile.raw_score + profile.legitimacy_bonus))
        
        # Calculate confidence
        profile.score_confidence = self._calculate_confidence(profile)
        
        # Determine category
        profile.risk_category = self._categorize_risk(profile.final_score)
        
        # Generate summary
        profile.because_summary = self._generate_because_summary(profile, driver)
        
        # Update driver object
        driver.risk_score = profile.final_score
        driver.risk_score_raw = profile.raw_score
        driver.legitimacy_bonus = profile.legitimacy_bonus
        driver.risk_confidence = profile.score_confidence
        driver.risk_category = profile.risk_category
        driver.risk_factors = [f.name for f in profile.factors]
        
        return profile
    
    def _score_capabilities(self, driver: DriverInfo) -> Tuple[float, List[RiskFactor]]:
        """Score based on detected capabilities."""
        score = 0.0
        factors = []
        
        for cap in driver.capabilities:
            weight = CAPABILITY_WEIGHTS.get(cap.capability_type, 3.0)
            contribution = weight * cap.confidence
            
            # Limit contribution from any single capability
            contribution = min(contribution, 5.0)
            
            score += contribution
            
            factors.append(RiskFactor(
                name=cap.capability_type.name,
                weight=weight,
                confidence=cap.confidence,
                because=cap.evidence,
                category="capability",
            ))
        
        # Normalize capability score contribution
        if driver.capabilities:
            # Average with some boost for having multiple capabilities
            score = (score / len(driver.capabilities)) * min(1 + len(driver.capabilities) * 0.1, 2.0)
        
        return min(score, 8.0), factors
    
    def _score_antiforensics(self, driver: DriverInfo) -> Tuple[float, List[RiskFactor]]:
        """Score based on anti-forensic indicators."""
        score = 0.0
        factors = []
        
        for indicator in driver.anti_forensic_indicators:
            weight = ANTIFORENSIC_WEIGHTS.get(indicator.indicator_type, 3.0)
            contribution = weight * indicator.confidence * 0.3  # Scale down
            
            score += contribution
            
            factors.append(RiskFactor(
                name=indicator.indicator_type.name,
                weight=weight,
                confidence=indicator.confidence,
                because=indicator.evidence,
                category="antiforensic",
            ))
        
        return min(score, 4.0), factors
    
    def _score_hooks(self, driver: DriverInfo) -> Tuple[float, List[RiskFactor]]:
        """Score based on MajorFunction hook detection."""
        score = 0.0
        factors = []
        
        for mf in driver.major_function_info:
            if mf.is_hooked:
                # IOCTL handler hook is most suspicious
                if mf.index == 14:  # IRP_MJ_DEVICE_CONTROL
                    hook_weight = HOOK_PENALTY * 1.5
                else:
                    hook_weight = HOOK_PENALTY
                
                score += hook_weight
                
                factors.append(RiskFactor(
                    name=f"HOOK_{mf._get_name()}",
                    weight=hook_weight,
                    confidence=0.95,
                    because=mf.because,
                    category="hook",
                ))
        
        return min(score, 5.0), factors
    
    def _score_known_vulns(self, driver: DriverInfo) -> Tuple[float, List[RiskFactor]]:
        """Score based on known vulnerability matching."""
        score = 0.0
        factors = []
        
        if driver.is_known_vulnerable:
            score = 3.0
            
            cve_str = ", ".join(driver.known_cves[:3]) if driver.known_cves else "unspecified"
            
            factors.append(RiskFactor(
                name="KNOWN_VULNERABLE_DRIVER",
                weight=3.0,
                confidence=0.99,
                because=f"BECAUSE: Driver matches known vulnerable driver database (CVE: {cve_str})",
                category="known_vuln",
            ))
        
        if driver.loldrivers_match:
            score += 2.0
            
            factors.append(RiskFactor(
                name="LOLDRIVERS_MATCH",
                weight=2.0,
                confidence=0.95,
                because="BECAUSE: Driver matches LOLDrivers database - known to be abused by attackers",
                category="known_vuln",
            ))
        
        return min(score, 5.0), factors
    
    def _score_signature(self, driver: DriverInfo) -> Tuple[float, List[RiskFactor]]:
        """Score based on signature status."""
        score = 0.0
        factors = []
        
        if not driver.signature_info or not driver.signature_info.is_signed:
            score = 1.5
            factors.append(RiskFactor(
                name="UNSIGNED_DRIVER",
                weight=1.5,
                confidence=0.95,
                because="BECAUSE: Driver is not digitally signed",
                category="signature",
            ))
        
        return score, factors
    
    def _calculate_legitimacy_bonus(self, driver: DriverInfo) -> float:
        """
        Calculate legitimacy bonus based on digital signature.
        
        Trusted signers get a negative adjustment (bonus = reduced score).
        However, we never trust completely - even signed drivers can be exploited.
        """
        if not driver.signature_info:
            return 0.0
        
        if not driver.signature_info.is_signed or not driver.signature_info.signature_valid:
            return 0.0
        
        signer = driver.signature_info.signer_name or ""
        
        # Check for known trusted signers
        for trusted_signer, bonus in SIGNER_LEGITIMACY_BONUS.items():
            if trusted_signer.lower() in signer.lower():
                # Cap the bonus
                return max(bonus, -self.max_legitimacy_bonus)
        
        # Generic signed driver gets small bonus
        if driver.signature_info.is_whql_signed:
            return -1.0
        elif driver.signature_info.is_microsoft_signed:
            return -1.5
        
        return -0.3
    
    def _calculate_confidence(self, profile: RiskProfile) -> float:
        """Calculate overall confidence in the risk assessment."""
        if not profile.factors:
            return 0.3
        
        # Weight confidence by factor contribution
        total_contribution = sum(f.weight * f.confidence for f in profile.factors)
        total_weight = sum(f.weight for f in profile.factors)
        
        if total_weight == 0:
            return 0.3
        
        base_confidence = total_contribution / total_weight
        
        # Boost confidence with more factors
        factor_bonus = min(len(profile.factors) * 0.02, 0.2)
        
        return min(0.99, base_confidence + factor_bonus)
    
    def _categorize_risk(self, score: float) -> str:
        """Categorize risk level based on score."""
        if score >= self.critical_threshold:
            return "critical"
        elif score >= self.high_threshold:
            return "high"
        elif score >= self.medium_threshold:
            return "medium"
        else:
            return "low"
    
    def _generate_because_summary(self, profile: RiskProfile, driver: DriverInfo) -> str:
        """Generate a comprehensive 'Because' summary for the driver."""
        reasons = []
        
        # Top capability reasons
        cap_factors = [f for f in profile.factors if f.category == "capability"]
        if cap_factors:
            top_caps = sorted(cap_factors, key=lambda x: x.weight * x.confidence, reverse=True)[:3]
            cap_names = [f.name for f in top_caps]
            reasons.append(f"has dangerous capabilities ({', '.join(cap_names)})")
        
        # Hook reasons
        hook_factors = [f for f in profile.factors if f.category == "hook"]
        if hook_factors:
            reasons.append(f"has {len(hook_factors)} hooked MajorFunction entries")
        
        # Anti-forensic reasons
        af_factors = [f for f in profile.factors if f.category == "antiforensic"]
        if af_factors:
            af_names = [f.name for f in af_factors[:2]]
            reasons.append(f"shows anti-forensic behavior ({', '.join(af_names)})")
        
        # Signature reasons
        sig_factors = [f for f in profile.factors if f.category == "signature"]
        if sig_factors:
            reasons.append("is not digitally signed")
        
        # Known vuln reasons
        vuln_factors = [f for f in profile.factors if f.category == "known_vuln"]
        if vuln_factors:
            reasons.append("matches known vulnerable driver database")
        
        # Legitimacy bonus note
        if profile.legitimacy_bonus < -0.5:
            signer = driver.signature_info.signer_name if driver.signature_info else "trusted authority"
            reasons.append(f"score reduced due to trusted signature from {signer}")
        
        if not reasons:
            if profile.final_score < self.medium_threshold:
                return "Flagged as LOW risk BECAUSE: No significant risk factors detected"
            else:
                return "Flagged BECAUSE: General elevated risk indicators"
        
        category_upper = profile.risk_category.upper()
        return f"Flagged as {category_upper} risk BECAUSE: {' AND '.join(reasons)}"
    
    def rank_drivers(self, drivers: List[DriverInfo]) -> List[Tuple[DriverInfo, RiskProfile]]:
        """
        Score and rank all drivers by risk.
        
        Returns:
            List of (driver, profile) tuples sorted by risk (highest first)
        """
        results = []
        
        for driver in drivers:
            profile = self.score_driver(driver)
            results.append((driver, profile))
        
        # Sort by final score descending
        results.sort(key=lambda x: x[1].final_score, reverse=True)
        
        return results
    
    def get_high_risk_drivers(
        self, 
        drivers: List[DriverInfo], 
        threshold: Optional[float] = None
    ) -> List[Tuple[DriverInfo, RiskProfile]]:
        """Get drivers above the risk threshold."""
        threshold = threshold or self.high_threshold
        
        ranked = self.rank_drivers(drivers)
        return [(d, p) for d, p in ranked if p.final_score >= threshold]
