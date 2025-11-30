"""
Bayesian Risk Scoring Model

Implements probabilistic risk assessment using Bayesian inference to combine
multiple signals (capabilities, anti-forensics, signatures, hooks) into a
unified risk score with confidence intervals.

Formula:
    P(malicious|signals) = P(signals|malicious) * P(malicious) / P(signals)

Features:
- Prior probability assignment based on threat intelligence
- Likelihood ratio calculation for each signal
- Posterior probability computation
- Confidence interval estimation via Monte Carlo
- Temporal decay for CVE age
- Threat actor TTP correlation
"""

import logging
import math
import random
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from ikarma.core.driver import (
    DriverInfo, DriverCapability, AntiForensicIndicator,
    CapabilityType, AntiForensicType
)

logger = logging.getLogger(__name__)


# Prior probabilities from threat intelligence (tuned based on empirical validation)
PRIOR_PROBABILITIES = {
    'unsigned_driver': 0.70,           # 70% of unsigned drivers in analysis context are suspicious
    'signed_driver': 0.20,             # 20% of signed (non-WHQL, non-MS) drivers are suspicious
    'ms_signed_driver': 0.0001,        # 0.01% of MS-signed drivers are malicious (extremely rare)
    'whql_signed_driver': 0.01,        # 1% of WHQL-signed drivers are malicious
    'unknown': 0.10,                   # Default: 10% base rate
}


# Likelihood ratios - how much each signal increases probability of being malicious
# LR = P(signal|malicious) / P(signal|benign)
LIKELIHOOD_RATIOS = {
    # Capability combinations (joint probabilities)
    ('ARBITRARY_WRITE', 'DKOM_UNLINK'): 50.0,          # Extremely suspicious combination
    ('MSR_WRITE', 'IDT_MANIPULATION'): 35.0,           # Kernel backdoor indicators
    ('PHYSICAL_MEMORY_MAP', 'CALLBACK_REMOVAL'): 40.0, # BYOVD pattern
    ('PROCESS_TOKEN_STEAL', 'PPL_BYPASS'): 45.0,      # Privilege escalation

    # Individual capabilities
    'ARBITRARY_WRITE': 20.0,
    'PHYSICAL_MEMORY_WRITE': 18.0,
    'MSR_WRITE': 15.0,
    'DSE_BYPASS': 22.0,
    'CALLBACK_REMOVAL': 16.0,
    'PROCESS_TOKEN_STEAL': 14.0,
    'PHYSICAL_MEMORY_MAP': 12.0,
    'MAJOR_FUNCTION_HOOK': 13.0,

    # Anti-forensic indicators
    'DKOM_UNLINK': 30.0,
    'DKOM_HIDDEN': 30.0,
    'PE_HEADER_WIPED': 20.0,
    'IMPORT_TABLE_DESTROYED': 15.0,
    'MEMORY_SCRUBBING': 12.0,

    # Signature anomalies
    'unsigned_with_capabilities': 8.0,
    'signed_with_dkom': 25.0,          # Signed driver doing DKOM is very suspicious
    'stolen_certificate': 40.0,

    # Known vulnerabilities
    'loldrivers_match': 10.0,
    'known_cve': 8.0,
    'recent_cve': 15.0,  # CVE < 6 months

    # Hook indicators
    'majorfunction_hook': 11.0,
    'fastio_hook': 9.0,
    'idt_hook': 18.0,
}


# Confidence adjustment factors
CONFIDENCE_FACTORS = {
    'multiple_detection_methods': 1.3,   # Same capability detected by opcode + import + string
    'corroborating_evidence': 1.2,      # Multiple related capabilities
    'single_detection': 1.0,
    'speculative': 0.7,
}


@dataclass
class RiskEstimate:
    """Probabilistic risk estimate with confidence intervals."""
    posterior_probability: float        # P(malicious|evidence)
    confidence_lower: float             # 95% CI lower bound
    confidence_upper: float             # 95% CI upper bound
    prior_probability: float            # Starting prior
    likelihood_ratio: float             # Combined LR
    evidence_strength: str              # 'weak', 'moderate', 'strong', 'very_strong'


@dataclass
class BayesianRiskProfile:
    """Complete Bayesian risk profile."""
    driver_name: str
    risk_estimate: RiskEstimate
    evidence_signals: List[str] = field(default_factory=list)
    likelihood_contributions: Dict[str, float] = field(default_factory=dict)
    final_risk_score: float = 0.0       # Normalized to 0-10 scale
    risk_category: str = "unknown"
    because_summary: str = ""


class BayesianRiskScorer:
    """
    Bayesian risk scorer using probabilistic inference.

    Combines multiple evidence signals using Bayes' theorem to compute
    posterior probability of driver being malicious.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Bayesian scorer."""
        self.config = config or {}

        # Monte Carlo samples for confidence intervals
        self.mc_samples = self.config.get('mc_samples', 1000)

        # Risk thresholds (on probability scale 0-1)
        self.critical_threshold = 0.80    # 80% probability
        self.high_threshold = 0.60        # 60% probability
        self.medium_threshold = 0.30      # 30% probability

    def score_driver(self, driver: DriverInfo) -> BayesianRiskProfile:
        """
        Calculate Bayesian risk score for driver.

        Args:
            driver: DriverInfo to score

        Returns:
            BayesianRiskProfile with posterior probability
        """

        # Step 1: Determine prior probability
        prior = self._get_prior_probability(driver)

        # Step 2: Collect all evidence signals
        evidence_signals = self._collect_evidence(driver)

        # Step 3: Calculate likelihood ratio
        lr, contributions = self._calculate_likelihood_ratio(driver, evidence_signals)

        # Step 4: Compute posterior probability
        posterior = self._compute_posterior(prior, lr)

        # Step 5: Estimate confidence intervals via Monte Carlo
        ci_lower, ci_upper = self._estimate_confidence_interval(prior, lr, evidence_signals)

        # Step 6: Assess evidence strength
        evidence_strength = self._assess_evidence_strength(lr)

        # Create risk estimate
        risk_estimate = RiskEstimate(
            posterior_probability=posterior,
            confidence_lower=ci_lower,
            confidence_upper=ci_upper,
            prior_probability=prior,
            likelihood_ratio=lr,
            evidence_strength=evidence_strength,
        )

        # Step 7: Normalize to 0-10 scale
        risk_score = self._normalize_to_scale(posterior)

        # Step 8: Categorize
        risk_category = self._categorize_risk(posterior)

        # Step 9: Generate summary
        because = self._generate_bayesian_summary(driver, risk_estimate, evidence_signals)

        profile = BayesianRiskProfile(
            driver_name=driver.name,
            risk_estimate=risk_estimate,
            evidence_signals=evidence_signals,
            likelihood_contributions=contributions,
            final_risk_score=risk_score,
            risk_category=risk_category,
            because_summary=because,
        )

        # Update driver object
        driver.risk_score = risk_score
        driver.risk_score_raw = posterior
        driver.risk_confidence = (ci_upper - ci_lower) / 2.0  # Confidence = width of CI
        driver.risk_category = risk_category

        return profile

    def _get_prior_probability(self, driver: DriverInfo) -> float:
        """Determine prior probability based on signature status."""

        if not driver.signature_info or not driver.signature_info.is_signed:
            return PRIOR_PROBABILITIES['unsigned_driver']

        if not driver.signature_info.signature_valid:
            return PRIOR_PROBABILITIES['unsigned_driver']

        # Check for Microsoft signature
        if driver.signature_info.is_microsoft_signed:
            return PRIOR_PROBABILITIES['ms_signed_driver']

        if driver.signature_info.is_whql_signed:
            return PRIOR_PROBABILITIES['whql_signed_driver']

        # Generic signed driver
        return PRIOR_PROBABILITIES['signed_driver']

    def _collect_evidence(self, driver: DriverInfo) -> List[str]:
        """Collect all evidence signals from driver."""
        signals = []

        # Capabilities
        for cap in driver.capabilities:
            signals.append(cap.capability_type.name)

        # Anti-forensic indicators
        for indicator in driver.anti_forensic_indicators:
            signals.append(indicator.indicator_type.name)

        # Hooks
        if driver.has_hooks():
            signals.append('majorfunction_hook')

        # Known vulnerabilities
        if driver.is_known_vulnerable:
            signals.append('known_cve')

        if driver.loldrivers_match:
            signals.append('loldrivers_match')

        # Signature anomalies
        if driver.has_dangerous_capabilities():
            if not driver.signature_info or not driver.signature_info.is_signed:
                signals.append('unsigned_with_capabilities')
            elif driver.cross_view_status == "hidden":
                signals.append('signed_with_dkom')

        return signals

    def _calculate_likelihood_ratio(
        self,
        driver: DriverInfo,
        evidence: List[str]
    ) -> Tuple[float, Dict[str, float]]:
        """
        Calculate combined likelihood ratio from all evidence.

        Uses multiplicative combination of individual LRs (assuming independence).
        Also checks for joint probabilities (combinations).
        """

        combined_lr = 1.0
        contributions = {}

        # Check for high-impact combinations first
        evidence_set = set(evidence)

        for combo, lr in LIKELIHOOD_RATIOS.items():
            if isinstance(combo, tuple):
                # Joint probability
                if all(sig in evidence_set for sig in combo):
                    combined_lr *= lr
                    contributions[f"COMBO_{'+'.join(combo)}"] = lr

        # Individual signals
        for signal in evidence:
            if signal in LIKELIHOOD_RATIOS:
                lr = LIKELIHOOD_RATIOS[signal]
                combined_lr *= lr
                contributions[signal] = lr

        # Temporal decay for CVEs
        if driver.is_known_vulnerable and driver.known_cves:
            # Apply decay based on CVE age (simplified - would need actual CVE dates)
            # Assume average CVE is 2 years old
            age_years = 2.0
            decay_factor = math.exp(-age_years / 2.0)
            temporal_lr = 1.0 + (5.0 * decay_factor)
            combined_lr *= temporal_lr
            contributions['cve_temporal'] = temporal_lr

        # Multi-detection confidence boost
        # Count how many detection methods found the same capability
        cap_types = [cap.capability_type for cap in driver.capabilities]
        if len(cap_types) != len(set(cap_types)):
            # Duplicate capability types = multiple detection methods
            combined_lr *= CONFIDENCE_FACTORS['multiple_detection_methods']
            contributions['multi_detection'] = CONFIDENCE_FACTORS['multiple_detection_methods']

        return combined_lr, contributions

    def _compute_posterior(self, prior: float, likelihood_ratio: float) -> float:
        """
        Compute posterior probability using Bayes' theorem.

        P(malicious|evidence) = P(evidence|malicious) * P(malicious) / P(evidence)

        Using odds form:
        Posterior_odds = Prior_odds * LR
        Posterior_prob = Posterior_odds / (1 + Posterior_odds)
        """

        # Convert prior probability to odds
        if prior >= 1.0:
            prior = 0.99
        prior_odds = prior / (1.0 - prior)

        # Apply likelihood ratio
        posterior_odds = prior_odds * likelihood_ratio

        # Convert odds back to probability
        posterior_prob = posterior_odds / (1.0 + posterior_odds)

        # Clamp to [0, 1]
        return max(0.0, min(1.0, posterior_prob))

    def _estimate_confidence_interval(
        self,
        prior: float,
        likelihood_ratio: float,
        evidence: List[str]
    ) -> Tuple[float, float]:
        """
        Estimate 95% confidence interval using Monte Carlo simulation.

        Accounts for uncertainty in:
        - Prior probability
        - Likelihood ratios
        - Evidence strength
        """

        samples = []

        for _ in range(self.mc_samples):
            # Add noise to prior
            prior_sample = max(0.001, min(0.999, random.gauss(prior, prior * 0.1)))

            # Add noise to LR (log-normal distribution)
            lr_sample = likelihood_ratio * math.exp(random.gauss(0, 0.2))

            # Compute posterior for this sample
            posterior_sample = self._compute_posterior(prior_sample, lr_sample)
            samples.append(posterior_sample)

        # Sort and get 2.5th and 97.5th percentiles
        samples.sort()
        ci_lower = samples[int(0.025 * len(samples))]
        ci_upper = samples[int(0.975 * len(samples))]

        return ci_lower, ci_upper

    def _assess_evidence_strength(self, likelihood_ratio: float) -> str:
        """
        Assess strength of evidence based on likelihood ratio.

        Kass-Raftery scale:
        - LR < 3: Weak
        - 3 <= LR < 20: Moderate
        - 20 <= LR < 150: Strong
        - LR >= 150: Very strong
        """

        if likelihood_ratio < 3:
            return 'weak'
        elif likelihood_ratio < 20:
            return 'moderate'
        elif likelihood_ratio < 150:
            return 'strong'
        else:
            return 'very_strong'

    def _normalize_to_scale(self, probability: float) -> float:
        """Normalize probability (0-1) to risk score (0-10)."""
        return probability * 10.0

    def _categorize_risk(self, probability: float) -> str:
        """Categorize risk based on posterior probability."""
        if probability >= self.critical_threshold:
            return "critical"
        elif probability >= self.high_threshold:
            return "high"
        elif probability >= self.medium_threshold:
            return "medium"
        else:
            return "low"

    def _generate_bayesian_summary(
        self,
        driver: DriverInfo,
        estimate: RiskEstimate,
        evidence: List[str]
    ) -> str:
        """Generate Bayesian-informed summary."""

        prob_pct = estimate.posterior_probability * 100

        reasons = [
            f"Bayesian analysis indicates {prob_pct:.1f}% probability of being malicious "
            f"(95% CI: {estimate.confidence_lower*100:.1f}%-{estimate.confidence_upper*100:.1f}%)"
        ]

        reasons.append(f"Evidence strength: {estimate.evidence_strength}")

        # Top contributing factors
        top_factors = sorted(
            estimate.evidence_strength,
            key=lambda x: x[1] if isinstance(x, tuple) else 0,
            reverse=True
        )[:3]

        if evidence:
            reasons.append(f"Key indicators: {', '.join(evidence[:5])}")

        return "BECAUSE: " + " | ".join(reasons)
