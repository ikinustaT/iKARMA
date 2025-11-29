"""
Indicator detector for high-confidence BYOVD behaviors.

This module looks for short, high-signal instruction sequences and artifacts
that are harder to explain away as noise (e.g., WP disable chains).
It returns structured findings the capability plugin can surface and export.
"""

from typing import List, Dict, Any

# Indicator definitions with risk weights and descriptions
INDICATOR_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "WP_DISABLE_SEQUENCE": {
        "risk_weight": 50,
        "description": "Write-protect bit tampering sequence (cli + mov cr0 ... + sti/none)"
    },
    "WRMSR_USAGE": {
        "risk_weight": 20,
        "description": "WRMSR instruction present (MSR manipulation)"
    },
    "PHYS_MAP_API": {
        "risk_weight": 20,
        "description": "References to MmMapIoSpace/physical mapping APIs"
    },
    "PORT_IO_HEAVY": {
        "risk_weight": 15,
        "description": "Multiple privileged IN/OUT instructions (I/O port access)"
    },
}


def _detect_wp_disable(disasm: List[str]) -> List[Dict[str, Any]]:
    findings = []
    for i, line in enumerate(disasm):
        text = line.lower()
        if " cli" in text or text.strip().startswith("0x") and "\tcli" in text:
            # Look ahead a few instructions for mov cr0
            window = disasm[i + 1:i + 6]
            for w in window:
                if "mov" in w.lower() and "cr0" in w.lower():
                    evidence = f"{text.strip()} -> {w.strip()}"
                    findings.append({
                        "indicator_type": "WP_DISABLE_SEQUENCE",
                        "evidence": evidence,
                        "because": "Write-protect bit tampering sequence detected (cli + mov cr0 ...)",
                        "risk_weight": INDICATOR_DEFINITIONS["WP_DISABLE_SEQUENCE"]["risk_weight"]
                    })
                    break
    return findings


def _detect_wrmsr(disasm: List[str]) -> List[Dict[str, Any]]:
    findings = []
    for line in disasm:
        if "wrmsr" in line.lower():
            findings.append({
                "indicator_type": "WRMSR_USAGE",
                "evidence": line.strip(),
                "because": "WRMSR instruction manipulates CPU MSRs",
                "risk_weight": INDICATOR_DEFINITIONS["WRMSR_USAGE"]["risk_weight"]
            })
    return findings


def _detect_phys_map(disasm: List[str]) -> List[Dict[str, Any]]:
    findings = []
    for line in disasm:
        lower = line.lower()
        if "mmmapiospace" in lower or "mapio" in lower or "physical" in lower:
            findings.append({
                "indicator_type": "PHYS_MAP_API",
                "evidence": line.strip(),
                "because": "Physical mapping API or string reference",
                "risk_weight": INDICATOR_DEFINITIONS["PHYS_MAP_API"]["risk_weight"]
            })
    return findings


def _detect_port_io(disasm: List[str]) -> List[Dict[str, Any]]:
    count = 0
    examples = []
    for line in disasm:
        lower = line.lower()
        if "\tout" in lower or "\tin" in lower:
            count += 1
            if len(examples) < 3:
                examples.append(line.strip())
    if count >= 3:
        return [{
            "indicator_type": "PORT_IO_HEAVY",
            "evidence": "; ".join(examples),
            "because": f"{count} IN/OUT instructions detected (I/O port access)",
            "risk_weight": INDICATOR_DEFINITIONS["PORT_IO_HEAVY"]["risk_weight"]
        }]
    return []


def analyze_driver_indicators(disassembly: List[str], raw_bytes: bytes = b"") -> Dict[str, Any]:
    """Analyze disassembly and return high-confidence indicator findings."""
    all_findings: List[Dict[str, Any]] = []
    all_findings.extend(_detect_wp_disable(disassembly))
    all_findings.extend(_detect_wrmsr(disassembly))
    all_findings.extend(_detect_phys_map(disassembly))
    all_findings.extend(_detect_port_io(disassembly))

    summary: Dict[str, int] = {}
    total_risk = 0
    for f in all_findings:
        itype = f["indicator_type"]
        summary[itype] = summary.get(itype, 0) + 1
        total_risk += f.get("risk_weight", 0)

    return {
        "indicator_count": len(summary),
        "finding_count": len(all_findings),
        "total_risk_weight": total_risk,
        "summary": summary,
        "findings": all_findings,
    }


def format_indicator_report(indicator_findings: Dict[str, Any]) -> str:
    """Format findings into a human-readable report string."""
    if not indicator_findings or indicator_findings.get("finding_count", 0) == 0:
        return "No high-confidence indicators detected."
    lines = []
    lines.append(f"{indicator_findings['finding_count']} high-confidence indicator(s) detected")
    for itype, count in indicator_findings.get("summary", {}).items():
        defn = INDICATOR_DEFINITIONS.get(itype, {})
        lines.append(f"- {itype}: {count} (risk +{defn.get('risk_weight', 0)})")
    for f in indicator_findings.get("findings", []):
        lines.append(f"  [{f['indicator_type']}] {f['evidence']} :: {f['because']}")
    return "\n".join(lines)
