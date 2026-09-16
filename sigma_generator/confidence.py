"""
confidence.py — NullTracer Sigma Auto-Generator
================================================
Assigns a confidence level and a false-positive annotation to a generated
Sigma rule based on heuristics applied to the detection pattern.

WHY: Auto-generated rules tend to be noisy. By encoding confidence/FP logic
as data-driven heuristics rather than relying on an analyst to manually label
every rule, we can at minimum produce a starting annotation that reviewers
can override. This also makes the annotation logic auditable and testable.

Confidence levels mirror the Sigma specification:
  critical / high / medium / low

False-positive categories (from Sigma spec):
  Pentest, Admin, Security software, Developer, Legitimate administrator action
"""

from dataclasses import dataclass
from typing import List, Dict

# ---------------------------------------------------------------------------
# Internal confidence heuristic weights
# Each rule gets a score. The score bucket maps to a Sigma confidence level.
# ---------------------------------------------------------------------------

# Indicators that INCREASE confidence (more specific → less likely FP)
HIGH_SPECIFICITY_INDICATORS: List[str] = [
    # command-line contains encoding flags
    "-enc",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-noprofile",
    # known LOLbin paths
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "cscript.exe",
    "wscript.exe",
    "msiexec.exe",
    "cmd.exe /c",
    # typical lateral movement indicators
    "wmiprvse.exe",
    "\\appdata\\",
    "\\public\\",
    "\\temp\\",
]

# Indicators that DECREASE confidence (overly broad → high FP risk)
LOW_SPECIFICITY_INDICATORS: List[str] = [
    "powershell.exe",   # very common; needs more context
    "explorer.exe",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
]

SCORE_THRESHOLDS: Dict[str, int] = {
    "critical": 4,
    "high":     2,
    "medium":   0,
    "low":      -99,  # fallback
}

FP_ANNOTATIONS: Dict[str, List[str]] = {
    "critical": ["Unlikely - chain requires multiple LOLbin steps in sequence"],
    "high":     ["Low - chain involves LOLbin tooling but could be admin activity"],
    "medium":   ["Medium - PowerShell or scripting engine usage is common; review context"],
    "low":      ["High - single-step or generic match; tune before production deployment"],
}


@dataclass
class ConfidenceResult:
    level: str              # "critical" / "high" / "medium" / "low"
    score: int              # raw score for debugging
    false_positives: List[str]


def score_detection_block(detection_conditions: List[Dict[str, str]]) -> ConfidenceResult:
    """
    Assign a Sigma confidence level and false-positive annotation to a detection
    block derived from a NullTracer attack chain.

    Args:
        detection_conditions: List of dicts representing each step's condition
            set, e.g. [{"Image": "*\\\\powershell.exe", "CommandLine": "*-enc*"}, ...]

    Returns:
        ConfidenceResult with level, score, and false-positive strings.
    """
    score = 0
    num_steps = len(detection_conditions)

    # Multi-step chains are inherently more precise
    # Each additional step after the first adds confidence
    score += (num_steps - 1) * 2

    # Walk every condition value and apply heuristics
    for condition_dict in detection_conditions:
        for field_val in condition_dict.values():
            normalized = field_val.lower()
            for indicator in HIGH_SPECIFICITY_INDICATORS:
                if indicator in normalized:
                    score += 1
            for indicator in LOW_SPECIFICITY_INDICATORS:
                if indicator in normalized:
                    score -= 1

    # Determine level from score
    level = "low"
    for lvl, threshold in SCORE_THRESHOLDS.items():
        if score >= threshold:
            level = lvl
            break

    return ConfidenceResult(
        level=level,
        score=score,
        false_positives=FP_ANNOTATIONS[level],
    )
