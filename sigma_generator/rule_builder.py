"""
rule_builder.py — NullTracer Sigma Auto-Generator
==================================================
Translates a NullTracer AttackChain (loaded from a YAML rule file) and
optionally a set of observed telemetry events into a valid Sigma rule dict,
which can then be serialized to YAML or passed to the compiler.

WHY: Keeping rule *construction* separate from rule *compilation* makes this
pipeline composable. You can build a rule dict from a chain definition, inspect
it, mutate it, or pass it directly to a backend without re-reading files.

Sigma rule structure reference:
  https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md
"""

import uuid
import datetime
from typing import Dict, Any, List, Optional

from engine.schema import AttackChain
from .field_mapping import LOGSOURCE_MAP, translate_field
from .confidence import score_detection_block, ConfidenceResult


# ---------------------------------------------------------------------------
# Sigma wildcard helpers
# ---------------------------------------------------------------------------

def _make_contains_pattern(value: str) -> str:
    """
    Wrap a raw value in Sigma wildcard notation for a substring match.
    e.g. "powershell.exe" -> "*\\powershell.exe"
    """
    # If it already looks like a path fragment, anchor from the right
    if "\\" in value or "/" in value:
        return f"*\\{value.lstrip('*\\/')}"
    return f"*{value}*"


def _build_selection_block(
    step_name: str,
    event_type: str,
    conditions: Dict[str, str],
) -> Dict[str, Any]:
    """
    Convert a single chain step's condition dict into a Sigma selection block.

    Each NullTracer condition uses internal field names (snake_case).
    We translate to Sigma fields here and apply wildcard wrapping.

    Args:
        step_name:   Human-readable label for this step (becomes selection key).
        event_type:  NullTracer event type string ("ProcessCreate", etc.).
        conditions:  Dict of {internal_field: match_value} from the YAML rule.

    Returns:
        Dict like {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"}
    """
    block: Dict[str, Any] = {}
    for internal_field, raw_value in conditions.items():
        sigma_field = translate_field(event_type, internal_field)
        if sigma_field is None:
            # Field has no Sigma mapping — skip with a comment key so it's visible
            block[f"# UNMAPPED_{internal_field}"] = raw_value
            continue

        # Choose the appropriate Sigma modifier based on the value shape
        if raw_value.startswith("^") and raw_value.endswith("$"):
            # Exact match (regex anchors stripped for Sigma)
            block[sigma_field] = raw_value[1:-1]
        elif "\\" in raw_value or "/" in raw_value:
            # Path-like value — use endswith modifier
            block[f"{sigma_field}|endswith"] = f"\\{raw_value.lstrip('*\\/')}"
        else:
            # Substring match — use contains modifier
            block[f"{sigma_field}|contains"] = raw_value

    return block


def build_sigma_rule(
    chain: AttackChain,
    telemetry_hint: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build a complete Sigma rule dict from a NullTracer AttackChain object.

    The generated rule is a *chain detection* rule: it emits one Sigma rule
    per chain step linked with a temporal `|near` filter where the backend
    supports it, or falls back to a single composite selection.

    WHY multi-step design: LOLbin attack chains are defined by their *sequence*
    and *process lineage*, not just individual events. A single-step Sigma rule
    for "PowerShell with -enc" has a very high FP rate. Chaining selections
    together dramatically reduces that rate.

    Args:
        chain:           Parsed AttackChain from engine/schema.py.
        telemetry_hint:  Optional list of observed telemetry event dicts that
                         can be used to enrich field values (e.g. actual paths).

    Returns:
        A dict representing the full Sigma rule, ready to be YAML-serialized.
    """
    # Determine the dominant event type for the logsource block.
    # We pick the type of the FIRST step (most chains start with ProcessCreate).
    primary_event_type = chain.steps[0].event_type if chain.steps else "ProcessCreate"
    logsource = LOGSOURCE_MAP.get(primary_event_type, {"category": "process_creation", "product": "windows"})

    # ------------------------------------------------------------------
    # Build detection blocks — one named selection per chain step
    # ------------------------------------------------------------------
    detection: Dict[str, Any] = {}
    condition_blocks: List[Dict[str, str]] = []

    for idx, step in enumerate(chain.steps):
        # Sigma selection keys must be valid YAML identifiers; use "selection_N"
        selection_key = f"selection_{idx + 1}"
        block = _build_selection_block(selection_key, step.event_type, step.conditions)
        detection[selection_key] = block
        condition_blocks.append(block)

    # ------------------------------------------------------------------
    # Sigma condition expression
    # ------------------------------------------------------------------
    # For single-step chains: just reference the one selection.
    # For multi-step chains: join all selections with `and` so the rule fires
    # only when ALL steps are observed (per-event basis on most backends).
    # NOTE: True temporal ordering requires a SIEM-side pipe or `|near` which
    # not all backends support. We annotate this in the rule tags.
    if len(chain.steps) == 1:
        detection["condition"] = "selection_1"
    else:
        selection_keys = " and ".join(f"selection_{i+1}" for i in range(len(chain.steps)))
        detection["condition"] = selection_keys

    # ------------------------------------------------------------------
    # Confidence and false-positive annotation
    # ------------------------------------------------------------------
    conf: ConfidenceResult = score_detection_block(condition_blocks)

    # ------------------------------------------------------------------
    # Assemble the full Sigma rule dict
    # ------------------------------------------------------------------
    rule: Dict[str, Any] = {
        "title": f"NullTracer: {chain.name}",
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": (
            f"{chain.description} "
            f"Auto-generated by NullTracer sigma_generator from chain '{chain.id}'."
        ),
        "references": [
            "https://attack.mitre.org/techniques/" + tag.replace(".", "/")
            for tag in chain.mitre_tags
        ],
        "author": "NullTracer Auto-Generator",
        "date": datetime.date.today().isoformat(),
        "tags": [
            f"attack.{tag.lower()}" for tag in chain.mitre_tags
        ],
        "logsource": logsource,
        "detection": detection,
        "falsepositives": conf.false_positives,
        "level": conf.level,
        # Custom NullTracer metadata block (non-standard, ignored by pySigma)
        "custom": {
            "nulltracer_chain_id": chain.id,
            "confidence_score": conf.score,
            "note": (
                "Multi-step detection: condition requires all selections to match "
                "within a single log query. For temporal ordering, wrap in a "
                "SIEM-side correlation rule or use |near modifier where available."
            ),
        },
    }

    return rule
