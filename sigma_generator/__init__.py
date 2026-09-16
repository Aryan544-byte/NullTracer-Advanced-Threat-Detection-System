"""
sigma_generator — NullTracer Sigma Auto-Generator Package
==========================================================
Exposes the main public API for external callers:

    from sigma_generator import build_sigma_rule, compile_rule, rule_dict_to_sigma_yaml

Typical pipeline:
    chain      = parse_chain_yaml("samples/rules/lolbin_chain.yml")
    rule_dict  = build_sigma_rule(chain)
    sigma_yaml = rule_dict_to_sigma_yaml(rule_dict)
    queries    = compile_rule(rule_dict)
"""

from .rule_builder import build_sigma_rule
from .compiler import compile_rule, rule_dict_to_sigma_yaml
from .field_mapping import translate_field, PROCESS_FIELD_MAP, LOGSOURCE_MAP
from .confidence import score_detection_block, ConfidenceResult

__all__ = [
    "build_sigma_rule",
    "rule_dict_to_sigma_yaml",
    "compile_rule",
    "translate_field",
    "PROCESS_FIELD_MAP",
    "LOGSOURCE_MAP",
    "score_detection_block",
    "ConfidenceResult",
]
