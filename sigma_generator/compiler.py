"""
compiler.py — NullTracer Sigma Auto-Generator
=============================================
Compiles a Sigma rule dict (produced by rule_builder.py) into backend-specific
query strings using the pySigma library.

WHY pySigma over raw string templating: pySigma provides validated, maintained
backend pipelines for Splunk, Elastic, and Microsoft Sentinel. Rolling our own
templates would require us to manually track field name changes and syntax
differences across backend versions — that is the library's entire job.

Supported backends (installed via requirements.txt):
  - pysigma-backend-splunk   → Splunk SPL
  - pysigma-backend-elasticsearch → Elastic Query DSL / Lucene
  - pysigma-backend-microsoft365defender → Sentinel KQL

Usage:
    rule_dict = build_sigma_rule(chain)
    results   = compile_rule(rule_dict)
    print(results["splunk"])
    print(results["elastic"])
    print(results["sentinel"])
"""

import yaml
import io
from typing import Dict, Optional, Any

# pySigma core
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection

# pySigma backends — each is an optional install; we handle ImportError gracefully
try:
    from sigma.backends.splunk import SplunkBackend
    _HAS_SPLUNK = True
except ImportError:
    _HAS_SPLUNK = False

try:
    from sigma.backends.elasticsearch import LuceneBackend as ElasticBackend
    _HAS_ELASTIC = True
except ImportError:
    _HAS_ELASTIC = False

try:
    from sigma.backends.microsoft365defender import KustoBackend as SentinelBackend
    _HAS_SENTINEL = True
except ImportError:
    try:
        from sigma.backends.microsoft365defender import Microsoft365DefenderBackend as SentinelBackend
        _HAS_SENTINEL = True
    except ImportError:
        _HAS_SENTINEL = False


# ---------------------------------------------------------------------------
# Sigma custom-field strip helper
# ---------------------------------------------------------------------------
# pySigma is strict about unknown top-level keys. We strip the `custom` block
# before passing the rule dict to pySigma, then re-attach it to the output.

def _strip_custom(rule_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the rule dict with non-standard keys removed."""
    sigma_keys = {
        "title", "id", "status", "description", "references",
        "author", "date", "modified", "tags", "logsource",
        "detection", "fields", "falsepositives", "level",
    }
    return {k: v for k, v in rule_dict.items() if k in sigma_keys}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def rule_dict_to_sigma_yaml(rule_dict: Dict[str, Any]) -> str:
    """
    Serialize a NullTracer rule dict to a Sigma-compatible YAML string.

    Custom metadata (the `custom` block) is included as a comment header so it
    appears in the written file but does not confuse the pySigma parser.

    Returns:
        A YAML string representing the full Sigma rule (with NullTracer comment).
    """
    custom = rule_dict.pop("custom", {})
    
    # Build YAML for the clean Sigma portion
    sigma_yaml = yaml.dump(rule_dict, default_flow_style=False, allow_unicode=True, sort_keys=False)
    
    # Prepend NullTracer metadata as a YAML comment block
    comment_lines = ["# --- NullTracer Auto-Generated Rule ---"]
    for k, v in custom.items():
        comment_lines.append(f"# {k}: {v}")
    comment_lines.append("# ---------------------------------------")
    
    rule_dict["custom"] = custom  # restore for caller
    return "\n".join(comment_lines) + "\n" + sigma_yaml


def compile_rule(rule_dict: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Compile a Sigma rule dict to all available backend query languages.

    Steps:
      1. Strip NullTracer-custom keys so pySigma can parse the rule.
      2. Serialize the clean dict to YAML (pySigma accepts YAML strings).
      3. Parse via SigmaCollection.from_yaml().
      4. Call each available backend and collect results.

    Args:
        rule_dict: Full rule dict as produced by rule_builder.build_sigma_rule().

    Returns:
        Dict with keys "splunk", "elastic", "sentinel". Value is the compiled
        query string, or None if the backend is not installed, or an error
        message string prefixed with "ERROR:" if compilation failed.
    """
    clean_dict = _strip_custom(rule_dict)
    sigma_yaml_str = yaml.dump(clean_dict, default_flow_style=False, allow_unicode=True, sort_keys=False)

    # Parse the Sigma collection from the YAML string
    try:
        collection = SigmaCollection.from_yaml(sigma_yaml_str)
    except Exception as exc:
        error_msg = f"ERROR: pySigma failed to parse rule YAML — {exc}"
        return {"splunk": error_msg, "elastic": error_msg, "sentinel": error_msg}

    results: Dict[str, Optional[str]] = {}

    # ------------------------------------------------------------------
    # Splunk SPL
    # ------------------------------------------------------------------
    if _HAS_SPLUNK:
        try:
            backend = SplunkBackend()
            queries = backend.convert(collection)
            # convert() returns a list of query strings (one per rule in collection)
            results["splunk"] = "\n".join(queries) if queries else "# No output from Splunk backend"
        except Exception as exc:
            results["splunk"] = f"ERROR: Splunk backend — {exc}"
    else:
        results["splunk"] = (
            "# pysigma-backend-splunk not installed. "
            "Run: pip install pysigma-backend-splunk"
        )

    # ------------------------------------------------------------------
    # Elastic Lucene / Query DSL
    # ------------------------------------------------------------------
    if _HAS_ELASTIC:
        try:
            backend = ElasticBackend()
            queries = backend.convert(collection)
            results["elastic"] = "\n".join(queries) if queries else "# No output from Elastic backend"
        except Exception as exc:
            results["elastic"] = f"ERROR: Elastic backend — {exc}"
    else:
        results["elastic"] = (
            "# pysigma-backend-elasticsearch not installed. "
            "Run: pip install pysigma-backend-elasticsearch"
        )

    # ------------------------------------------------------------------
    # Microsoft Sentinel KQL
    # ------------------------------------------------------------------
    if _HAS_SENTINEL:
        try:
            backend = SentinelBackend()
            queries = backend.convert(collection)
            results["sentinel"] = "\n".join(queries) if queries else "# No output from Sentinel backend"
        except Exception as exc:
            results["sentinel"] = f"ERROR: Sentinel backend — {exc}"
    else:
        results["sentinel"] = (
            "# pysigma-backend-microsoft365defender not installed. "
            "Run: pip install pysigma-backend-microsoft365defender"
        )

    return results
