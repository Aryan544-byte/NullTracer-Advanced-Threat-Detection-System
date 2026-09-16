"""
cli.py — NullTracer Sigma Auto-Generator Entry Point
=====================================================
A command-line interface for running the Sigma rule auto-generation pipeline.

Usage:
    # Generate a Sigma YAML rule and all compiled backends from a chain rule file
    python -m sigma_generator.cli --rule samples/rules/lolbin_chain.yml --output samples/sigma_output/

    # Show only the Splunk SPL query
    python -m sigma_generator.cli --rule samples/rules/lolbin_chain.yml --backend splunk

    # Pass a telemetry file as enrichment hint
    python -m sigma_generator.cli --rule samples/rules/lolbin_chain.yml \
        --telemetry samples/telemetry/synthetic_events.json --output samples/sigma_output/
"""

import argparse
import json
import os
import sys
import yaml

# Ensure the project root is importable when running as `python -m sigma_generator.cli`
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.schema import parse_chain_yaml
from .rule_builder import build_sigma_rule, rule_dict_to_sigma_yaml  # noqa: E402
from .compiler import compile_rule                                     # noqa: E402


BANNER = """
╔══════════════════════════════════════════════════╗
║         NullTracer — Sigma Auto-Generator        ║
║  Attack Chain YAML → Sigma YAML + SPL/DSL/KQL   ║
╚══════════════════════════════════════════════════╝
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sigma_generator",
        description="Generate Sigma rules from NullTracer attack-chain YAML files.",
    )
    parser.add_argument(
        "--rule", "-r",
        required=True,
        metavar="RULE_YAML",
        help="Path to a NullTracer chain rule YAML file (e.g. samples/rules/lolbin_chain.yml).",
    )
    parser.add_argument(
        "--telemetry", "-t",
        required=False,
        metavar="TELEMETRY_JSON",
        help="Optional path to a synthetic telemetry JSON file to enrich field values.",
    )
    parser.add_argument(
        "--output", "-o",
        required=False,
        metavar="OUTPUT_DIR",
        help=(
            "Directory to write output files into. "
            "Writes <rule_id>.yml (Sigma YAML) and <rule_id>_<backend>.txt for each backend. "
            "If omitted, prints everything to stdout."
        ),
    )
    parser.add_argument(
        "--backend", "-b",
        choices=["splunk", "elastic", "sentinel", "all"],
        default="all",
        help="Which backend to compile for. Default: all.",
    )
    return parser.parse_args()


def load_telemetry(path: str):
    """Load a JSON list of telemetry events from a file."""
    with open(path, "r") as f:
        return json.load(f)


def write_output(output_dir: str, chain_id: str, sigma_yaml: str, compiled: dict, backend: str):
    """Write generated files to the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    # Write the Sigma YAML rule
    sigma_path = os.path.join(output_dir, f"{chain_id}.yml")
    with open(sigma_path, "w") as f:
        f.write(sigma_yaml)
    print(f"  [+] Sigma YAML  → {sigma_path}")

    # Write each requested compiled backend output
    targets = ["splunk", "elastic", "sentinel"] if backend == "all" else [backend]
    for target in targets:
        query = compiled.get(target, "# not available")
        out_path = os.path.join(output_dir, f"{chain_id}_{target}.txt")
        with open(out_path, "w") as f:
            f.write(f"# NullTracer auto-generated {target.upper()} query\n")
            f.write(f"# Chain ID: {chain_id}\n\n")
            f.write(query)
        print(f"  [+] {target.upper():8s} query → {out_path}")


def main():
    print(BANNER)
    args = parse_args()

    # 1. Parse the chain rule YAML
    print(f"[*] Loading chain rule: {args.rule}")
    chain = parse_chain_yaml(args.rule)
    print(f"    ID          : {chain.id}")
    print(f"    Name        : {chain.name}")
    print(f"    Steps       : {len(chain.steps)}")
    print(f"    MITRE tags  : {', '.join(chain.mitre_tags)}")

    # 2. Load optional telemetry enrichment
    telemetry = None
    if args.telemetry:
        print(f"[*] Loading telemetry enrichment: {args.telemetry}")
        telemetry = load_telemetry(args.telemetry)
        print(f"    Events loaded: {len(telemetry)}")

    # 3. Build the Sigma rule dict
    print("[*] Building Sigma rule...")
    rule_dict = build_sigma_rule(chain, telemetry_hint=telemetry)
    print(f"    Confidence  : {rule_dict['level']}")
    print(f"    False pos.  : {rule_dict['falsepositives']}")

    # 4. Serialize to Sigma YAML
    sigma_yaml = rule_dict_to_sigma_yaml(rule_dict)

    # 5. Compile to backend queries
    print("[*] Compiling to backend queries...")
    compiled = compile_rule(rule_dict)

    # 6. Output
    if args.output:
        print(f"[*] Writing output to: {args.output}")
        write_output(args.output, chain.id, sigma_yaml, compiled, args.backend)
    else:
        targets = ["splunk", "elastic", "sentinel"] if args.backend == "all" else [args.backend]
        print("\n" + "=" * 60)
        print("SIGMA YAML")
        print("=" * 60)
        print(sigma_yaml)
        for target in targets:
            print("=" * 60)
            print(f"{target.upper()} QUERY")
            print("=" * 60)
            print(compiled.get(target, "# not available"))

    print("\n[✓] Done.")


if __name__ == "__main__":
    main()
