from __future__ import annotations
import argparse
import json
from pathlib import Path
from .engine import analyze_components, generate_cyclonedx
from .scanner import scan_path


def main() -> int:
    parser = argparse.ArgumentParser(prog="scs", description="Offline software supply-chain risk analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a project directory or supported manifest")
    scan.add_argument("path")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--output")
    scan.add_argument("--sbom", help="Write CycloneDX JSON SBOM to this path")
    args = parser.parse_args()
    if args.command == "scan":
        components, extra, scanned = scan_path(args.path)
        result = analyze_components(components, extra)
        result["scanned_files"] = scanned
        rendered = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        if args.format == "json":
            print(rendered)
        else:
            s = result["summary"]
            print(f"SupplyChainSentry | {len(scanned)} files | {s['components']} components | risk score {s['risk_score']}/100")
            for f in result["findings"]:
                print(f"[{f['severity'].upper()}] {f['rule_id']} {f['title']} — {f['component']}")
            if not result["findings"]:
                print("No heuristic findings detected.")
        if args.sbom:
            Path(args.sbom).write_text(json.dumps(generate_cyclonedx(components), indent=2) + "\n", encoding="utf-8")
        return 0
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
