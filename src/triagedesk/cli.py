"""Command-line interface.

Examples::

    triagedesk rules
    triagedesk analyze data/samples/auth.log data/samples/access.log
    triagedesk analyze data/samples/*.log --report reports/case.md --json reports/case.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triagedesk import __version__
from triagedesk.ai import OfflineSummariser
from triagedesk.config import load_settings
from triagedesk.detection import load_rules
from triagedesk.pipeline import InputError, InputFile, analyze
from triagedesk.report import render_json, render_markdown


def _print_rules() -> int:
    rules = load_rules()
    print(f"{'Rule':<11} {'Type':<10} {'Severity':<9} {'Techniques':<24} Title")
    for rule in rules:
        print(
            f"{rule.rule_id:<11} {rule.rule_type:<10} {rule.severity:<9} "
            f"{', '.join(rule.techniques):<24} {rule.title}"
        )
    print(f"\n{len(rules)} rules loaded and validated.")
    return 0


def _analyze(args: argparse.Namespace) -> int:
    settings = load_settings()
    files = []
    for path in args.files:
        if not path.is_file():
            print(f"error: {path} does not exist", file=sys.stderr)
            return 2
        files.append(InputFile(name=path.name, data=path.read_bytes(), source_type=args.type))
    summariser = OfflineSummariser() if args.offline else None
    try:
        result = analyze(files, settings=settings, summariser=summariser)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Case {result.case_id}  (summaries: {result.summariser}, enrichment: {result.enrichment_mode})")
    for record in result.evidence:
        print(
            f"  {record.file_tag} {record.file_name}: {record.source_type}, "
            f"{record.lines_parsed} events, {record.lines_ignored} ignored, "
            f"{record.lines_malformed} malformed, sha256 {record.sha256[:16]}..."
        )
    print(f"\n{len(result.alerts)} alerts in {len(result.incidents)} incidents\n")
    print(f"{'Incident':<9} {'Priority':<9} {'Score':<6} {'Source':<16} {'Assessment':<17} Rules")
    for incident in result.incidents:
        rules = ", ".join(sorted({a.rule_id for a in incident.alerts}))
        assessment = incident.summary.assessment if incident.summary else "-"
        print(
            f"{incident.incident_id:<9} {incident.priority:<9} {incident.score:<6} "
            f"{incident.entity:<16} {assessment:<17} {rules}"
        )

    for target, render in ((args.report, render_markdown), (args.json, render_json)):
        if target:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(render(result), encoding="utf-8")
            print(f"\nWrote {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="triagedesk", description="Evidence-grounded log triage.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("rules", help="list and validate the detection rules")

    run = commands.add_parser("analyze", help="analyse one or more log files")
    run.add_argument("files", nargs="+", type=Path, help="log files to analyse")
    run.add_argument("--type", choices=["ssh", "web"], help="force the log type for every file")
    run.add_argument("--report", type=Path, help="write the Markdown report to this path")
    run.add_argument("--json", type=Path, help="write the JSON export to this path")
    run.add_argument("--offline", action="store_true", help="never call the language model")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return _print_rules()
    return _analyze(args)


if __name__ == "__main__":
    raise SystemExit(main())
