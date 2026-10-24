#!/usr/bin/env python3
"""
ForensiQ AI - Command Line Forensic Investigation Utility
Usage:
  python3 forensiq_cli.py hash <file_or_string>
  python3 forensiq_cli.py triage <log_file>
  python3 forensiq_cli.py extract-iocs <log_file>
  python3 forensiq_cli.py report <case_id> <log_file>
"""

import sys
import os
import argparse
import json
from forensiq.hasher import compute_sha256, compute_md5, generate_custody_seal
from forensiq.ioc_extractor import extract_iocs
from forensiq.timeline import parse_timeline
from forensiq.mitre import map_events_to_mitre
from forensiq.ollama_client import generate_deterministic_analysis, is_ollama_available, query_ollama
from forensiq.report_generator import generate_markdown_report


def main():
    parser = argparse.ArgumentParser(
        description="ForensiQ AI - Open-Source Digital Forensics Investigation Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Forensic action to execute")

    # Hash Command
    hash_parser = subparsers.add_parser("hash", help="Compute SHA-256 and MD5 bitstream hashes")
    hash_parser.add_argument("target", help="File path or string to hash")

    # Triage Command
    triage_parser = subparsers.add_parser("triage", help="Triage log stream and detect anomalies")
    triage_parser.add_argument("file", help="Path to evidence log file")
    triage_parser.add_argument("--case", default="CAS-2026-0891", help="Case Reference ID")

    # IOCs Command
    ioc_parser = subparsers.add_parser("extract-iocs", help="Extract indicators of compromise")
    ioc_parser.add_argument("file", help="Path to evidence log file")

    # Report Command
    report_parser = subparsers.add_parser("report", help="Generate court-admissible forensic report")
    report_parser.add_argument("case_id", help="Case Reference ID")
    report_parser.add_argument("file", help="Path to evidence log file")
    report_parser.add_argument("--out", default="forensic_report.md", help="Output file path")

    args = parser.parse_args()

    if args.command == "hash":
        target = args.target
        if os.path.exists(target):
            with open(target, "rb") as f:
                content = f.read()
            print(f"Target: [FILE] {target}")
            print(f"Size:   {len(content)} bytes")
            print(f"SHA256: {compute_sha256(content)}")
            print(f"MD5:    {compute_md5(content)}")
        else:
            print(f"Target: [STRING] {target}")
            print(f"SHA256: {compute_sha256(target)}")
            print(f"MD5:    {compute_md5(target)}")

    elif args.command == "triage":
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        events = parse_timeline(text, os.path.basename(args.file))
        iocs = extract_iocs(text)
        case_data = {
            "case_id": args.case,
            "incident_type": "Host Intrusion & Forensic Triage",
            "classification": "TLP:AMBER+STRICT"
        }

        analysis = generate_deterministic_analysis(case_data, events, iocs)
        print(analysis)

    elif args.command == "extract-iocs":
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        iocs = extract_iocs(text)
        print(f"Extracted {len(iocs)} Indicators of Compromise:")
        print(json.dumps(iocs, indent=2))

    elif args.command == "report":
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        filename = os.path.basename(args.file)
        sha256 = compute_sha256(text)
        evidence_items = [{
            "id": "EVD-001",
            "filename": filename,
            "file_type": "raw_logs",
            "sha256": sha256,
            "write_blocker_model": "Tableau Forensic Bridge"
        }]

        events = parse_timeline(text, filename)
        iocs = extract_iocs(text)
        case_data = {
            "case_id": args.case_id,
            "incident_type": "Ransomware / Host Intrusion",
            "classification": "TLP:AMBER+STRICT",
            "agency": "Cyber Incident Response Unit",
            "examiner_name": "Lead Forensic Specialist",
            "case_summary": f"Automated digital forensics investigation of {filename}."
        }

        findings = generate_deterministic_analysis(case_data, events, iocs)
        report_md = generate_markdown_report(case_data, evidence_items, events, iocs, findings)

        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"Court-admissible forensic report successfully written to {args.out}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
