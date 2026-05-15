#!/usr/bin/env python3
"""
Agent Memory Guard Scanner — Static analysis for OWASP ASI06 memory poisoning vulnerabilities.

Scans Python codebases for common memory poisoning attack patterns in AI agent frameworks.
Part of the OWASP Agent Memory Guard project.
"""

import argparse
import ast
import json
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class Finding:
    """A memory security finding."""
    file: str
    line: int
    severity: str
    category: str
    description: str
    recommendation: str
    owasp_ref: str = "ASI06"


# Patterns that indicate unprotected memory operations
UNSAFE_PATTERNS = {
    "unvalidated_memory_store": {
        "severity": "high",
        "category": "Unvalidated Memory Store",
        "description": "Memory is stored without integrity validation. An attacker could inject poisoned memories.",
        "recommendation": "Wrap memory store operations with agent_memory_guard.validate() before persisting.",
        "indicators": [
            "memory.save_context",
            "memory.add_message",
            "memory.add_memory",
            "memory.chat_memory.add",
            "ConversationBufferMemory",
            "ConversationSummaryMemory",
            "VectorStoreRetrieverMemory",
            ".add_texts(",
            ".add_documents(",
            "mem0.add(",
            "memory_store.put(",
        ]
    },
    "unprotected_memory_retrieval": {
        "severity": "medium",
        "category": "Unprotected Memory Retrieval",
        "description": "Memory is retrieved without integrity verification. Poisoned memories could influence agent behavior.",
        "recommendation": "Use agent_memory_guard.verify() to check memory integrity before using retrieved context.",
        "indicators": [
            "memory.load_memory_variables",
            "memory.get_relevant",
            "memory.search(",
            "retriever.get_relevant_documents",
            "retriever.invoke(",
            "mem0.search(",
            "memory_store.get(",
        ]
    },
    "shared_memory_no_isolation": {
        "severity": "critical",
        "category": "Shared Memory Without Isolation",
        "description": "Multiple agents share memory without tenant isolation. Cross-agent memory poisoning is possible.",
        "recommendation": "Implement per-agent memory namespaces with agent_memory_guard.isolate().",
        "indicators": [
            "shared_memory",
            "global_memory",
            "team_memory",
            "crew_memory",
            "shared_context",
        ]
    },
    "no_memory_audit_logging": {
        "severity": "low",
        "category": "Missing Memory Audit Trail",
        "description": "Memory operations lack audit logging. Memory poisoning attacks may go undetected.",
        "recommendation": "Enable agent_memory_guard.audit_log() for all memory operations.",
        "indicators": [
            "memory.clear()",
            "memory.delete(",
            "memory.update(",
        ]
    },
    "raw_user_input_to_memory": {
        "severity": "critical",
        "category": "Raw User Input Stored in Memory",
        "description": "User input is stored directly in agent memory without sanitization. This is the primary memory poisoning vector.",
        "recommendation": "Sanitize all user inputs with agent_memory_guard.sanitize() before storing in memory.",
        "indicators": [
            "user_input",
            "human_message",
            "HumanMessage(",
            "user_message",
        ]
    }
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def scan_file(filepath: str, severity_threshold: str) -> List[Finding]:
    """Scan a single Python file for memory poisoning vulnerabilities."""
    findings = []
    threshold = SEVERITY_ORDER.get(severity_threshold, 1)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            content = "".join(lines)
    except (IOError, OSError):
        return findings

    # Check if file is relevant (contains memory-related imports or patterns)
    memory_keywords = ["memory", "Memory", "retriever", "Retriever", "mem0", "vector_store"]
    if not any(kw in content for kw in memory_keywords):
        return findings

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
            continue

        for pattern_id, pattern_info in UNSAFE_PATTERNS.items():
            if SEVERITY_ORDER.get(pattern_info["severity"], 0) < threshold:
                continue

            for indicator in pattern_info["indicators"]:
                if indicator in line:
                    # Check if agent_memory_guard is already protecting this operation
                    context_start = max(0, line_num - 5)
                    context_end = min(len(lines), line_num + 2)
                    context = "".join(lines[context_start:context_end])

                    if "agent_memory_guard" in context or "memory_guard" in context:
                        continue  # Already protected

                    findings.append(Finding(
                        file=filepath,
                        line=line_num,
                        severity=pattern_info["severity"],
                        category=pattern_info["category"],
                        description=pattern_info["description"],
                        recommendation=pattern_info["recommendation"],
                    ))
                    break  # One finding per line per pattern

    return findings


def scan_directory(scan_path: str, severity_threshold: str) -> List[Finding]:
    """Recursively scan a directory for memory poisoning vulnerabilities."""
    all_findings = []
    scan_root = Path(scan_path)

    if scan_root.is_file() and scan_root.suffix == ".py":
        return scan_file(str(scan_root), severity_threshold)

    for py_file in scan_root.rglob("*.py"):
        # Skip common non-project directories
        parts = py_file.parts
        if any(skip in parts for skip in [
            "node_modules", ".venv", "venv", "__pycache__",
            ".git", ".tox", "dist", "build", "egg-info"
        ]):
            continue

        findings = scan_file(str(py_file), severity_threshold)
        all_findings.extend(findings)

    return all_findings


def calculate_risk_score(findings: List[Finding]) -> int:
    """Calculate an overall risk score from 0-100."""
    if not findings:
        return 0

    severity_weights = {"low": 5, "medium": 15, "high": 30, "critical": 50}
    total_weight = sum(severity_weights.get(f.severity, 0) for f in findings)
    return min(100, total_weight)


def generate_report(findings: List[Finding], scan_path: str) -> dict:
    """Generate a structured scan report."""
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "scanner": "agent-memory-guard",
        "version": "0.2.1",
        "owasp_reference": "ASI06 - Memory Poisoning",
        "scan_path": scan_path,
        "total_findings": len(findings),
        "risk_score": calculate_risk_score(findings),
        "severity_breakdown": severity_counts,
        "findings": [asdict(f) for f in findings],
        "remediation_guide": "https://github.com/OWASP/www-project-agent-memory-guard#quickstart",
        "owasp_agentic_top10": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/"
    }


def main():
    parser = argparse.ArgumentParser(description="Agent Memory Guard Scanner")
    parser.add_argument("--path", default=".", help="Path to scan")
    parser.add_argument("--severity", default="medium", help="Minimum severity threshold")
    parser.add_argument("--config", default=None, help="Configuration file path")
    parser.add_argument("--output", default="memory-guard-report.json", help="Output report path")
    args = parser.parse_args()

    print(f"\U0001f6e1\ufe0f  Agent Memory Guard Scanner v0.2.1")
    print(f"\U0001f4cb OWASP Reference: ASI06 (Memory Poisoning)")
    print(f"\U0001f50d Scanning: {args.path}")
    print(f"\u26a0\ufe0f  Severity threshold: {args.severity}")
    print()

    findings = scan_directory(args.path, args.severity)
    report = generate_report(findings, args.path)

    # Write report
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # Set GitHub Actions outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"findings-count={len(findings)}\n")
            f.write(f"report-path={args.output}\n")
            f.write(f"risk-score={report['risk_score']}\n")

    # Print summary
    if findings:
        print(f"\u26a0\ufe0f  Found {len(findings)} memory poisoning vulnerabilities:")
        for sev in ["critical", "high", "medium", "low"]:
            count = report["severity_breakdown"].get(sev, 0)
            if count:
                emoji = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "\U0001f535"}
                print(f"  {emoji.get(sev, '\u26aa')} {sev.upper()}: {count}")
        print()
        print(f"\U0001f4ca Risk Score: {report['risk_score']}/100")
        print(f"\U0001f4c4 Full report: {args.output}")
        print(f"\U0001f527 Remediation: pip install agent-memory-guard")
    else:
        print("\u2705 No memory poisoning vulnerabilities found!")
        print(f"\U0001f4ca Risk Score: 0/100")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
