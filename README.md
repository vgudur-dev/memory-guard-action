# Agent Memory Guard Scanner — GitHub Action

[![OWASP](https://img.shields.io/badge/OWASP-ASI06-blue)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/)
[![PyPI](https://img.shields.io/pypi/v/agent-memory-guard)](https://pypi.org/project/agent-memory-guard/)
[![Downloads](https://static.pepy.tech/badge/agent-memory-guard)](https://pepy.tech/project/agent-memory-guard)

**Scan your AI agent codebase for OWASP ASI06 memory poisoning vulnerabilities in CI/CD.**

This GitHub Action automatically detects unprotected memory operations in AI agent codebases that could be exploited for memory poisoning attacks — the #6 threat in the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/).

## What It Detects

| Category | Severity | Description |
|----------|----------|-------------|
| Raw User Input to Memory | Critical | User input stored directly in agent memory without sanitization |
| Shared Memory Without Isolation | Critical | Multiple agents sharing memory without tenant isolation |
| Unvalidated Memory Store | High | Memory stored without integrity validation |
| Unprotected Memory Retrieval | Medium | Memory retrieved without integrity verification |
| Missing Memory Audit Trail | Low | Memory operations lacking audit logging |

## Quick Start

```yaml
name: Memory Security Scan
on: [push, pull_request]

jobs:
  memory-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OWASP/memory-guard-action@v1
        with:
          scan-path: './src'
          severity-threshold: 'medium'
          fail-on-findings: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Path to scan for vulnerabilities | `.` |
| `severity-threshold` | Minimum severity to report | `medium` |
| `fail-on-findings` | Fail the workflow if vulnerabilities are found | `true` |
| `config-file` | Path to configuration file | `` |
| `python-version` | Python version to use | `3.11` |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of vulnerabilities found |
| `report-path` | Path to the detailed JSON report |
| `risk-score` | Overall risk score (0-100) |

## Supported Frameworks

Detects vulnerable patterns in:
- **LangChain** — ConversationBufferMemory, VectorStoreRetrieverMemory
- **LlamaIndex** — Memory modules and retriever patterns
- **AutoGen** — Shared memory and group chat memory
- **CrewAI** — Crew memory and shared context
- **Mem0** — Memory add/search operations
- **Semantic Kernel** — Memory store operations

## Remediation

```bash
pip install agent-memory-guard
```

## Links

- [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/)
- [PyPI Package](https://pypi.org/project/agent-memory-guard/)

## License

Apache 2.0 — Part of the OWASP Agent Memory Guard project.
