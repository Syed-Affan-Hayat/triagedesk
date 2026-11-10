# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-10

### Added

- Evidence registration with SHA-256 hashes for every input file.
- Parsers for OpenSSH authentication logs (classic syslog and RFC 3339) and Combined Log Format
  access logs, with automatic format detection.
- YAML detection rule engine with match, threshold, distinct and sequence rules, and ten rules
  mapped to MITRE ATT&CK and MITRE ATLAS.
- IP reputation enrichment through AbuseIPDB, with an offline mock provider for the samples.
- Transparent alert scoring, P1 to P4 priorities and incident grouping by source address.
- Offline incident summaries, and language model summaries behind prompt injection guardrails.
- Fallback notes that record the HTTP status code when a model request fails.
- Markdown incident report structured on PICERL, and JSON export.
- Command-line interface and Streamlit dashboard.
- Synthetic sample data generator with six planted attack scenarios.
- Test suite, continuous integration, Dockerfile and Render Blueprint.
- Deployment on Render: <https://triagedesk-f5tt.onrender.com/>.
