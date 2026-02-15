# Security Policy

## Supported Versions

We release patches for the latest minor version. Security updates are prioritized for the current release branch.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please do **not** open a public issue for security vulnerabilities.

- **Email:** Report to the maintainers (e.g. via GitHub private vulnerability reporting if enabled, or open an issue with the "Security" label and minimal details asking for private contact).
- Describe the issue, steps to reproduce, and impact.
- We will respond as soon as possible and work on a fix and coordinated disclosure.

## Security Notes

- OWO runs as **root** to load eBPF and attach kprobes. Restrict binary and config to root-only; use the provided systemd unit with hardening options where possible.
- Do not store secrets (tokens, API keys) in `config.yaml` in plain text if the file is world-readable; use environment variables or a secrets manager for sensitive remote credentials when added.
