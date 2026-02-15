# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-02-15

### Added

- eBPF-based execve monitoring (kprobe on `__x64_sys_execve`)
- eBPF file hooks: openat, unlink, rename (path filter or watch-all mode)
- eBPF network hooks: connect, sendto (TCP/UDP)
- Exec enrichment: SHA256 (with /proc exe fallback), inode, TTY, container ID
- JSONL output: file, stderr, remote (TCP/TLS/HTTP) with agent identity
- Single YAML config (agent, monitor, output)
- Behavior engine: exec-from-tmp + connect correlation (reverse shell)
- systemd unit (`contrib/owo.service`) and logrotate (`contrib/owo.logrotate`)
- Process tree dump on SIGUSR1

### Notes

- Monitoring-only: no built-in rule engine; SIEM (e.g. Wazuh) does matching/alerting.
- Requires root; Linux kernel ≥ 5.x with BTF.
