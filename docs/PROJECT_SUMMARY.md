# waffy: Project Summary

waffy is an application-layer Web Application Firewall (WAF) that acts as an inline proxy to detect and block web application attacks (such as SQLi, XSS, and command injection). It employs deterministic signature matching, anomaly detection, and positive security models to arrive at enforcement decisions.

waffy is a sibling project to **pirewall**, targeting the application layer (L7) while pirewall targets the network layer (L3/L4). They share event-shape compatibility for SIEM integration but are completely decoupled at the codebase level, sharing no dependencies or runtime APIs.

## Current State

The following represents the honest, validated state of the project:

- **Core Engine**: Fully implemented and tested. Includes HTTP parsing, signature engine, Isolation Forest anomaly scoring, and decision/enforcement engine.
- **Proxy Modes**: Standalone TLS proxy, Plaintext proxy, and ASGI middleware modes are implemented.
- **Management API & Control Panel**: Fully implemented, tested, and decoupled from the proxy data plane via IPC.
- **SIEM Integration**: Syslog/JSON event sink implemented and Wazuh-compatible.

## Known Limitations — Scope Boundary

- **Embedded-middleware mode for non-Python stacks**: waffy's embedded middleware mode is explicitly Python-only (ASGI). For other stacks (e.g., Go, Node.js), waffy must be run as a standalone proxy.
- **Plaintext Mode TLS Signals**: When running behind an existing TLS terminator (like Nginx), TLS-derived bot signals (like JA3 fingerprints) are unavailable to waffy unless explicitly forwarded via custom headers.
- **ACME Automation**: Not implemented. Standalone TLS mode requires manual provisioning and rotation of certificates on disk.
- **Real-hardware benchmarks**: Missing. Performance overhead has not yet been validated against a real production-shaped application on target deployment hardware.
- **Attack-lab corpus validation**: Missing. The synthetic attack corpus to validate false-positive and false-negative rates for each signature category has not been fully implemented or run.
- **Systemd units**: Generated, but not yet installed, activated, or validated in a real target environment.
