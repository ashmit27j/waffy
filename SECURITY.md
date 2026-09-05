# Security Policy

This document describes how to report a security vulnerability **in waffy
itself**. For waffy's own security posture, threat model, and known scope
boundaries (what it detects, how it fails, what's explicitly out of
scope), see [`docs/SECURITY.md`](docs/SECURITY.md) instead.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Email **ashmit27j@gmail.com** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept (a synthetic payload, not
  anything exercised against a real production system).
- The affected version/commit.

There is no dedicated security-team mailing list or GitHub Security
Advisories process configured for this repository yet — the maintainer's
own email above is the current, real reporting channel. If you'd prefer to
use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
feature instead and it isn't enabled on this repository, mention that in
your report and the maintainer will enable it.

## Response timeframe

This is a single-maintainer project without a dedicated security team or a
contractual SLA. As a target, not a guarantee: an initial acknowledgment
within **5 business days**, and a plan for remediation or a public
statement within **30 days** of a confirmed report. If you haven't heard
back within that window, it's reasonable to follow up.

## Coordinated disclosure

Please give the maintainer a reasonable opportunity to investigate and
release a fix before any public disclosure. There is no formal embargo
process defined yet; in the absence of one, a **90-day** disclosure
timeline from initial report (or sooner, once a fix ships and users have
had a reasonable chance to update) is a reasonable default both sides can
work from — this can be adjusted by mutual agreement based on the
vulnerability's severity and complexity.

## Scope

This applies to the waffy codebase in this repository. It does not cover:

- Vulnerabilities in third-party dependencies (report those upstream —
  though a report here that identifies one is still welcome, so it can be
  tracked and updated).
- Findings that require an already-compromised deployment environment
  (e.g. an attacker with existing root access to the host).
- Issues already listed as a known limitation in
  [`docs/SECURITY.md`](docs/SECURITY.md) or [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
  (e.g. WebSocket support being unimplemented, or middleware mode's
  documented lack of process isolation) — those are tracked openly, not
  hidden, so they're not a surprise finding, though a report on the
  concrete exploitability of one is still useful.
