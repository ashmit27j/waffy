# waffy

![waffy](Waff-banner.png)

A standalone, per-host application-layer Web Application Firewall (WAF). It
sits inline with decrypted HTTP(S) traffic on an individual machine to inspect
requests/responses and detect/block web application attacks (SQLi, XSS,
command injection, path traversal, SSRF, SSTI, XXE, bot abuse, etc.).

waffy is an architectural sibling project to **pirewall** (an AI-assisted
network-layer firewall) with **no code dependency** on pirewall.

For specifications and design details, see `docs/`.

## Architecture, in one line

```text
HTTP(S) Traffic -> Request/Response Inspection -> Attack Detection
                -> Decision -> Allow / Block