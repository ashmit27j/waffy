# waffy and pirewall Interoperability

## Overview

waffy and pirewall are sibling projects designed to complement each other in a
defense-in-depth architecture. However, they are **strictly decoupled** at the
code level. There are no shared dependencies, no direct network API calls between
the two, and no shared state.

They achieve interoperability entirely through **event-shape compatibility** and
SIEM correlation. Both projects emit security events that can be ingested by the
same SIEM (like Wazuh), allowing operators to build dashboards and alerts that
correlate network-layer incidents (pirewall) with application-layer attacks (waffy).

## Event Shape Compatibility

Both waffy and pirewall emit JSON-formatted events wrapped in an RFC 5424 syslog
message.

### waffy `SecurityEvent`
```json
{
  "type": "signature_match",
  "severity": "high",
  "timestamp": "2024-01-01T00:00:00Z",
  "source_ip": "1.2.3.4",
  "correlation_id": "req-12345",
  "summary": "SQLi attempt detected in query string",
  "details": {
    "rule_id": "SQLI-001"
  },
  "waffy_event_id": "a12f6596-..."
}
```

### Shared Correlation Fields

To link events across the two systems, SIEM dashboards should join on:
- `source_ip`: The originating client IP address.
- `timestamp`: Time proximity (e.g., within 5 minutes).

*Note:* The `correlation_id` in waffy relates to a specific HTTP request, while
pirewall's correlation ID usually relates to a network connection or flow. They
will differ. `source_ip` is the primary key for cross-system correlation.

## SIEM Integration (Wazuh Example)

You can point waffy's `SyslogEventSink` to the same Wazuh agent/server that
receives pirewall logs.

### Sample Wazuh Custom Rule

Here is an illustrative example of a Wazuh rule that correlates a pirewall port
scan event with a subsequent waffy attack event from the same source IP. This
indicates a sequence of reconnaissance followed by an exploitation attempt.

**`/var/ossec/etc/rules/local_rules.xml`**

```xml
<group name="waffy, pirewall, correlation,">
  
  <!-- Rule to detect a waffy high severity event -->
  <rule id="100100" level="8">
    <decoded_as>json</decoded_as>
    <field name="type">signature_match|anomaly_detected|positive_security_violation</field>
    <field name="severity">high|critical</field>
    <description>waffy: High severity application attack detected.</description>
  </rule>

  <!-- Correlate waffy attack with prior pirewall reconnaissance -->
  <rule id="100101" level="12" frequency="1" timeframe="300">
    <if_matched_sid>100100</if_matched_sid>
    <!-- Assuming rule 90100 is a custom pirewall rule for port scanning -->
    <if_matched_sid>90100</if_matched_sid> 
    <same_source_ip />
    <description>Correlation: Application attack (waffy) preceded by network recon (pirewall) from the same IP.</description>
    <group>attack_chain, high_confidence,</group>
  </rule>

</group>
```

*(This is a small, documented example for illustration, not a shipped or maintained ruleset).*

## Centralized Dashboarding

By shipping logs from both systems to a central SIEM (like ELK via Wazuh, or Splunk),
you can build a unified "Target Host Overview" dashboard displaying:
1. Network drops (pirewall)
2. Blocked malicious HTTP requests (waffy)
3. IP behavior scores aggregating network-level and app-level violations.
