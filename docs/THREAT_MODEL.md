# Threat Model

## Purpose and defender goal

BeaconScope helps an analyst find repeated outbound channels in an offline packet capture that may warrant investigation. It is not an endpoint sensor, inline firewall, malware classifier, or incident-response system.

## Threat behavior in scope

The primary behavior is a process that repeatedly initiates outbound connections or datagrams to a stable destination, with timing and request-size patterns that may persist over a capture window. The tool assumes the activity generates observable network packets and that the capture contains enough of them to measure a pattern.

## Assumptions

- The analyst is authorized to process the capture and protect its potentially sensitive contents.
- Source IPs can identify monitored hosts well enough for channel grouping and fan-in analysis.
- The capture preserves usable timestamps and enough outbound connection starts.
- A benign allowlist is collected separately from the evaluation/test period.
- Thresholds and synthetic labels are not evidence of malicious intent.

## Out of scope

- In-memory-only implants with no network activity and fully passive backdoors.
- Payload execution, malware detonation, host process attribution, TLS decryption, or endpoint remediation.
- Blocking, firewall changes, or automated response. BeaconScope has no active response path.
- Confirming C2 based only on IP reputation, periodicity, or a score.

## Attacker capabilities and evasion

An attacker may randomize timing, rotate destinations, pad request sizes, reuse common cloud/CDN services, communicate through encrypted DNS, or wait for gaps in capture coverage. These behaviors can lower or obscure BeaconScope features. Conversely, benign scheduled software can create the same regularity and persistence signals.

## Data handling boundary

The application reads local PCAP/PCAPNG files and writes local CSV summaries. It does not initiate connections to packet endpoints and does not execute packet payloads. Captures, baseline destination lists, and reports can include sensitive network data and should be access controlled and retained only as needed.

## Analyst use

Treat an alert as a lead. Review source-host identity, destination context, capture coverage, and independent host or network evidence. Check both suppressed and unsuppressed decisions; high fan-in is not a benign verdict, and rare destinations are not inherently malicious.
