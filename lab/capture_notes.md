# Capture Session Notes

Use one copy per authorized lab session. Do not commit raw PCAPs, check-in logs, or host identifiers.

| Field | Value |
|---|---|
| Date/time and timezone | |
| Operator | |
| Host-only subnet | |
| Windows host IP | |
| Kali source IP(s) | |
| Capture interface and filter | |
| Capture file path and SHA-256 | |
| Beacon client command/seed | |
| Server command and log path | |
| Expected check-in count | |
| Captured SYN/event count | |
| Clock drift notes | |
| BeaconScope version/commit (if available) | |
| Output directory | |
| Observed issues | |

Use `checkins.log` as independent generator ground truth, not as a substitute for packet-capture labels. Record capture loss, start/stop timing, and client/server clock differences before interpreting intervals.
