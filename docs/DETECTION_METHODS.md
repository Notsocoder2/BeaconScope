# Detection Methods

BeaconScope finds network channels with behavior that merits analyst review. No feature or score alone proves malware or command-and-control activity.

## Channel definition

The channel key is `(src_ip, dst_ip, dst_port, protocol)`. For TCP, an event is an outbound SYN with SYN set and ACK clear. Retransmitted SYNs for an active directional four-tuple are collapsed. TCP request size is the sum of outbound transport payload bytes observed for that connection. For UDP, an event is the first datagram observed for each directional five-tuple; repeated datagrams on the same tuple are not separate events. The source IP is retained so multiple internal hosts are not merged into one timing series.

## Features

| Feature | Hypothesis and method | Weakness | One evasion or benign mimic |
|---|---|---|---|
| Jitter-tolerant interval regularity | If intervals cluster around a median, some periodic behavior is present. Score is the fraction of intervals within ±30% of the median. | A short sequence can look regular by chance; a fixed tolerance may miss high jitter. | A beacon can vary its sleep beyond the band; benign update checks can have a stable schedule. |
| Spectral/autocorrelation score | Repeated event timing produces peaks in the autocorrelation of one-second (or coarser) event-count bins. BeaconScope uses an FFT to calculate autocorrelation and keeps the strongest non-trivial lag peak. | Capture duration, bin width, bursts, and searching many lags affect the peak; this is not a significance test. | Randomized intervals can blur peaks; periodic health checks can create them. |
| Outbound size regularity | Repeated requests with similar payload byte totals can indicate a stable check-in protocol. Score is `clip(1 - population_CV, 0, 1)` over positive per-connection outbound payload totals. | Encryption, compression, capture truncation, multi-request sessions, and application variability change the measured size. | Padding or randomized payload lengths reduce this signal; small fixed benign probes can mimic it. |
| Persistence | Activity spread across the observation window is more consistent with a recurring process than a short burst. Score is the fraction of ten equal-width time bins containing events. | Depends on capture window selection and event count; it does not distinguish malicious from benign persistence. | A beacon can sleep for long periods or run only in bursts; scheduled benign monitoring can be persistent. |
| Observation confidence | More events provide more evidence. The score includes `min(1, event_count / 6)` at weight 0.10. | Six is a heuristic cutoff, not a statistical confidence interval. | Attackers can use fewer observed events; long-running benign services naturally accumulate events. |
| Destination fan-in suppression | Many internal hosts contacting one destination may indicate shared infrastructure such as DNS, updates, or telemetry. It is enabled separately and uses distinct source IP count. | Shared C2, proxying, NAT, or limited source visibility can make fan-in misleading. | An attacker can use unique infrastructure; a benign service can appear rare in a narrow capture. |
| Benign baseline allowlist | A destination seen in a separate benign-only baseline can be suppressed in later analysis. | Baseline drift and contamination can preserve a newly malicious destination. | An attacker may reuse an already allowlisted destination or wait until it appears in the baseline. |
| DNS query rate and subdomain-length entropy | High query volume and varied subdomain-label lengths can be useful DNS-tunneling context. Rate is queries per minute of capture; entropy is Shannon entropy over observed subdomain label lengths, grouped by an approximate last-two-label suffix. | The suffix is not a Public Suffix List; a single query has no meaningful rate; entropy needs enough queries; no DNS-labeled evaluation exists. | DoH/DoT hides the query names; attackers can keep labels fixed or blend in with CDN and tracking traffic. DNS features are not yet included in scoring. |

## Score

The default explainable score is:

```text
0.30 × interval regularity
+ 0.30 × spectral score
+ 0.15 × size regularity
+ 0.15 × persistence
+ 0.10 × observation confidence
```

Each component is bounded between zero and one, and the weights sum to one. The score is a ranking heuristic, not a probability. `--threshold` defaults to 0.5 and can be changed for evaluation. Thresholds and weights remain provisional until evaluated on held-out labeled data.

An alert requires the selected score threshold, timing corroboration (at least half of intervals cluster within the tolerance band, or the spectral score is at least 0.4), and at least six observed events. Channels with fewer observations retain their raw score for ranking but cannot trigger an alert; the explanation reports the observation shortfall. This gate prevents a short, coincidentally regular sequence from alerting on limited evidence. It is a provisional heuristic, not a calibrated statistical confidence bound. Analysts should review destination context, capture coverage, host identity, and other independent evidence before attributing malicious intent.
