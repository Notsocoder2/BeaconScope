# BeaconScope Architecture

BeaconScope is an offline, channel-oriented analysis pipeline. Its analysis unit is one internal source IP communicating with one destination IP, destination port, and transport protocol. Packet records are not retained after extraction; connection events and per-channel features are.

```text
PCAP / PCAPNG
    |
    v
pcap_to_channels.py  (Scapy; TCP starts, UDP first datagrams, DNS summaries)
    |
    v
features.py          (timing regularity, FFT autocorrelation, size, persistence)
    |
    v
suppress.py          (benign-only baseline allowlist and destination fan-in)
    |
    v
scoring.py           (weighted, explainable 0–1 heuristic)
    |
    v
cli.py               (ranked CSV and analyst-facing reasons)
    |
    v
evaluate.py          (confusion metrics, AP/PR-AUC, synthetic jitter sweep)
```

## Stages

### PCAP channel extraction

`pcap_to_channels.py` streams PCAP/PCAPNG packets with Scapy. A TCP channel event is the first outbound SYN without ACK for a directional four-tuple; repeated SYNs while the tuple is active are treated as retransmits. Its timestamp is the SYN time, and event size is the total outbound TCP payload observed for that connection. UDP uses one first-observed datagram per directional five-tuple. By default, private, loopback, and link-local source addresses are treated as internal; `--internal-cidr` selects explicit networks. This makes the channel identity consistent with the roadmap while avoiding grouping unrelated source hosts together.

The parser writes `channels.csv`. It also summarizes decoded outbound DNS queries into `dns_features.csv`, grouping on client, DNS server, and an approximate domain suffix. DNS summaries are sidecar evidence, not part of the current score.

### Feature extraction

`features.py` computes interval median and median absolute deviation, a fraction of intervals within 30% of the median, a bounded FFT autocorrelation peak, outbound payload-size regularity, and occupancy across ten time bins. All scores are bounded in [0, 1]. Fewer than two intervals do not produce a regularity signal.

### Suppression

`suppress.py` checks a destination allowlist learned from a separate benign-only baseline, then counts distinct source hosts that contacted a destination. Suppression affects the alert decision but leaves the raw score visible with an explanation. Fan-in is contextual evidence, not proof that the destination is benign.

### Scoring and output

`scoring.py` combines the four behavioral features and a minimum-observation confidence component with explicit weights. `cli.py` writes one channel row per score, ranks the rows, and includes feature values and an explanation. It does not claim that an unlabeled capture has precision or recall.

### Evaluation

`evaluate.py` evaluates labeled rows at a selected threshold and calculates confusion counts, precision, recall, F1, false-positive rate, true-positive rate, and step-wise average precision (reported as PR-AUC average precision). Its fixed-seed synthetic mode also breaks recall out by jitter fraction. Synthetic topology used for fan-in tests is declared in code and must not be mistaken for topology inferred from PCAPs.

## Outputs

| File | Contents |
|---|---|
| `channels.csv` | Channel identity, event timestamps, and outbound payload sizes |
| `features.csv` | One row of behavioral features per transport channel |
| `dns_features.csv` | Query count/rate and subdomain-length entropy by approximate domain |
| `scored_connections.csv` | Ranked score, alert decision, suppression reason, and features |
| `evaluation_summary.csv` | Capture counts, or metrics when valid labels are supplied |

The modules remain callable independently for unit tests and future detection methods. A single CLI entry point coordinates the pipeline; no external systems are contacted during analysis.
