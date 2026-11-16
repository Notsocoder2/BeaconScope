# Evaluation

## Method

The evaluation harness uses a fixed NumPy random seed (42 by default) and creates six-hour channel sequences. At threshold 0.5, a row is predicted positive when its score clears the threshold, it has timing corroboration, and it has not been suppressed. Metrics are calculated from explicit labels; no score is treated as a probability.

The synthetic corpus contains 21 channels: 15 generated beacons (five jitter fractions × three intervals), three periodic benign services, and three irregular browsing channels. It reports confusion counts, precision, recall, F1, false-positive rate, true-positive rate, and step-wise average precision (AP, labeled `pr_auc_average_precision`). Jitter recall is reported per fraction, with three beacon channels per row.

## Seeded synthetic results

| Configuration | TP | FP | TN | FN | Precision | Recall | F1 | False-positive rate | AP / PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Raw score + timing gate, threshold 0.5 | 15 | 3 | 3 | 0 | 0.8333 | 1.0000 | 0.9091 | 0.5000 | 0.9646 |
| Plus synthetic fan-in suppression | 15 | 0 | 6 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |

The three raw false positives are the generated NTP/update-style periodic channels. In the suppression scenario each of those benign destinations is contacted by four source hosts, while every beacon destination is unique to one host. That scenario tests the suppression code but makes its outcome easier than a real network; these values are not estimates of operational precision.

### Jitter sweep

| Generated interval jitter | Beacon channels | TP | FN | Recall |
|---:|---:|---:|---:|---:|
| 0% | 3 | 3 | 0 | 1.0000 |
| 10% | 3 | 3 | 0 | 1.0000 |
| 20% | 3 | 3 | 0 | 1.0000 |
| 30% | 3 | 3 | 0 | 1.0000 |
| 50% | 3 | 3 | 0 | 1.0000 |

These results are for one deterministic six-hour synthetic run at one threshold. They do not establish robustness to other seeds, missing capture windows, network delay, beacon periods, destination rotation, or realistic benign diversity. The 30% interval tolerance and the 50% measured ceiling are implementation choices; behavior above 50% jitter has not been measured.

## Existing local PCAP smoke checks

The two existing small PCAPs were run through the end-to-end CLI after implementation. At threshold 0.5, `beacon_test.pcap` produced one channel with score 0.974 and an alert. `benign_test.pcap` produced one channel with raw score 0.528 but no alert because its timing features did not satisfy the timing-corroboration gate. These are useful parser/pipeline smoke checks. The captures have the same loopback endpoint and no channel-level label file, so they are not independent labeled accuracy data.

## Held-out data and comparison status

| Study | Status |
|---|---|
| Sliver-derived isolated capture | Not run; no Kali/VirtualBox lab was available in this execution environment. |
| Public labeled PCAPs | Not downloaded or evaluated. No external capture or verified labels are in the repository. |
| RITA comparison | Not run; Zeek/RITA are not installed and no held-out PCAP is available. |
| 50 MB / 200 MB resource profile | Not run; there are no captures of those sizes. No runtime or memory figures are claimed. |
| DNS feature evaluation | Unit tested on generated DNS packets; no labeled DNS-tunneling corpus was evaluated. DNS does not affect the score. |
| Docker build/run | Dockerfile is present, but Docker was unavailable here, so image build and container execution were not verified. |

Before using portfolio claims, collect held-out malicious and benign PCAPs with terms and labels recorded, freeze thresholds before testing, report per-dataset confusion metrics and sample sizes, and compare the same captures with a documented RITA/Zeek version.
