# BeaconScope

BeaconScope is an offline Python tool that extracts directional network channels from PCAP/PCAPNG captures and ranks channels with regular timing, stable outbound request sizes, persistent activity, and autocorrelation. Optional destination fan-in and a separately supplied benign baseline can suppress alerts. A score is a triage signal, not a verdict that traffic is malicious.

The complete build roadmap is in [`beaconscope_roadmap.pdf`](beaconscope_roadmap.pdf). This implementation follows its channel → features → suppression → scoring → evaluation design. The DNS sidecar reports query rate and subdomain-label length entropy; it is experimental and does not contribute to the current beacon score.

## Install

Python 3.10–3.13 is supported. On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

On Linux/Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
```

For a packet-capture lab, install tcpdump/Wireshark separately. See [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md). No external network access is needed to run the synthetic evaluation.

## Analyze a capture

```powershell
python -m beaconscope.cli `
  --pcap eval/results/beacon_test.pcap `
  --output-dir eval/results/beaconscope_run `
  --threshold 0.5
```

If BeaconScope should only consider a known internal network, pass its CIDR (repeat the flag for multiple networks):

```powershell
python -m beaconscope.cli --pcap capture.pcap --internal-cidr 192.168.56.0/24
```

Outputs are `channels.csv`, `features.csv`, `dns_features.csv`, `scored_connections.csv`, and `evaluation_summary.csv`. Supply `--labels labels.csv` to calculate labeled metrics. Supply `--suppress --fanin-threshold 3` to suppress destinations seen from at least three distinct source IPs. A baseline CSV can add a separately learned allowlist and must have a `destination` column:

```csv
destination
192.0.2.53
```

Use a benign-only baseline capture from a separate time period. Suppression preserves the raw score and records the suppression reason in the output.

## Reproduce the local evaluation

```powershell
python -m beaconscope.evaluate --synthetic --threshold 0.5 --output eval/results/synthetic.csv
python -m beaconscope.evaluate --synthetic --suppress --threshold 0.5 --output eval/results/synthetic_suppressed.csv
python -m pytest -q
```

The seeded synthetic set currently contains 15 beacon channels (0–50% generated interval jitter), three periodic benign channels, and three irregular browsing channels. On this set at threshold 0.5, raw precision is 83.3% and recall is 100% (15 TP, 3 FP, 3 TN, 0 FN). With its simulated topology (each benign periodic destination has four source hosts; beacon destinations are unique), suppression yields 100% precision and recall. This is a controlled synthetic result, not a real-network performance claim. Details and jitter results are in [`docs/EVALUATION.md`](docs/EVALUATION.md).

Example from the existing regular local capture:

```text
[ALERT] 127.0.0.1 -> 127.0.0.1:8443/tcp score=0.974
100% of intervals cluster near 2.0s; autocorrelation peak 0.91;
outbound request sizes are unusually uniform; activity persists across the observation window
```

On managed Windows images where Application Control blocks Hypothesis's optional native plugin, run the suite with plugin autoload disabled (the current tests do not use third-party pytest plugins):

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
python -m pytest -q
```

## Docker

```powershell
docker build -t beaconscope .
docker run --rm -v "${PWD}:/pcaps:ro" -v "${PWD}/results:/results" beaconscope `
  --pcap /pcaps/eval/results/beacon_test.pcap --output-dir /results
```

## Project map

- `src/beaconscope/pcap_to_channels.py`: streaming PCAP channel and DNS extraction.
- `src/beaconscope/features.py`: timing regularity, autocorrelation, size regularity, and persistence.
- `src/beaconscope/scoring.py`: weighted, explainable 0–1 heuristic score.
- `src/beaconscope/suppress.py`: benign baseline and destination fan-in.
- `src/beaconscope/simulate.py`, `evaluate.py`: seeded traffic and evaluation metrics.
- `lab/`: controlled HTTP check-in generator and listener.
- `tests/`: parser, feature, score, suppression, and pipeline tests.

## Limitations

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). In brief: benign scheduled traffic can be periodic; destination fan-in can suppress shared C2 infrastructure; the synthetic corpus is small and self-generated; DNS features are not scored; and no public held-out capture or RITA comparison has been completed. TLS/DoH payloads are not decrypted. BeaconScope is intended for offline analyst triage.

The repository's `LICENSE` file is empty. Choose the project's reuse terms before publishing it; no license has been inferred as part of this implementation.
