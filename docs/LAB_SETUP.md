# Isolated Lab Setup

## Network design

Use a Windows host and one Kali VM in VirtualBox. Attach the Kali VM to two adapters:

1. Adapter 1: NAT for package installation only.
2. Adapter 2: Host-only Adapter (for example `vboxnet0`) for all lab traffic.

Create or inspect the host-only network in VirtualBox's Host Network Manager. Record the Windows host and Kali guest addresses from `ipconfig` and `ip a`; do not assume the default `192.168.56.0/24`. Keep the test listener and client on the host-only network. Never bridge a test client to a real LAN or point it at a third-party host.

## Install BeaconScope

On Windows PowerShell:

```powershell
cd C:\Projects\beaconscope-updated
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

On Kali, install Python, tcpdump, and Wireshark using the distribution package manager, then create a virtual environment and install the project dependencies. If the repository is not mounted in Kali, copy only the lab generator scripts and install BeaconScope separately on the capture/analysis system.

## Run a controlled capture

Start the listener on Windows, bound to the host-only address where practical:

```powershell
python lab/beacon_server.py --bind 192.168.56.1 --port 8443 --log checkins.log
```

Replace `192.168.56.1` with the address recorded from your host. On Kali, identify the host-only interface with `ip a`, start capture before the client, then generate labeled check-ins:

```bash
sudo tcpdump -i <host-only-interface> -nn -s 0 -w week1_capture.pcap 'tcp port 8443'
```

In another Kali terminal:

```bash
python3 beacon_client.py --target 192.168.56.1 --port 8443 \
  --interval 15 --jitter 0.1 --duration 300 --payload-bytes 500
```

Stop tcpdump with Ctrl+C. Compare the server's `checkins.log` with packet timestamps; host/VM clock drift may require a tolerance. Do not commit the capture or logs.

To simulate multiple source hosts for fan-in testing, create IP aliases on Kali's host-only interface using addresses in the configured host-only subnet. The client `--bind` flag can select an existing local alias; it does not configure interfaces. Keep the aliases and traffic isolated.

## Analyze and evaluate

From the repository root:

```powershell
python -m beaconscope.cli --pcap week1_capture.pcap `
  --internal-cidr 192.168.56.0/24 --output-dir results/week1 --threshold 0.5
python -m beaconscope.evaluate --synthetic --threshold 0.5 --output results/synthetic.csv
python -m pytest -q
```

For capture-scoped suppression, add `--suppress`. For a previously prepared benign-only destination baseline, pass `--baseline baseline.csv`; the file needs a `destination` column. Keep baseline and evaluation periods separate to avoid test leakage.

## Safety and capture hygiene

- Capture only networks and devices you own or are authorized to monitor.
- Bind the lab server to the host-only interface when possible.
- Avoid collecting unrelated traffic; use a narrow tcpdump filter.
- Protect PCAPs and logs as sensitive network data and delete them under your retention policy.
- BeaconScope parses packet metadata; it does not execute payloads or contact extracted destinations.
- Docker and external dataset workflows are described in the README/Evaluation doc; no external network test is required for the synthetic harness.
