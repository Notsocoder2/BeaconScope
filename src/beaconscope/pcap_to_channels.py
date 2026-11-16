"""Extract per-channel connection events from PCAP/PCAPNG captures.

A channel is directional: (internal source, destination, destination port,
transport protocol). TCP timestamps are first outbound SYNs, with retransmitted
SYNs collapsed while a connection is active. Event sizes are total outbound
transport payload bytes observed for that TCP connection. UDP uses the first
datagram for each directional five-tuple as its event.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from dataclasses import dataclass, field
import ipaddress
import json
import math
from pathlib import Path
from typing import Iterable

from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, PcapReader
from scapy.error import Scapy_Exception


@dataclass
class Channel:
    src: str
    dst: str
    port: int
    proto: str
    timestamps: list[float] = field(default_factory=list)
    sizes: list[float] = field(default_factory=list)

    @property
    def channel_id(self) -> str:
        return f"{self.src}|{self.dst}|{self.port}|{self.proto}"

    def add_event(self, timestamp: float, initial_size: int = 0) -> int:
        self.timestamps.append(timestamp)
        self.sizes.append(float(initial_size))
        return len(self.timestamps) - 1


CHANNEL_FIELDS = [
    "channel_id", "src_ip", "dst_ip", "dst_port", "protocol",
    "connection_count", "timestamps_json", "outbound_payload_bytes_json",
]
DNS_FIELDS = [
    "src_ip", "dns_server_ip", "domain", "query_count",
    "capture_duration_minutes", "query_rate_per_minute",
    "subdomain_length_entropy_bits", "mean_qname_length",
]


def _is_internal(address: str, networks: tuple[ipaddress._BaseNetwork, ...] | None) -> bool:
    ip = ipaddress.ip_address(address)
    if networks is not None:
        return any(ip.version == network.version and ip in network for network in networks)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _parse_networks(values: Iterable[str] | None) -> tuple[ipaddress._BaseNetwork, ...] | None:
    if values is None:
        return None
    try:
        return tuple(ipaddress.ip_network(value, strict=False) for value in values)
    except ValueError as exc:
        raise ValueError(f"invalid internal CIDR: {exc}") from exc


def extract_channels(
    pcap_path: str | Path,
    internal_networks: Iterable[str] | None = None,
) -> dict[tuple[str, str, int, str], Channel]:
    """Stream a capture into channel start events without retaining packets.

    By default, RFC1918/private, loopback, and link-local source addresses are
    treated as internal. Pass CIDRs to explicitly select the monitored hosts.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    networks = _parse_networks(internal_networks)
    channels: dict[tuple[str, str, int, str], Channel] = {}
    active_tcp: dict[
        tuple[tuple[str, int], tuple[str, int]],
        tuple[tuple[str, int], Channel, int],
    ] = {}
    seen_udp: set[tuple[str, int, str, int]] = set()

    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if IP in packet:
                    ip_layer = packet[IP]
                elif IPv6 in packet:
                    ip_layer = packet[IPv6]
                else:
                    continue

                src_ip, dst_ip = ip_layer.src, ip_layer.dst
                timestamp = float(packet.time)
                if not (timestamp == timestamp and abs(timestamp) != float("inf")):
                    continue

                if TCP in packet:
                    transport = packet[TCP]
                    src_endpoint = (src_ip, int(transport.sport))
                    dst_endpoint = (dst_ip, int(transport.dport))
                    flow = tuple(sorted((src_endpoint, dst_endpoint)))
                    flags = int(transport.flags)
                    initial_syn = bool(flags & 0x02) and not bool(flags & 0x10)

                    if initial_syn and _is_internal(src_ip, networks):
                        # A repeated SYN for an active four-tuple is a
                        # retransmission, not another check-in.
                        if flow not in active_tcp:
                            key = (src_ip, dst_ip, int(transport.dport), "tcp")
                            channel = channels.setdefault(key, Channel(*key))
                            event_index = channel.add_event(timestamp)
                            active_tcp[flow] = (src_endpoint, channel, event_index)

                    active = active_tcp.get(flow)
                    if active is not None:
                        client_endpoint, channel, event_index = active
                        if src_endpoint == client_endpoint:
                            channel.sizes[event_index] += float(len(bytes(transport.payload)))
                        if flags & (0x01 | 0x04):  # FIN or RST closes the observed tuple.
                            active_tcp.pop(flow, None)

                elif UDP in packet and _is_internal(src_ip, networks):
                    transport = packet[UDP]
                    flow = (src_ip, int(transport.sport), dst_ip, int(transport.dport))
                    if flow in seen_udp:
                        continue
                    seen_udp.add(flow)
                    key = (src_ip, dst_ip, int(transport.dport), "udp")
                    channel = channels.setdefault(key, Channel(*key))
                    channel.add_event(timestamp, len(bytes(transport.payload)))
    except (OSError, EOFError, ValueError, Scapy_Exception) as exc:
        raise ValueError(f"could not read PCAP {path}: {exc}") from exc

    # Keep timestamps and their associated sizes paired if the input was
    # captured out of timestamp order.
    for channel in channels.values():
        paired = sorted(zip(channel.timestamps, channel.sizes), key=lambda item: item[0])
        channel.timestamps[:] = [timestamp for timestamp, _ in paired]
        channel.sizes[:] = [size for _, size in paired]
    return channels


def write_channels(channels: dict[tuple[str, str, int, str], Channel], output_path: str | Path) -> None:
    """Write reproducible channel events to a CSV file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CHANNEL_FIELDS)
        writer.writeheader()
        for channel in sorted(channels.values(), key=lambda item: item.channel_id):
            writer.writerow({
                "channel_id": channel.channel_id,
                "src_ip": channel.src,
                "dst_ip": channel.dst,
                "dst_port": channel.port,
                "protocol": channel.proto,
                "connection_count": len(channel.timestamps),
                "timestamps_json": json.dumps(channel.timestamps, separators=(",", ":")),
                "outbound_payload_bytes_json": json.dumps(channel.sizes, separators=(",", ":")),
            })


def extract_dns_features(
    pcap_path: str | Path,
    internal_networks: Iterable[str] | None = None,
    suffix_labels: int = 2,
) -> list[dict[str, object]]:
    """Summarize outbound DNS query rate and subdomain-label length entropy.

    Domain grouping uses the last ``suffix_labels`` labels as a simple suffix
    approximation. This is not a Public Suffix List and can group some
    multi-label country-code domains incorrectly. DNS-over-HTTPS/TLS is opaque
    to this parser.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    if suffix_labels < 1:
        raise ValueError("suffix_labels must be positive")
    networks = _parse_networks(internal_networks)
    queries: dict[tuple[str, str, str], list[tuple[float, int, list[int]]]] = {}
    timestamps: list[float] = []
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if DNS not in packet or IP not in packet and IPv6 not in packet:
                    continue
                ip_layer = packet[IP] if IP in packet else packet[IPv6]
                if not _is_internal(ip_layer.src, networks):
                    continue
                dns = packet[DNS]
                question = dns.qd
                if isinstance(question, (list, tuple)):
                    question = question[0] if question else None
                if int(dns.qr) != 0 or question is None or not hasattr(question, "qname"):
                    continue
                try:
                    raw_name = bytes(question.qname)
                    name = raw_name.rstrip(b".").decode("idna").lower()
                except (UnicodeError, AttributeError, TypeError):
                    continue
                labels = [label for label in name.split(".") if label]
                if not labels:
                    continue
                domain = ".".join(labels[-suffix_labels:])
                subdomain_labels = labels[:-suffix_labels]
                lengths = [len(label) for label in subdomain_labels]
                timestamp = float(packet.time)
                if not math.isfinite(timestamp):
                    continue
                key = (ip_layer.src, ip_layer.dst, domain)
                queries.setdefault(key, []).append((timestamp, len(raw_name.rstrip(b".")), lengths))
                timestamps.append(timestamp)
    except (OSError, EOFError, ValueError, Scapy_Exception) as exc:
        raise ValueError(f"could not read PCAP {path}: {exc}") from exc

    capture_minutes = (max(timestamps) - min(timestamps)) / 60 if len(timestamps) >= 2 else 0.0
    rows: list[dict[str, object]] = []
    for (src_ip, dns_server, domain), events in sorted(queries.items()):
        lengths = [length for _, _, event_lengths in events for length in event_lengths]
        if lengths:
            counts = Counter(lengths)
            total = sum(counts.values())
            entropy = float(-sum((count / total) * math.log2(count / total) for count in counts.values()))
        else:
            entropy = 0.0
        rate = len(events) / capture_minutes if capture_minutes > 0 else 0.0
        rows.append({
            "src_ip": src_ip,
            "dns_server_ip": dns_server,
            "domain": domain,
            "query_count": len(events),
            "capture_duration_minutes": capture_minutes,
            "query_rate_per_minute": rate,
            "subdomain_length_entropy_bits": entropy,
            "mean_qname_length": sum(size for _, size, _ in events) / len(events),
        })
    return rows


def write_dns_features(rows: list[dict[str, object]], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=DNS_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract BeaconScope channels from a PCAP.")
    parser.add_argument("pcap", help="Input PCAP or PCAPNG capture")
    parser.add_argument("--output", help="Optional channel CSV output")
    parser.add_argument("--dns-output", help="Optional DNS feature CSV output")
    parser.add_argument("--internal-cidr", action="append", dest="internal_networks")
    args = parser.parse_args()
    try:
        channels = extract_channels(args.pcap, args.internal_networks)
        if args.output:
            write_channels(channels, args.output)
        if args.dns_output:
            write_dns_features(extract_dns_features(args.pcap, args.internal_networks), args.dns_output)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    print(f"found {len(channels)} channels")
    for channel in sorted(channels.values(), key=lambda item: -len(item.timestamps)):
        print(f"{channel.src} -> {channel.dst}:{channel.port}/{channel.proto} n={len(channel.timestamps)}")


if __name__ == "__main__":
    main()
