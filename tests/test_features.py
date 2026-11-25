"""Tests for channel features, parsing, scoring, suppression, and evaluation."""

import csv
import math
from http.server import ThreadingHTTPServer
import threading

import numpy as np
import pytest
from scapy.all import DNS, DNSQR, Ether, IP, IPv6, TCP, UDP, Raw, wrpcap

from beaconscope.cli import run_pipeline
from beaconscope.evaluate import (
    confusion_metrics,
    load_labels,
    match_label,
    run_synthetic_evaluation,
)
from beaconscope.features import (
    ChannelFeatures,
    extract_features,
    jitter_tolerant_regularity,
    size_regularity,
    spectral_score,
)
from beaconscope.pcap_to_channels import extract_channels, extract_dns_features
from beaconscope.scoring import DEFAULT_WEIGHTS, score_channel
from beaconscope.simulate import make_beacon, make_random_browsing
from beaconscope.suppress import (
    build_allowlist_from_baseline,
    check_suppression,
    destination_fanin,
)
from lab.beacon_client import send_checkin
from lab.beacon_server import make_handler


def test_perfect_beacon_scores_high_and_is_explainable():
    timestamps, sizes = make_beacon(3600, 30, 0, rng=np.random.default_rng(1))
    features = extract_features(timestamps, sizes)
    scored = score_channel(features)
    assert scored.score > 0.9
    assert "intervals" in scored.explanation


def test_random_browsing_scores_below_alert_threshold():
    timestamps, sizes = make_random_browsing(3600, 20, rng=np.random.default_rng(10))
    assert score_channel(extract_features(timestamps, sizes)).score < 0.5


@pytest.mark.parametrize("jitter", [0.0, 0.1, 0.2, 0.3])
def test_jittered_beacon_retains_timing_signal(jitter):
    timestamps, sizes = make_beacon(7200, 45, jitter, rng=np.random.default_rng(3))
    features = extract_features(timestamps, sizes)
    assert features.jitter_tolerant_regularity >= 0.6
    assert score_channel(features).score > 0.4


def test_scoring_is_deterministic_and_weighted():
    timestamps, sizes = make_beacon(3600, 60, 0.1, rng=np.random.default_rng(42))
    features = extract_features(timestamps, sizes)
    assert score_channel(features).score == score_channel(features).score
    assert math.isclose(sum(DEFAULT_WEIGHTS.values()), 1.0)


def test_small_samples_do_not_claim_timing_regularity():
    assert jitter_tolerant_regularity([30.0]) == 0.0
    assert extract_features([100.0, 130.0]).jitter_tolerant_regularity == 0.0
    assert "low confidence" in score_channel(extract_features([100.0, 130.0])).explanation


def test_three_regular_observations_cannot_trigger_an_alert():
    features = extract_features([100.0, 110.0, 120.0], [500.0, 500.0, 500.0])
    scored = score_channel(features)

    assert scored.score == pytest.approx(0.545)
    assert scored.timing_supported
    assert not scored.is_alert(0.5)
    assert not scored.is_alert(0.0)
    assert "at least 6 are required for alerts" in scored.explanation


def test_missing_observation_becomes_a_longer_interval():
    features = extract_features([0, 10, 20, 50, 60, 70], [400] * 6)
    assert features.n_connections == 6
    assert features.median_interval == 10
    assert features.jitter_tolerant_regularity == pytest.approx(0.8)


def test_size_and_persistence_without_timing_corroboration_do_not_alert():
    features = ChannelFeatures(12, 47, 4.6, 2.5, 0.27, 0.20, 1.0, 0.9)
    scored = score_channel(features)
    assert scored.score > 0.5  # Raw score remains visible for review.
    assert not scored.timing_supported
    assert not scored.is_alert(0.5)
    assert "no timing corroboration" in scored.explanation


def test_feature_input_validation_and_size_regularity():
    assert size_regularity([500, 500, 500]) == 1.0
    assert size_regularity([]) == 0.0
    with pytest.raises(ValueError):
        extract_features([1.0, float("nan")])
    with pytest.raises(ValueError):
        score_channel(extract_features([1, 2]), {"bad": 1.0})


def _packet(src, dst, sport, dport, flags, timestamp, payload=b""):
    packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        packet = packet / Raw(load=payload)
    packet.time = timestamp
    return packet


def test_pcap_extracts_directional_channels_and_collapses_syn_retransmits(tmp_path):
    pcap = tmp_path / "known.pcap"
    packets = [
        _packet("10.1.1.5", "203.0.113.9", 51000, 443, "S", 1.0),
        _packet("10.1.1.5", "203.0.113.9", 51000, 443, "S", 1.1),  # retransmit
        _packet("10.1.1.5", "203.0.113.9", 51000, 443, "PA", 1.2, b"hello"),
        _packet("203.0.113.9", "10.1.1.5", 443, 51000, "PA", 1.25, b"response"),
        _packet("10.1.1.5", "203.0.113.9", 51000, 443, "FA", 1.3),
        _packet("10.1.1.5", "203.0.113.9", 51001, 443, "S", 11.0),
        _packet("10.1.1.5", "203.0.113.9", 51001, 443, "PA", 11.2, b"world!"),
    ]
    wrpcap(str(pcap), packets)
    channels = extract_channels(pcap)
    assert len(channels) == 1
    channel = next(iter(channels.values()))
    assert channel.proto == "tcp"
    assert channel.timestamps == pytest.approx([1.0, 11.0])
    assert channel.sizes == [5.0, 6.0]


def test_pcap_udp_counts_one_event_per_directional_tuple(tmp_path):
    pcap = tmp_path / "udp.pcap"
    packets = []
    for timestamp, sport, payload in [(1.0, 53000, b"a"), (1.1, 53000, b"b"), (5.0, 53001, b"c")]:
        packet = Ether() / IP(src="10.0.0.4", dst="192.0.2.53") / UDP(sport=sport, dport=53) / Raw(load=payload)
        packet.time = timestamp
        packets.append(packet)
    wrpcap(str(pcap), packets)
    channels = extract_channels(pcap)
    channel = next(iter(channels.values()))
    assert channel.proto == "udp"
    assert channel.timestamps == pytest.approx([1.0, 5.0])
    assert channel.sizes == [1.0, 1.0]


def test_pcap_explicit_internal_network_filter(tmp_path):
    pcap = tmp_path / "filter.pcap"
    wrpcap(str(pcap), [_packet("10.1.1.5", "203.0.113.9", 50000, 443, "S", 1)])
    assert extract_channels(pcap, ["192.168.56.0/24"]) == {}
    assert len(extract_channels(pcap, ["10.1.0.0/16"])) == 1


def test_pcap_ipv6_source_channel(tmp_path):
    pcap = tmp_path / "ipv6.pcap"
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src="fd00::5", dst="2001:db8::53") / UDP(sport=53000, dport=53) / Raw(load=b"x")
    packet.time = 1.0
    wrpcap(str(pcap), [packet])
    channels = extract_channels(pcap)
    channel = next(iter(channels.values()))
    assert channel.src == "fd00::5"
    assert channel.dst == "2001:db8::53"
    assert channel.proto == "udp"


def test_lab_client_server_exchange_records_ground_truth(tmp_path):
    log_path = tmp_path / "checkins.csv"
    log_path.write_text("timestamp,client_ip,bytes\n", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(str(log_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/checkin"
        try:
            assert send_checkin(url, b"controlled-test-payload", bind="127.0.0.1") == 200
        except PermissionError as exc:
            if getattr(exc, "winerror", None) == 10013:
                pytest.skip("host policy blocks loopback socket tests")
            raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    with log_path.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]["client_ip"] == "127.0.0.1"
    assert rows[0]["bytes"] == "23"


def test_corrupt_pcap_has_a_clear_value_error(tmp_path):
    pcap = tmp_path / "broken.pcap"
    pcap.write_bytes(b"not a packet capture")
    with pytest.raises(ValueError, match="could not read PCAP"):
        extract_channels(pcap)


def test_valid_empty_pcap_returns_no_channels(tmp_path):
    from scapy.utils import PcapWriter

    pcap = tmp_path / "empty.pcap"
    writer = PcapWriter(str(pcap))
    writer.close()
    assert extract_channels(pcap) == {}


def test_dns_query_rate_and_subdomain_length_entropy(tmp_path):
    pcap = tmp_path / "dns.pcap"
    packets = []
    for timestamp, label in zip((0, 30, 60, 90), (b"a", b"bb", b"ccc", b"dddd")):
        packet = (
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.53")
            / UDP(sport=53000 + timestamp, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=label + b".example.com"))
        )
        packet.time = timestamp
        packets.append(packet)
    wrpcap(str(pcap), packets)
    rows = extract_dns_features(pcap)
    assert len(rows) == 1
    assert rows[0]["domain"] == "example.com"
    assert rows[0]["query_count"] == 4
    assert rows[0]["query_rate_per_minute"] == pytest.approx(4 / 1.5)
    assert rows[0]["subdomain_length_entropy_bits"] == pytest.approx(2.0)


def test_fanin_and_allowlist_suppression_keep_reason():
    topology = {
        "10.0.0.1": {"198.51.100.9"},
        "10.0.0.2": {"198.51.100.9"},
        "10.0.0.3": {"198.51.100.9"},
        "10.0.0.4": {"203.0.113.8"},
    }
    assert destination_fanin("198.51.100.9", topology) == 3
    suppressed = check_suppression("198.51.100.9", topology)
    assert suppressed.suppressed and "3 distinct" in suppressed.reason
    assert not check_suppression("203.0.113.8", topology).suppressed
    allowlist = build_allowlist_from_baseline([("10.0.0.4", "203.0.113.8")])
    assert check_suppression("203.0.113.8", topology, allowlist).suppressed


def test_confusion_metrics_are_exact_and_include_pr_auc():
    rows = [
        {"label": 1, "score": 0.9},
        {"label": 0, "score": 0.8},
        {"label": 0, "score": 0.2},
        {"label": 1, "score": 0.1},
    ]
    metrics = confusion_metrics(rows, threshold=0.5)
    assert (metrics["true_positives"], metrics["false_positives"]) == (1, 1)
    assert (metrics["true_negatives"], metrics["false_negatives"]) == (1, 1)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1_score"] == 0.5
    assert metrics["pr_auc_average_precision"] == pytest.approx(0.75)


def test_labels_match_full_channel_identity_and_reject_duplicates(tmp_path):
    labels_path = tmp_path / "labels.csv"
    labels_path.write_text(
        "src_ip,dst_ip,dst_port,protocol,label\n"
        "10.0.0.1,198.51.100.8,443,tcp,1\n"
        "10.0.0.2,198.51.100.8,443,tcp,0\n",
        encoding="utf-8",
    )
    labels, strict = load_labels(labels_path)
    assert strict
    assert match_label({"src_ip": "10.0.0.1", "dst_ip": "198.51.100.8", "dst_port": 443,
                        "protocol": "TCP"}, labels, strict) == 1
    assert match_label({"src_ip": "10.0.0.2", "dst_ip": "198.51.100.8", "dst_port": 443,
                        "protocol": "tcp"}, labels, strict) == 0
    labels_path.write_text(
        "src_ip,dst_ip,dst_port,protocol,label\n"
        "10.0.0.1,198.51.100.8,443,tcp,1\n"
        "10.0.0.1,198.51.100.8,443,tcp,0\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate label key"):
        load_labels(labels_path)


def test_synthetic_eval_is_reproducible_and_suppression_reduces_false_positives():
    rows1, raw, _ = run_synthetic_evaluation(seed=42, suppress=False)
    rows2, suppressed, _ = run_synthetic_evaluation(seed=42, suppress=True)
    assert [row["score"] for row in rows1] == [row["score"] for row in rows2]
    assert raw["false_positives"] > suppressed["false_positives"]
    assert suppressed["recall"] == raw["recall"]


def test_cli_pipeline_writes_channel_feature_and_score_csvs(tmp_path):
    pcap = tmp_path / "input.pcap"
    packets = [
        _packet("10.2.0.1", "203.0.113.5", 51000 + index, 8443, "S", 1 + index * 10)
        for index in range(7)
    ]
    wrpcap(str(pcap), packets)
    out = tmp_path / "out"
    summary = run_pipeline(pcap, out)
    assert summary["total_channels"] == 1
    with (out / "scored_connections.csv").open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["protocol"] == "tcp"
    assert row["n_connections"] == "7"
    assert (out / "channels.csv").is_file()
    assert (out / "features.csv").is_file()


def test_spectral_score_requires_sufficient_observations():
    assert spectral_score([1.0, 2.0]) == 0.0
