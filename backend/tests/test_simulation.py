"""
CyberFlux — Simulation & Feature Tests
"""

import random
import pytest

from app.simulation.scenarios import SCENARIOS, generate_benign, generate_syn_flood
from app.simulation.engine import SimulationEngine
from app.processing.flow_aggregator import FlowAggregator
from app.processing.feature_extractor import extract_features
from app.models.flow import FlowEvent


rng = random.Random(42)


# ─── Scenario Coverage ───────────────────────────────────────────────

def test_all_scenarios_registered():
    expected = {
        "BENIGN", "SYN_FLOOD", "UDP_REFLECTION", "BOTNET_C2",
        "DGA_DOMAIN", "DNS_TUNNELING", "MALWARE_TLS", "RECON_SCAN",
        "DATA_EXFILTRATION",
    }
    assert set(SCENARIOS.keys()) == expected


def test_all_scenarios_generate_flows():
    for name, profile in SCENARIOS.items():
        flow = profile.generator(rng, 1.0)
        assert isinstance(flow, FlowEvent), f"{name} did not produce FlowEvent"
        assert flow.flow_id != "", f"{name} has empty flow_id"


# ─── Feature Extraction ──────────────────────────────────────────────

def test_feature_extraction_returns_dict():
    flow = generate_benign(rng, 1.0)
    features = extract_features(flow)
    assert isinstance(features, dict)
    assert len(features) > 20  # Should have 30+ features


def test_feature_keys():
    flow = generate_syn_flood(rng, 1.0)
    features = extract_features(flow)
    expected_keys = [
        "packets_per_second", "bytes_per_second", "source_entropy",
        "destination_fanout", "port_fanout", "dns_entropy",
        "mean_interarrival", "periodicity_score",
    ]
    for key in expected_keys:
        assert key in features, f"Missing feature: {key}"


# ─── Flow Aggregator ─────────────────────────────────────────────────

def test_aggregator_bounded():
    agg = FlowAggregator(max_flows=10)
    for _ in range(20):
        flow = generate_benign(rng, 1.0)
        agg.process(flow)
    assert agg.active_count <= 10
    assert agg.total_processed == 20


def test_aggregator_get_flow():
    agg = FlowAggregator()
    flow = generate_benign(rng, 1.0)
    processed = agg.process(flow)
    assert agg.get_flow(processed.flow_id) is not None


def test_aggregator_filtering():
    agg = FlowAggregator()
    for _ in range(10):
        agg.process(generate_benign(rng, 1.0))
    flows = agg.get_flows(limit=5)
    assert len(flows) <= 5


# ─── Simulation Engine ───────────────────────────────────────────────

def test_engine_state():
    engine = SimulationEngine()
    assert engine.state.value == "IDLE"

    engine.start()
    assert engine.state.value == "RUNNING"

    engine.pause()
    assert engine.state.value == "PAUSED"

    engine.resume()
    assert engine.state.value == "RUNNING"

    engine.stop()
    assert engine.state.value == "IDLE"


def test_engine_deterministic():
    engine1 = SimulationEngine()
    engine1._rng = random.Random(99)
    engine1._scenario = "BENIGN"
    flow1 = engine1._generate_event()

    engine2 = SimulationEngine()
    engine2._rng = random.Random(99)
    engine2._scenario = "BENIGN"
    flow2 = engine2._generate_event()

    assert flow1.src_ip == flow2.src_ip
    assert flow1.dst_ip == flow2.dst_ip
    assert flow1.packets == flow2.packets
