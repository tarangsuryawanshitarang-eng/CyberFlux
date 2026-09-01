"""
CyberFlux — REST API Routes

Clean endpoints with predictable schemas and error responses.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app import config

router = APIRouter()

# Pipeline is set by main.py after initialization
_pipeline = None


def set_pipeline(pipeline) -> None:
    global _pipeline
    _pipeline = pipeline


def _get_pipeline():
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    return _pipeline


# ─── Health & Info ────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "CyberFlux AI Threat Detection",
        "version": "1.0.0-prototype",
        "security_posture": config.SECURITY_POSTURE,
    }


@router.get("/security-posture")
async def security_posture():
    return config.SECURITY_POSTURE


# ─── Metrics ──────────────────────────────────────────────────────────

@router.get("/metrics")
async def get_metrics():
    pipeline = _get_pipeline()
    snapshot = pipeline.metrics_service.take_snapshot(
        active_flows=pipeline.aggregator.active_count
    )
    return snapshot.model_dump()


@router.get("/metrics/history")
async def get_metrics_history(limit: int = 60):
    pipeline = _get_pipeline()
    history = pipeline.metrics_service.get_history(limit)
    return [m.model_dump() for m in history]


# ─── Flows ────────────────────────────────────────────────────────────

@router.get("/flows")
async def get_flows(
    limit: int = 100,
    protocol: str | None = None,
    threat_status: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
):
    pipeline = _get_pipeline()
    flows = pipeline.aggregator.get_flows(
        limit=limit,
        protocol=protocol,
        threat_status=threat_status,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )
    return [f.model_dump() for f in flows]


@router.get("/flows/{flow_id}")
async def get_flow(flow_id: str):
    pipeline = _get_pipeline()
    flow = pipeline.aggregator.get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow.model_dump()


# ─── Alerts ───────────────────────────────────────────────────────────

@router.get("/alerts")
async def get_alerts(limit: int = 50, severity: str | None = None):
    pipeline = _get_pipeline()
    alerts = pipeline.alert_service.get_alerts(limit=limit, severity=severity)
    return [a.model_dump() for a in alerts]


@router.get("/alerts/summary")
async def get_alert_summary():
    pipeline = _get_pipeline()
    return pipeline.alert_service.get_summary().model_dump()


# ─── Threats ──────────────────────────────────────────────────────────

@router.get("/threats")
async def get_threats():
    """Threat category overview with counts and recent flows."""
    pipeline = _get_pipeline()
    summary = pipeline.alert_service.get_summary()

    from app.models.flow import ThreatClass
    categories = []
    for tc in ThreatClass:
        if tc == ThreatClass.BENIGN:
            continue
        count = summary.threat_class_counts.get(tc.value, 0)
        # Get recent flows for this threat
        flows = pipeline.aggregator.get_flows(limit=5, threat_status="MALICIOUS")
        threat_flows = [f for f in flows if f.threat_class == tc.value][:3]

        categories.append({
            "threat_class": tc.value,
            "display_name": tc.value.replace("_", " ").title(),
            "count": count,
            "recent_flows": [f.model_dump() for f in threat_flows],
        })

    return categories


# ─── Simulation Control ──────────────────────────────────────────────

@router.post("/simulation/start")
async def start_simulation(scenario: str = "BENIGN", intensity: float = 1.0, event_rate: float = 50.0):
    pipeline = _get_pipeline()
    pipeline.simulator.configure(scenario=scenario, intensity=intensity, event_rate=event_rate)
    pipeline.start_pipeline()
    return {"status": "started", "scenario": scenario}


@router.post("/simulation/stop")
async def stop_simulation():
    pipeline = _get_pipeline()
    pipeline.stop_pipeline()
    return {"status": "stopped"}


@router.post("/simulation/pause")
async def pause_simulation():
    pipeline = _get_pipeline()
    pipeline.simulator.pause()
    return {"status": "paused"}


@router.post("/simulation/resume")
async def resume_simulation():
    pipeline = _get_pipeline()
    pipeline.simulator.resume()
    return {"status": "resumed"}


@router.get("/simulation/status")
async def simulation_status():
    pipeline = _get_pipeline()
    status = pipeline.simulator.status
    demo_phase = None
    if pipeline.demo.is_running:
        from app.simulation.demo import DEMO_SEQUENCE
        idx = pipeline.demo.current_phase_index
        if idx < len(DEMO_SEQUENCE):
            phase = DEMO_SEQUENCE[idx]
            demo_phase = {
                "phase_name": phase[0].value,
                "phase_index": idx,
                "total_phases": len(DEMO_SEQUENCE),
                "description": phase[2],
            }

    return {
        **status.model_dump(),
        "demo_phase": demo_phase,
    }


# ─── Demo ─────────────────────────────────────────────────────────────

@router.post("/demo/start")
async def start_demo():
    pipeline = _get_pipeline()
    await pipeline.start_demo()
    return {"status": "demo_started"}


@router.post("/demo/stop")
async def stop_demo():
    pipeline = _get_pipeline()
    await pipeline.stop_demo()
    return {"status": "demo_stopped"}


@router.post("/demo/pause")
async def pause_demo():
    pipeline = _get_pipeline()
    pipeline.demo.pause()
    return {"status": "demo_paused"}


@router.post("/demo/resume")
async def resume_demo():
    pipeline = _get_pipeline()
    pipeline.demo.resume()
    return {"status": "demo_resumed"}


# ─── Detection Engine Info ────────────────────────────────────────────

@router.get("/detection/info")
async def detection_info():
    pipeline = _get_pipeline()
    return {
        "detector_name": pipeline.detector.name,
        "detector_type": pipeline.detector.detector_type,
        "note": "This is a prototype rule-based detector. Confidence values are computed from feature magnitudes. Not a trained ML model.",
    }
