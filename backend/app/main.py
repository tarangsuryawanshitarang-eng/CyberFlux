"""
CyberFlux — FastAPI Application Entry Point

SIH 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Prototype / Research Build

MONITORING MODE: READ-ONLY
TRAFFIC DIRECTION: UNIDIRECTIONAL
RETURN PATH: BLOCKED
ACTIVE PROBING: DISABLED
PAYLOAD DECRYPTION: DISABLED
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.api import routes, websocket
from app.api.websocket import manager, websocket_endpoint
from app.services.pipeline import Pipeline

# ─── Logging ──────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cyberflux")

# ─── Pipeline ─────────────────────────────────────────────────────────

pipeline = Pipeline()


# Wire pipeline events to WebSocket broadcasts
async def _broadcast_flow(flow):
    await manager.broadcast("traffic_update", flow.model_dump())


async def _broadcast_alert(alert):
    await manager.broadcast("alert", alert.model_dump())


async def _broadcast_metrics(metrics):
    manager_count = manager.connection_count
    pipeline.metrics_service.set_active_connections(manager_count)
    await manager.broadcast("metrics_update", metrics.model_dump())


async def _broadcast_demo_phase(phase_info):
    await manager.broadcast("demo_phase", phase_info.model_dump())


pipeline.on_flow(_broadcast_flow)
pipeline.on_alert(_broadcast_alert)
pipeline.on_metrics(_broadcast_metrics)
pipeline.demo.on_phase_change(_broadcast_demo_phase)

# Give routes access to the pipeline
routes.set_pipeline(pipeline)


# ─── App Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("CyberFlux — AI Threat Detection System")
    logger.info("SIH 26145 Prototype / Research Build")
    logger.info("=" * 60)
    logger.info("Security Posture:")
    for key, value in config.SECURITY_POSTURE.items():
        logger.info("  %s: %s", key.upper(), value)
    logger.info("=" * 60)

    # Auto-start simulation with benign traffic
    pipeline.simulator.configure(scenario="BENIGN", event_rate=config.SIMULATION_RATE)
    pipeline.start_pipeline()
    logger.info("Pipeline started with BENIGN traffic at %.0f events/sec", config.SIMULATION_RATE)

    yield

    # Shutdown
    pipeline.stop_pipeline()
    logger.info("Pipeline stopped — shutting down")


# ─── FastAPI App ──────────────────────────────────────────────────────

app = FastAPI(
    title="CyberFlux — AI Threat Detection",
    description="SIH 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (Prototype)",
    version="1.0.0-prototype",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(routes.router, prefix="/api")

# WebSocket
app.add_api_websocket_route("/ws/events", websocket_endpoint)
