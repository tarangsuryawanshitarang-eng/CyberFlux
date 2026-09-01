"""
CyberFlux — Centralized Configuration

All configurable values in one place. No magic values scattered throughout.
"""

from __future__ import annotations

import os


# ─── Server ───────────────────────────────────────────────────────────
API_HOST: str = os.getenv("CYBERFLUX_HOST", "0.0.0.0")
API_PORT: int = int(os.getenv("CYBERFLUX_PORT", "8000"))
CORS_ORIGINS: list[str] = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# ─── Simulation ───────────────────────────────────────────────────────
SIMULATION_RATE: float = float(os.getenv("CYBERFLUX_SIM_RATE", "50"))  # events/sec
SIMULATION_SEED: int | None = None  # Set for determinism
DEMO_PHASE_DURATION: float = float(os.getenv("CYBERFLUX_DEMO_PHASE", "15"))  # seconds

# ─── Bounds ───────────────────────────────────────────────────────────
MAX_LIVE_FLOWS: int = 500
MAX_ALERT_HISTORY: int = 200
MAX_METRIC_POINTS: int = 300
MAX_WEBSOCKET_QUEUE: int = 256
MAX_CLIENT_EVENTS: int = 1000

# ─── Performance ──────────────────────────────────────────────────────
METRICS_INTERVAL: float = 1.0  # seconds between metric snapshots
WS_HEARTBEAT_INTERVAL: float = 15.0  # seconds
WS_BATCH_INTERVAL: float = 0.1  # batch events for this long before sending

# ─── Logging ──────────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("CYBERFLUX_LOG_LEVEL", "INFO")

# ─── Security Constants ──────────────────────────────────────────────
# These are displayed in the UI and must match the architecture.
SECURITY_POSTURE = {
    "monitoring_mode": "READ-ONLY",
    "traffic_direction": "UNIDIRECTIONAL",
    "return_path": "BLOCKED",
    "active_probing": "DISABLED",
    "payload_decryption": "DISABLED",
}
