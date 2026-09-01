"""
CyberFlux — WebSocket Handler

Real-time event streaming over WebSocket. Events are batched and sent
with bounded queues. Handles connection lifecycle, heartbeat, and
graceful disconnection.

Event types:
  - traffic_update: new/updated flow
  - alert: new alert
  - metrics_update: periodic system metrics
  - demo_phase: demo phase transition
  - system_status: health/status changes
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from app import config

logger = logging.getLogger("cyberflux.websocket")


class ConnectionManager:
    """Manages WebSocket connections with bounded queues."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._queues: dict[int, asyncio.Queue] = {}

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        self._queues[id(ws)] = asyncio.Queue(maxsize=config.MAX_WEBSOCKET_QUEUE)
        logger.info("WebSocket connected (total: %d)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        self._queues.pop(id(ws), None)
        logger.info("WebSocket disconnected (remaining: %d)", len(self._connections))

    async def broadcast(self, event_type: str, data: Any) -> None:
        """Broadcast an event to all connected clients."""
        if not self._connections:
            return

        message = json.dumps({
            "type": event_type,
            "data": data,
            "timestamp": time.time(),
        }, default=str)

        dead_connections = []
        for ws in self._connections:
            try:
                queue = self._queues.get(id(ws))
                if queue:
                    if queue.full():
                        # Drop oldest to make room (bounded queue)
                        try:
                            queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    await asyncio.wait_for(queue.put(message), timeout=0.1)
            except (asyncio.TimeoutError, Exception):
                dead_connections.append(ws)

        for ws in dead_connections:
            self.disconnect(ws)

    async def send_loop(self, ws: WebSocket) -> None:
        """Send queued messages to a single client. Run as a task per connection."""
        queue = self._queues.get(id(ws))
        if not queue:
            return

        try:
            while True:
                # Batch messages for efficiency
                messages = []
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=config.WS_HEARTBEAT_INTERVAL)
                    messages.append(msg)
                    # Drain additional available messages
                    while not queue.empty() and len(messages) < 20:
                        messages.append(queue.get_nowait())
                except asyncio.TimeoutError:
                    # Send heartbeat
                    await ws.send_json({"type": "heartbeat", "timestamp": time.time()})
                    continue

                for msg in messages:
                    await ws.send_text(msg)

        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error("WebSocket send error: %s", e)
        finally:
            self.disconnect(ws)


# Singleton manager
manager = ConnectionManager()


async def websocket_endpoint(ws: WebSocket) -> None:
    """WebSocket endpoint handler at /ws/events."""
    await manager.connect(ws)

    # Start send loop
    send_task = asyncio.create_task(manager.send_loop(ws))

    try:
        # Receive loop (for client commands like ping)
        while True:
            try:
                data = await ws.receive_text()
                msg = json.loads(data)

                if msg.get("type") == "ping":
                    await ws.send_json({"type": "pong", "timestamp": time.time()})

            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                continue
            except Exception:
                break

    finally:
        send_task.cancel()
        manager.disconnect(ws)
