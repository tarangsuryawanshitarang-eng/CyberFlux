"""
CyberFlux — Flow Aggregator

Maintains a bounded table of active flows. Computes running statistics
for duration, packet/byte counts, and rates.
"""

from __future__ import annotations

import logging
from collections import OrderedDict

from app import config
from app.models.flow import FlowEvent

logger = logging.getLogger("cyberflux.processing")


class FlowAggregator:
    """Bounded flow table with LRU eviction."""

    def __init__(self, max_flows: int = config.MAX_LIVE_FLOWS) -> None:
        self._flows: OrderedDict[str, FlowEvent] = OrderedDict()
        self._max_flows = max_flows
        self._total_processed: int = 0

    @property
    def active_count(self) -> int:
        return len(self._flows)

    @property
    def total_processed(self) -> int:
        return self._total_processed

    def process(self, flow: FlowEvent) -> FlowEvent:
        """Add or update a flow in the table. Returns the processed flow."""
        self._total_processed += 1

        # Compute derived rates if not already set
        if flow.duration > 0:
            if flow.packets_per_second == 0:
                flow.packets_per_second = round(flow.packets / flow.duration, 1)
            if flow.bytes_per_second == 0:
                flow.bytes_per_second = round(flow.bytes_total / flow.duration, 1)

        # Compute outbound/inbound ratio
        if flow.inbound_bytes > 0 and flow.outbound_inbound_ratio == 0:
            flow.outbound_inbound_ratio = round(
                flow.outbound_bytes / max(flow.inbound_bytes, 1), 2
            )

        # Insert into bounded table
        self._flows[flow.flow_id] = flow
        self._flows.move_to_end(flow.flow_id)

        # Evict oldest if over limit
        while len(self._flows) > self._max_flows:
            self._flows.popitem(last=False)

        return flow

    def get_flow(self, flow_id: str) -> FlowEvent | None:
        return self._flows.get(flow_id)

    def get_flows(
        self,
        limit: int = 100,
        protocol: str | None = None,
        threat_status: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
    ) -> list[FlowEvent]:
        """Return recent flows with optional filtering."""
        flows = list(reversed(self._flows.values()))

        if protocol:
            flows = [f for f in flows if f.protocol == protocol]
        if threat_status:
            flows = [f for f in flows if f.threat_status == threat_status]
        if src_ip:
            flows = [f for f in flows if src_ip in f.src_ip]
        if dst_ip:
            flows = [f for f in flows if dst_ip in f.dst_ip]

        return flows[:limit]

    def clear(self) -> None:
        self._flows.clear()
        self._total_processed = 0
