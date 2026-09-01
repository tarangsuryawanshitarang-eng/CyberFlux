# CyberFlux — AI-Based Cyber Threat Detection in Unidirectional IP Traffic

> **Smart India Hackathon (SIH 2026) — Problem Statement 26145**  
> **Prototype / Research & Demonstration Build**

```text
MONITORING MODE: READ-ONLY
TRAFFIC DIRECTION: UNIDIRECTIONAL
RETURN PATH: BLOCKED
ACTIVE PROBING: DISABLED
PAYLOAD DECRYPTION: DISABLED
```

---

## 1. Project Overview

**CyberFlux** is an end-to-end Security Operations Center (SOC) prototype demonstrating real-time, AI-assisted detection of cybersecurity threats in **unidirectional IP traffic**.

In high-security networks (e.g., defense, critical infrastructure, financial enclaves), data diodes enforce physical unidirectional data flow. Monitoring systems in such enclaves receive traffic passively without any ability to transmit packets back to the source or complete TCP handshakes. CyberFlux proves that sophisticated threats can be accurately detected using purely **metadata, statistical, and behavioral characteristics** without payload decryption or active network probing.

---

## 2. System Architecture

```text
Monitored Source / Peering Link
           │
           │ ONE-WAY TRAFFIC
           ▼
  Read-Only Ingestion (Data Diode / Enclave)
           │
           ▼
     Flow Engine (Aggregation & Bounded LRU Table)
           │
           ▼
   Feature Engine (30+ Behavioral Features Extracted)
           │
           ▼
   Detection Engine (Deterministic Baseline / ML Interface)
           │
           ▼
      Risk Engine (Confidence Scoring & Severity Derivation)
           │
           ▼
     Alert Engine (Evidence & Feature Contribution Mapping)
           │
           ▼
   WebSocket Server (Real-Time Bidirectional Event Streaming)
           │
           ▼
   React SOC Dashboard (Data-Dense, Responsive Interface)
```

### Absolute Architectural Invariants
* **Strictly Read-Only**: The monitoring enclave receives one-way telemetry.
* **No Return Path**: The system never transmits packets to the monitored network.
* **No Active Probing**: Never scans, pings, or attempts handshakes with targets.
* **No Payload Decryption**: Encrypted traffic (TLS/QUIC) is analyzed via metadata only (JA3/JA4 fingerprints, cipher suites, packet timing, size distributions).
* **Safe Telemetry**: The simulation engine generates statistical distributions, not attack tooling.

---

## 3. Supported Threat Models

| Threat Category | Key Behavioral Indicators | Detection Mechanism |
|---|---|---|
| **Volumetric SYN Flood** | Extreme packet rate, small uniform packet sizes (~60B), high source IP entropy | Rate threshold + entropy + packet size uniformity |
| **UDP Reflection / Amplification** | Asymmetric inbound/outbound ratio (>10x), high inbound volume from DNS/NTP/SNMP ports | Asymmetry ratio + inbound byte volume |
| **Botnet C2 Beaconing** | Highly periodic communication, low inter-arrival variance (CV < 0.15), small fixed destinations | Periodicity score + timing regularity + fanout |
| **DGA Domain Activity** | High character entropy (>3.0), non-standard domain lengths, query bursts | Shannon entropy of domain names + query frequency |
| **DNS Tunneling** | Exceptionally long queries (>40 chars), high character entropy, high query frequency, outbound asymmetry | Query length + entropy + data directionality |
| **Malware over TLS/QUIC** | Suspicious JA3/JA4 fingerprints, deprecated TLS versions, anomalous traffic asymmetry | TLS metadata + fingerprint matching + timing |
| **Reconnaissance / Port Scan** | High destination host/port fanout, brief connection durations, high failure rate | Host/port fanout + duration distribution |
| **Data Exfiltration** | Sustained large outbound transfers (>500KB), high outbound/inbound ratio (>5x) | Outbound volume + duration + directional ratio |

---

## 4. Feature Engineering

The feature extraction layer computes **30+ behavioral features** per flow:

* **Volumetric**: `packets_per_second`, `bytes_per_second`, `packet_count`, `byte_count`, `duration`
* **Directional**: `inbound_bytes`, `outbound_bytes`, `outbound_inbound_ratio`
* **Network Topology**: `source_entropy`, `destination_fanout`, `port_fanout`
* **Timing Characteristics**: `mean_interarrival`, `interarrival_std`, `interarrival_cv`, `periodicity_score`
* **DNS Behavioral**: `dns_entropy`, `dns_query_length`, `dns_query_frequency`
* **Encrypted Metadata**: `tls_version_num`, `has_ja3`, `has_suspicious_fingerprint`, `ja4`
* **Packet Size Statistics**: `packet_size_mean`, `packet_size_std`, `packet_size_cv`
* **Compound Indicators**: `syn_indicator`, `scan_indicator`, `exfil_indicator`, `beacon_indicator`

---

## 5. Technology Stack

* **Frontend**: React 18, TypeScript (Strict), Vite, Tailwind CSS + SOC CSS Design Tokens, Recharts, Lucide Icons, Zustand
* **Backend**: Python 3.11+, FastAPI, Pydantic v2, WebSockets, NumPy, scikit-learn (ML interface)
* **Architecture**: Asynchronous, non-blocking pipeline with bounded queues and memory-controlled buffers

---

## 6. Running Locally

### Prerequisites
* Python 3.10+
* Node.js 18+ and npm

### Quick Start (Single Command)

**Windows**:
```bat
start.bat
```

**Linux / macOS**:
```bash
chmod +x start.sh && ./start.sh
```

---

### Manual Setup

#### 1. Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
* Backend API: `http://localhost:8000`
* Interactive API Docs: `http://localhost:8000/docs`
* WebSocket Endpoint: `ws://localhost:8000/ws/events`

#### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
* Dashboard UI: `http://localhost:5173`

#### 3. Running Backend Tests
```bash
cd backend
pytest tests/ -v
```

#### 4. Building Frontend for Production
```bash
cd frontend
npm run build
```

---

## 7. One-Click Demo Mode

Click **"START DEMO"** on the dashboard to trigger an automated 8-phase demonstration:

1. **Phase 1 — Normal Traffic**: Establishes behavioral baseline
2. **Phase 2 — Reconnaissance**: Port scanning and network mapping detection
3. **Phase 3 — SYN Flood**: Volumetric DDoS detection with source entropy
4. **Phase 4 — DNS Tunneling**: High-entropy covert data exfiltration via DNS
5. **Phase 5 — Botnet C2**: Periodic beaconing detection via timing regularity
6. **Phase 6 — Malware over TLS**: Encrypted threat detection via metadata & JA3
7. **Phase 7 — Data Exfiltration**: Large sustained outbound transfer detection
8. **Phase 8 — Return to Normal**: Demonstration of threat subsidence

Controls available: **Start**, **Pause**, **Resume**, **Stop**.

---

## 8. Performance & Technical Transparency

* **Detection Latency**: **Measured in real time** (`time_completed - time_received`) and displayed live in milliseconds/microseconds.
* **Bounded Memory**: Bounded client-side buffers (150 alerts, 200 flows, 120 metric points) and LRU backend tables (500 flows) prevent memory leaks.
* **Throttled Rendering & Batching**: High-frequency telemetry streams are batched for WebSocket transport and UI rendering (~5-20fps) to keep the browser responsive.
* **Technical Honesty**: This system is a **prototype / demonstration build**. Confidence scores are computed from mathematical feature indicators rather than a black-box trained model. No fabricated accuracy/F1 claims are made.

---

## 9. Future Extensibility

The modular architecture enables seamless expansion:
1. **PCAP & NetFlow Ingestion**: Replace the synthetic generator with live DPDK, AF_PACKET, or NetFlow/IPFIX collectors.
2. **Trained ML Models**: The `Detector` abstract base class allows drop-in replacement with Random Forest, XGBoost, or Isolation Forest models without altering API or frontend contracts.
3. **SIEM / Kafka Transport**: Streaming backend can integrate with Kafka/Redpanda message brokers for high-throughput enterprise pipelines.
