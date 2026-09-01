# SIH 26145 — Execute `.agent.md`

You are now operating as the **lead engineer for this SIH 26145 prototype**.

There is an `.agent.md` file in the workspace. **Read it completely before making any changes. It is the primary engineering specification for this project.**

## Your task

Do not explain how the project could be built.

**Build the prototype.**

Follow `.agent.md` as the source of truth for:

* Architecture
* Technology choices
* Security constraints
* Threat detection
* Synthetic traffic generation
* ML/detection abstraction
* Real-time WebSocket streaming
* Dashboard
* Flow explorer
* Threat analysis
* One-click demo
* Performance optimization
* Loading optimization
* Testing
* Documentation
* Definition of Done

## Execution protocol

### Step 1 — Inspect

First inspect the existing workspace.

Determine:

* Current project structure
* Existing frontend
* Existing backend
* Existing dependencies
* Existing configuration
* Existing components that can be reused
* Current run/build commands
* Any incomplete implementation

**Do not overwrite existing working code unnecessarily.**

### Step 2 — Plan

Create a concise implementation plan based on the actual repository.

Prioritize:

1. Working end-to-end pipeline
2. Fast initial loading
3. Efficient real-time streaming
4. Technically defensible SIH architecture
5. Reliable one-click demo
6. UI polish

Do not over-engineer infrastructure.

### Step 3 — Implement incrementally

Implement and verify in this order:

```text
Project Skeleton
      ↓
Backend / Frontend Startup
      ↓
Event Schema
      ↓
Synthetic Traffic Engine
      ↓
Flow Processing
      ↓
Feature Engineering
      ↓
Detection Engine
      ↓
Risk / Confidence / Severity
      ↓
WebSocket Streaming
      ↓
SOC Dashboard
      ↓
Flow Explorer
      ↓
Threat Details
      ↓
Demo Mode
      ↓
Performance Optimization
      ↓
Testing
      ↓
Documentation
```

After each major stage, verify that the application still runs.

### Step 4 — Performance is mandatory

Do not treat performance optimization as a final cosmetic step.

Implement the requirements from `.agent.md`, especially:

* Route-level lazy loading
* Code splitting
* Deferred heavy components
* Skeleton loading
* Lightweight dependencies
* Bounded event buffers
* Bounded browser history
* Virtualized/paginated tables
* Memoized React components where useful
* Batched state updates
* Throttled chart rendering
* Efficient WebSocket handling
* Async backend processing
* No unnecessary polling
* No unbounded memory growth

The dashboard should remain responsive while synthetic telemetry is streaming.

### Step 5 — Security architecture

Preserve the SIH constraint throughout the implementation.

The prototype must visibly communicate:

```text
MONITORING MODE: READ-ONLY
TRAFFIC DIRECTION: UNIDIRECTIONAL
RETURN PATH: BLOCKED
ACTIVE PROBING: DISABLED
PAYLOAD DECRYPTION: DISABLED
```

Never introduce functionality that violates these constraints.

Do not implement offensive attack functionality.

### Step 6 — Detection

Implement the safe synthetic detection pipeline described in `.agent.md`.

Support:

* DDoS
* C2 Beaconing
* DGA
* DNS Tunneling
* TLS/QUIC metadata-based threat
* Reconnaissance
* Data Exfiltration

Use deterministic/statistical detection initially if a trained ML model is not available.

**Do not fabricate ML accuracy, precision, recall, F1, throughput, or production capability.**

The detector must have a clean interface so a real ML model can replace it later.

### Step 7 — Real-time behavior

The system must actually stream:

```text
Synthetic Traffic
      ↓
Feature Extraction
      ↓
Detection
      ↓
Alert
      ↓
WebSocket
      ↓
Dashboard
```

Alerts must appear without refreshing the page.

Metrics and charts must update live.

### Step 8 — One-click demo

Implement the complete demo sequence from `.agent.md`.

The user should be able to click:

```text
START DEMO
```

and observe:

```text
Normal
  ↓
Reconnaissance
  ↓
SYN Flood
  ↓
DNS Tunnel
  ↓
C2 Beaconing
  ↓
TLS/QUIC Threat
  ↓
Data Exfiltration
  ↓
Normal
```

The current phase must be visible.

The corresponding telemetry and alerts must appear during each phase.

### Step 9 — Test the actual application

Do not stop after writing code.

Actually run:

* Backend
* Frontend
* API
* WebSocket
* Simulator
* Detection pipeline
* Demo sequence
* Production frontend build
* Tests

Fix runtime errors rather than merely reporting them.

### Step 10 — Final audit

Before declaring completion, compare the implementation against **every section of `.agent.md`**.

Specifically verify:

```text
[ ] Architecture implemented
[ ] Security constraints preserved
[ ] Synthetic traffic works
[ ] Feature extraction works
[ ] Detection works
[ ] Evidence works
[ ] Confidence works
[ ] Severity works
[ ] WebSocket works
[ ] Live dashboard works
[ ] Traffic explorer works
[ ] Flow detail works
[ ] Threat detail works
[ ] Demo mode works
[ ] Performance optimizations implemented
[ ] Loading optimized
[ ] Memory bounded
[ ] Error handling implemented
[ ] Tests pass
[ ] Production build succeeds
[ ] README matches implementation
```

## Important behavior

Do not ask me to manually implement individual pieces unless you are genuinely blocked by missing information.

If you encounter an implementation decision not explicitly specified:

1. Prefer the architecture in `.agent.md`.
2. Prefer the simplest working solution.
3. Prefer performance and reliability over unnecessary complexity.
4. Preserve extensibility for future real ML/traffic ingestion.
5. Do not invent capabilities the prototype does not actually have.

**Start by reading `.agent.md` and inspecting the workspace. Then proceed with implementation.**
