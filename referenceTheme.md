# CyberFlux Reference Theme

> **CyberFlux V2 Design System Specification**  
> Adapted from modern data product and operational dashboard design principles (inspired by clean analytical dashboard compositions, rigorous data hierarchies, and data-dense enterprise monitoring).

---

## 1. Design Philosophy

CyberFlux V2 is an operational Security Operations Center (SOC) dashboard engineered for real-time cyber threat detection in **unidirectional, read-only network enclaves**. 

The design philosophy rests on five core pillars:
1. **Clarity Over Clutter**: Every pixel communicates operational signal. Muted backgrounds and restrained accents keep attention focused on critical security indicators.
2. **Technical Honesty & Truthful Telemetry**: The UI represents real passive data diode constraints—never implying active firewall mitigation, payload decryption, or packet return paths.
3. **Data Density without Visual Overload**: High-density layouts, compact cards, and scannable tabular feeds enable analysts to absorb network velocity, latency, and threat postures in a single glance.
4. **Instant Actionability & Severity Distinction**: Severe threats (Critical, High) command unmistakable but non-garish semantic accents, while benign network traffic remains unobtrusive.
5. **Fluid, Low-Lag Interactivity**: Optimized DOM structures, bounded buffers, memoized computations, and slide-over investigation drawers ensure immediate feedback during high-throughput live replay.

---

## 2. Overall Visual Language

- **Theme Mode**: Sophisticated Dark SOC Workstation (deep obsidian, slate navy, and restrained neon/luminous accents).
- **Aesthetic Tone**: Technical, authoritative, modern, and disciplined. Avoids gimmicky "gamer" cyber aesthetics, excessive glassmorphism, heavy blur filters, and decorative geometric blobs.
- **Form Factor**: Razor-sharp, finely outlined containers with consistent 1px structural borders, subtle elevation shadows, and disciplined grid alignments.
- **Data Accents**: Cohesive indigo/violet primary accents with semantic status colors (ruby for critical threats, amber for warnings, emerald for healthy flows, and sky blue for informational telemetry).

---

## 3. Color System

All colors are defined with concrete HEX and RGBA values for consistent multi-tier surfaces.

### Primary Background
- **HEX**: `#070b14` (Deep Space Navy)
- **Role**: Root application background behind all main views and shells.

### Secondary Background
- **HEX**: `#0b1324` (Dark Slate Navy)
- **Role**: Layout framing, outer wrapper gutters, and top header background.

### Surface
- **HEX**: `#111c33` (Deep Navy Surface)
- **Role**: Base container background for primary cards, data widgets, and tabular grids.

### Elevated Surface
- **HEX**: `#172644` (Elevated Navy Surface)
- **Role**: Dropdowns, slide-over detail drawers, tooltips, popovers, and hovered table rows.

### Primary Accent
- **HEX**: `#6366f1` (Indigo Primary)
- **Hover**: `#4f46e5`
- **Soft Background**: `rgba(99, 102, 241, 0.14)`
- **Border**: `rgba(99, 102, 241, 0.40)`
- **Role**: Primary actions, active navigation states, key metric highlights.

### Secondary Accent
- **HEX**: `#8b5cf6` (Electric Violet)
- **Hover**: `#7c3aed`
- **Soft Background**: `rgba(139, 92, 246, 0.14)`
- **Role**: AI confidence indicators, behavioral anomaly scores, secondary charts.

### Success
- **HEX**: `#10b981` (Emerald Green)
- **Hover**: `#059669`
- **Soft Background**: `rgba(16, 185, 129, 0.12)`
- **Border**: `rgba(16, 185, 129, 0.35)`
- **Role**: Benign traffic, healthy pipeline status, connected telemetry stream.

### Warning
- **HEX**: `#f59e0b` (Warm Amber)
- **Hover**: `#d97706`
- **Soft Background**: `rgba(245, 158, 11, 0.12)`
- **Border**: `rgba(245, 158, 11, 0.35)`
- **Role**: Suspicious flow states, medium severity alerts, degraded pipeline conditions.

### Critical
- **HEX**: `#ef4444` (Crimson Red)
- **Hover**: `#dc2626`
- **Soft Background**: `rgba(239, 68, 68, 0.14)`
- **Border**: `rgba(239, 68, 68, 0.40)`
- **Role**: Malicious classifications, critical/high alerts, blocked return path badges.

### Info
- **HEX**: `#38bdf8` (Sky Blue)
- **Soft Background**: `rgba(56, 189, 248, 0.12)`
- **Border**: `rgba(56, 189, 248, 0.35)`
- **Role**: Informational telemetry, protocol tags, metadata chips.

### Primary Text
- **HEX**: `#f8fafc` (Near White / Slate 50)
- **Role**: Main titles, high-priority metric values, critical alert headlines.

### Secondary Text
- **HEX**: `#cbd5e1` (Slate 300)
- **Role**: Card subtitles, navigation item labels, table body content.

### Muted Text
- **HEX**: `#94a3b8` (Slate 400)
- **Role**: Column headers, timestamps, secondary feature attributes, inactive labels.

### Borders
- **Standard Border**: `#1e293b` (1px solid Slate 800)
- **Subtle Border**: `rgba(255, 255, 255, 0.08)`
- **Focus Border**: `#6366f1` (Indigo 500)
- **Divider**: `rgba(255, 255, 255, 0.05)`

---

## 4. Typography

### Font Family
- **Primary Interface**: `'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`
- **Technical & Numeric Telemetry**: `'JetBrains Mono', 'Fira Code', ui-monospace, monospace` (for IPs, ports, flow IDs, latency, confidence %, and data volumes).

### Heading Sizes
- **H1 (Page Title)**: `22px` (Line height: `28px`, Letter spacing: `-0.02em`, Weight: `700`)
- **H2 (Section Header)**: `16px` (Line height: `22px`, Letter spacing: `-0.01em`, Weight: `650`)
- **H3 (Card Title)**: `13.5px` (Line height: `18px`, Letter spacing: `0em`, Weight: `600`)
- **H4 (Sub-widget Title)**: `12px` (Line height: `16px`, Letter spacing: `0.02em`, Weight: `600`)

### Body Sizes
- **Body Large**: `14px` (Line height: `20px`)
- **Body Regular**: `13px` (Line height: `18px`)
- **Body Small**: `12px` (Line height: `16px`)
- **Micro / Mono**: `11px` (Line height: `14px`)

### Labels
- **Section & Column Label**: `10.5px` (Weight: `700`, Letter spacing: `0.06em`, Text transform: `uppercase`)
- **Badge Label**: `10px` (Weight: `700`, Letter spacing: `0.04em`)

### Font Weights
- **Regular**: `400`
- **Medium**: `500`
- **SemiBold**: `600`
- **Bold**: `700`

### Line Heights
- **Headings**: `1.2 – 1.3`
- **Body & Tabular**: `1.4 – 1.5`
- **Monospace Telemetry**: `1.2`

---

## 5. Layout

### Sidebar
- **Width**: `244px` (Fixed, full height `100vh`)
- **Background**: `#09101f` with 1px right border `#172338`
- **Z-Index**: `40`

### Header
- **Height**: `60px` (Fixed, sticky top)
- **Background**: `rgba(11, 19, 36, 0.85)` with `backdrop-filter: blur(8px)`
- **Border**: 1px bottom border `#1e293b`
- **Z-Index**: `30`

### Main Content
- **Margin Left**: `244px`
- **Padding**: `20px 24px 32px 24px`
- **Max Width**: `1680px` centered

### Grid
- **System**: 12-Column Responsive CSS Grid
- **Default Column Gap**: `16px`
- **Row Gap**: `16px`
- **Responsive Adjustments**: Single-column fallback below 1024px; 12-column spanning on desktop.

### Container Width
- **Full Viewport**: `100%`
- **Max Content Bounds**: `1680px`
- **Modal / Drawer Width**: `460px`

### Spacing Scale
- `space-1`: `4px`
- `space-2`: `8px`
- `space-3`: `12px`
- `space-4`: `16px`
- `space-5`: `20px`
- `space-6`: `24px`
- `space-8`: `32px`

---

## 6. Cards

### Border Radius
- **Outer Card**: `10px` (`--radius-md`)
- **Inner Sub-element / Pill**: `6px` (`--radius-sm`)
- **Pill / Dot Badge**: `9999px`

### Border
- **Thickness**: `1px`
- **Color**: `rgba(255, 255, 255, 0.08)`
- **Hover Border**: `rgba(99, 102, 241, 0.35)`

### Shadow
- **Card Base**: `0 2px 8px rgba(0, 0, 0, 0.35)`
- **Elevated / Drawer**: `0 12px 36px rgba(0, 0, 0, 0.55)`
- **Hover Glow**: `0 4px 16px rgba(99, 102, 241, 0.12)`

### Padding
- **Standard Card**: `16px 18px`
- **Compact Metric Card**: `12px 14px`
- **Dense Table Cell**: `8px 12px`

### Header
- **Height**: Auto (`28px` min)
- **Composition**: Left-aligned Title + Right-aligned Action / Filter / Badge
- **Margin Bottom**: `12px`

### Footer
- **Border Top**: `1px solid rgba(255, 255, 255, 0.06)`
- **Padding Top**: `10px`
- **Font Size**: `11px`

---

## 7. Buttons

### Primary
- **Background**: `#6366f1`
- **Hover**: `#4f46e5`
- **Text**: `#ffffff`
- **Padding**: `7px 14px`
- **Radius**: `6px`
- **Font**: `12.5px`, Weight: `600`
- **Shadow**: `0 1px 3px rgba(99, 102, 241, 0.3)`

### Secondary
- **Background**: `rgba(255, 255, 255, 0.06)`
- **Border**: `1px solid rgba(255, 255, 255, 0.12)`
- **Hover**: `rgba(255, 255, 255, 0.10)`
- **Text**: `#e2e8f0`
- **Padding**: `7px 12px`
- **Radius**: `6px`

### Ghost
- **Background**: `transparent`
- **Hover**: `rgba(255, 255, 255, 0.06)`
- **Text**: `#94a3b8` (Hover: `#f8fafc`)
- **Padding**: `6px 10px`

### Danger
- **Background**: `rgba(239, 68, 68, 0.15)`
- **Border**: `1px solid rgba(239, 68, 68, 0.40)`
- **Hover**: `rgba(239, 68, 68, 0.25)`
- **Text**: `#fca5a5`
- **Padding**: `7px 12px`

---

## 8. Navigation

### Sidebar
- **Container**: Fixed vertical strip with brand header, categorized groups, and pinned data-diode security footer.
- **Section Margins**: `16px 0 6px 0`

### Active Item
- **Background**: `rgba(99, 102, 241, 0.16)`
- **Border Left**: `3px solid #6366f1`
- **Text Color**: `#f8fafc`
- **Icon Color**: `#818cf8`
- **Font Weight**: `650`

### Hover State
- **Background**: `rgba(255, 255, 255, 0.05)`
- **Text Color**: `#f1f5f9`
- **Transition**: `background 0.15s ease, color 0.15s ease`

### Section Labels
- **Typography**: `10px`, Weight: `700`, Letter spacing: `0.08em`
- **Color**: `#64748b` (Slate 500)
- **Padding**: `8px 16px 4px 16px`

---

## 9. Data Visualization

### Charts
- **Area / Line Stroke**: `2px` width with subtle opacity gradients (`0.25` top to `0.01` bottom).
- **Grid Lines**: `rgba(255, 255, 255, 0.05)` dashed `3 3`.
- **Axes**: Font size `10.5px`, fill `#64748b`, stroke none.
- **Tooltips**: Background `#1e293b`, border `1px solid #334155`, text `#f8fafc`, box-shadow `0 8px 24px rgba(0, 0, 0, 0.5)`.

### Tables
- **Header**: Background `#0c1527`, uppercase text `10.5px`, color `#94a3b8`, 1px border `#1e293b`.
- **Row Heights**: `38px` dense mode, `44px` standard mode.
- **Row Hover**: `rgba(99, 102, 241, 0.07)`.
- **Alternating Rows**: Optional subtle zebra `rgba(255, 255, 255, 0.015)`.
- **Numeric & IP Alignment**: Right-aligned or strict monospace tabular alignment.

### KPI Cards
- **Structure**: Compact vertical hierarchy:
  1. Label with icon (`11px`, `#94a3b8`)
  2. Large Metric Value (`22px – 26px`, Monospace, `#f8fafc`)
  3. Subtitle / Delta pill (`11px`, e.g., `+3.8 Mbps` or `p95: 140 μs`)

### Progress Indicators
- **Track Height**: `5px`
- **Track Background**: `rgba(255, 255, 255, 0.08)`
- **Fill Radius**: `9999px`
- **Color Gradation**: Green (<50%), Amber (50-80%), Crimson (>80%).

### Sparklines
- **Height**: `24px`
- **Stroke**: `1.5px`
- **Fill**: Low-opacity area tint under stroke curve.

---

## 10. Cybersecurity Severity

Color and badge specifications across all threat classification layers:

### Critical
- **Badge Background**: `rgba(239, 68, 68, 0.16)`
- **Badge Border**: `1px solid rgba(239, 68, 68, 0.50)`
- **Badge Text**: `#f87171`
- **Pulse Indicator**: Glowing Crimson Dot `#ef4444`
- **Triggers**: DDoS SYN flood volume surges, active data exfiltration, C2 command executions.

### High
- **Badge Background**: `rgba(249, 115, 22, 0.16)`
- **Badge Border**: `1px solid rgba(249, 115, 22, 0.45)`
- **Badge Text**: `#fb923c`
- **Triggers**: Port reconnaissance fanout, DGA burst activity, DNS tunnel queries.

### Medium
- **Badge Background**: `rgba(245, 158, 11, 0.14)`
- **Badge Border**: `1px solid rgba(245, 158, 11, 0.40)`
- **Badge Text**: `#fbbf24`
- **Triggers**: Anomalous directional ratios, repetitive unclassified beacons.

### Low
- **Badge Background**: `rgba(59, 130, 246, 0.14)`
- **Badge Border**: `1px solid rgba(59, 130, 246, 0.35)`
- **Badge Text**: `#60a5fa`
- **Triggers**: Minor entropy deviations, unusual protocol ports.

### Informational
- **Badge Background**: `rgba(148, 163, 184, 0.12)`
- **Badge Border**: `1px solid rgba(148, 163, 184, 0.25)`
- **Badge Text**: `#94a3b8`
- **Triggers**: Baseline normal flow registrations, pipeline state updates.

---

## 11. Interaction States

### Hover
- **Cards**: Border transitions from `#1e293b` to `rgba(99, 102, 241, 0.35)`; subtle elevation lift.
- **Table Rows**: Background shifts to `rgba(99, 102, 241, 0.08)`.

### Active
- **Buttons / Chips**: Scale down `0.98`, background brightness increases.

### Selected
- **Cards / Tabs**: 1px solid `#6366f1` with `box-shadow: 0 0 0 1px #6366f1`.

### Focus
- **Input / Controls**: Outline `2px solid #6366f1`, outline-offset `2px`.

### Disabled
- **Opacity**: `0.45`
- **Cursor**: `not-allowed`
- **Pointer Events**: `none`

### Loading
- **Skeleton Shimmer**: Linear gradient animated from `#111c33` through `#1c2d4f` back to `#111c33` over `1.5s`.

### Error
- **Border**: `1px solid #ef4444`
- **Surface**: `rgba(239, 68, 68, 0.1)`

### Empty
- **Container**: Centered iconography with muted message, zero data illustrations, and prompt to trigger replay/demo.

---

## 12. Responsive Behaviour

Desktop-focused layout optimized for modern SOC multi-monitor environments:

- **1920 × 1080 (FHD SOC Command Wall)**: Full 12-column layout, 6-card KPI strip, dual visualization charts, expanded tabular logs.
- **1440 × 900 (High-Resolution Laptop)**: 12-column layout with 4-card or 6-card flex KPI grid, side-by-side charts with auto-scaled height.
- **1366 × 768 (Standard Corporate Display)**: Main dashboard adapts cleanly, charts scale to 220px height, table horizontal overflow enabled with sticky header, zero page-level horizontal overflow.

---

## 13. Visual Hierarchy

The interface strictly organizes information into 5 distinct cognitive priority levels:

- **Level 1 → Critical Security Information**: Active threat classification, alert severity badges, overall system threat posture, one-click demo controls.
- **Level 2 → Detection Information**: AI confidence score (e.g. `96.4%`), MITRE ATT&CK Tactic & Technique IDs, anomaly score deviation.
- **Level 3 → Network Telemetry**: Throughput (Mbps), packet rate (pps), flow count, directional Out/In ratio, protocol breakdown.
- **Level 4 → Technical Metadata**: Source IP/port, Destination IP/port, JA3/JA4 TLS fingerprints, DNS query entropy, flow duration.
- **Level 5 → Raw Evidence**: Feature contributions list, statistical inter-arrival variance, packet size distribution curves.

---

## 14. Do / Don't Guidelines

### Do
- **Do** use monospace fonts (`JetBrains Mono`) for all IP addresses, ports, hex fingerprints, and numbers.
- **Do** keep cards compact and information-dense to preserve first-viewport visibility.
- **Do** use slide-over drawers for alert details rather than forcing a disruptive full-page navigation.
- **Do** clearly show the MITRE ATT&CK tactic and technique relationship for every threat category.
- **Do** memoize chart datasets to 40–60 points to eliminate browser frame drops during high-rate telemetry.
- **Do** prominently feature the read-only, passive data-diode security constraints.

### Don't
- **Don't** add fake mitigation actions (e.g., "Block IP", "Quarantine Host", "Reset Connection") that contradict the unidirectional read-only architecture.
- **Don't** use overly bright, garish saturated backgrounds or rainbow gradients.
- **Don't** create oversized, fluffy cards with excessive empty white space.
- **Don't** re-render the entire React component tree on every single WebSocket packet.
- **Don't** show empty blank screens—always provide informative, styled empty states with contextual hints.

---

## 15. CyberFlux-Specific Adaptations

To reflect CyberFlux's unique data-diode monitoring architecture:

1. **Passive Telemetry Banner**: Pinned header badge and sidebar callouts stating:
   - `MONITORING: READ-ONLY`
   - `TRAFFIC DIRECTION: UNIDIRECTIONAL`
   - `RETURN PATH: BLOCKED`
   - `ACTIVE PROBING: DISABLED`
   - `PAYLOAD DECRYPTION: DISABLED`
2. **Interactive Attack Scenario Selector**: Instant demonstration bar allowing SOC evaluators and judges to trigger supported attack profiles:
   - `SYN Flood (DDoS)`
   - `Botnet C2 Beaconing`
   - `DGA Domain Activity`
   - `DNS Tunneling`
   - `Malware over TLS/QUIC`
   - `Port Scan / Reconnaissance`
   - `Data Exfiltration`
   - `UDP Reflection`
   - `Automated 8-Phase Demo`
3. **Slide-over Alert Detail Drawer**: Clicking any alert or flow opens a non-disruptive drawer displaying:
   - Alert ID & Flow ID
   - Severity & AI Confidence %
   - MITRE ATT&CK Tactic & Technique (`T1046`, `T1498`, `T1071`, etc.)
   - Source IP:Port → Destination IP:Port
   - Empirical evidence indicators & top feature contributions
   - Deep link to full flow investigation view
4. **Transparent Pipeline Telemetry**: The 6-stage enclave pipeline visualizer explicitly highlights measured processing latencies (p50 in microseconds, p95, p99) and OS-measured process memory.
