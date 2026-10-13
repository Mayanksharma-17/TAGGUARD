# TAGGUARD
Tamper-evident laboratory measurement logger using ESP32 edge telemetry and HMAC-SHA256 independent verification.

# TAGGUARD — Tamper-Evident Laboratory Measurement Logger

> **ENG-05 Track | CyberHack 2026 — Build. Break. Defend.**
> Developed by **Quad-Coders** (Rajalakshmi Engineering College)

## 📌 Overview
Digital instruments in engineering and research laboratories export measurements to standard formats like CSV and JSON, but once exported, values can be silently manipulated without detection. 

**TAGGUARD** establishes record authenticity directly at the sensor acquisition layer:
1. **Hardware Acquisition**: An ESP32 microcontroller samples sensor voltages and attaches strictly monotonically increasing sequence numbers and UTC timestamps.
2. **Edge Cryptography**: Computes canonical HMAC-SHA256 authentication tags in real time using hardware-accelerated mbedTLS.
3. **Offline Export**: Emits standard, human-readable CSV/JSON records containing measurement data alongside cryptographic integrity tags.
4. **Independent Verifier**: A lightweight, zero-dependency Python verifier recalculates tags using constant-time comparison, instantly flagging data modifications, record deletions, and sequence anomalies.
