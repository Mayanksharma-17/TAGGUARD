# TAGGUARD — Tamper-Evident Laboratory Measurement Logger

> **ENG-05 Track | CyberHack 2026 — Build. Break. Defend.**  
> Developed by **Quad-Coders** (Rajalakshmi Engineering College)  
> *Nithin Aaron Smile (Team Lead) • Nandhan (Hardware) • Niranjana (Researcher) • Mayank Sharma (Software)*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Hardware](https://img.shields.io/badge/Hardware-ESP32%20WROOM--32-orange.svg)](https://www.espressif.com/)
[![Crypto](https://img.shields.io/badge/Crypto-HMAC--SHA256%20%28mbedTLS%29-green.svg)](https://tls.mbed.org/)

---

## 📌 Overview

Digital instruments in engineering and research laboratories record and export measurements to formats like CSV and JSON. However, once exported, values can be silently modified or manipulated without detection.

**TAGGUARD** establishes record authenticity directly at the point of capture:
1. **Hardware Acquisition**: An ESP32 microcontroller samples physical sensor inputs (e.g. potentiometer voltage), binding each reading with a strictly monotonic sequence number and UTC timestamp.
2. **Edge Cryptography**: Computes canonical **HMAC-SHA256** authentication tags in real time on the ESP32 using hardware-accelerated `mbedTLS`.
3. **Offline Export**: Emits human-readable CSV or JSON records containing measurement telemetry alongside 256-bit cryptographic integrity tags.
4. **Independent Verification**: A lightweight, zero-dependency Python verifier recomputes tags using constant-time comparison, immediately identifying tampered values, missing records, or sequence anomalies.

---

## 🏗️ Architecture

```text
[ 1. Hardware Layer ]       [ 2. Embedded & Crypto ]      [ 3. Data & Export ]      [ 4. Verification ]
 ESP32 + Potentiometer  -->  Arduino C++ / mbedTLS   -->   Canonical CSV / JSON -->   Python (hmac + hashlib)
 Push Button & LEDs          HMAC-SHA256 at Edge           Sequence, Value, Tag       Constant-Time Compare
```

| Layer | Component | Description |
|---|---|---|
| **Hardware** | ESP32 WROOM-32 | GPIO34 (ADC input), GPIO18 (Capture button), GPIO25-27 (Status LEDs) |
| **Embedded** | Arduino / mbedTLS | Hardware-accelerated HMAC-SHA256, NVS key storage, debounced capture |
| **Data Format** | JSON / CSV | Canonical format: `{"sequence":1,"source":"POT_SENSOR","timestamp":"...","unit":"V","value":"2.614"}` |
| **Verifier** | Python 3.10+ | Zero-dependency CLI and test suite with ANSI color-coded verification reports |

---

## ⚡ Quick Start

### 1. Verification & CLI (Python)

Requires Python 3.10+ with standard libraries only (no external packages needed).

```sh
# Generate signing key (stored at .tagguard.key)
python verifier/verify.py init-key

# Show key formatted for ESP32 Serial
python verifier/verify.py show-key

# Sign sample records
python verifier/verify.py sign examples/samples.json --output examples/signed.json

# Verify integrity and sequence
python verifier/verify.py verify examples/signed.json
```

### 2. Live Hackathon Demo (1-Click)

To demonstrate authentic verification, value tampering detection, and sequence gap detection in one command:

```sh
python demo.py
```

### 3. ESP32 Firmware

The firmware is located in [`firmware/tagguard/tagguard.ino`](firmware/tagguard/tagguard.ino).
- Open in **Arduino IDE 2.x** with the `esp32` board package installed.
- Select **ESP32 Dev Module**, 115200 baud.
- Upload to the board.
- Open Serial Monitor, configure key via `KEY <hex>` and clock via `TIME <iso8601>`.
- Press the hardware button on **GPIO18** to capture tamper-evident readings!
- Type `EXPORT` or `EXPORT_CSV` in the Serial Monitor to retrieve signed records.

See [firmware/README.md](firmware/README.md) for full wiring and setup details.

---

## 🧪 Testing

Run the automated test suite covering record schema validation, deterministic canonicalization, signing, tamper detection, and UTF-8 BOM compatibility:

```sh
python -m unittest discover tests -v
```

---

## 📜 Record Schema

| Field | Type | Description |
|---|---|---|
| `sequence` | integer | Monotonically increasing counter starting at 1 |
| `source` | string | Sensor identifier (e.g. `POT_SENSOR`) |
| `value` | decimal string | Exact measurement value (e.g. `2.614`) |
| `unit` | string | Measurement unit (e.g. `V`) |
| `timestamp` | string | UTC ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`) |
| `tag` | hex string | 64-character lowercase HMAC-SHA256 digest |

---

## ⚖️ Integrity vs. Truth Notice

TAGGUARD mathematically proves that an exported record has not been altered or deleted after it was recorded by the device. It does not verify physical sensor calibration or the honesty of manual user inputs.
