# TAGGUARD Firmware — ESP32

## Requirements

- **Board**: ESP32 WROOM-32 DevKit V1 (30-pin)
- **IDE**: Arduino IDE 2.x
- **Board Package**: ESP32 by Espressif (install via Board Manager)
- **No extra libraries needed** — mbedTLS and Preferences are built into the ESP32 core

## Setup in Arduino IDE

1. **Install ESP32 board package**
   - File → Preferences → Additional Board Manager URLs:
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
   - Tools → Board → Board Manager → Search "ESP32" → Install

2. **Open the sketch**
   - File → Open → `firmware/tagguard/tagguard.ino`

3. **Select board**
   - Tools → Board → ESP32 Arduino → "ESP32 Dev Module"
   - Tools → Upload Speed → 115200
   - Tools → Port → (your COM port)

4. **Upload**
   - Click Upload (→ arrow button)

## First-Time Setup (Serial Monitor)

Open Serial Monitor at **115200 baud**, line ending = "Newline":

```
1. Set the HMAC key (get it from Python verifier):
   python verifier/verify.py show-key
   → Copy the KEY ... line and paste it into Serial Monitor

2. Set the clock:
   TIME 2026-10-14T09:00:00Z

3. Check status:
   STATUS
```

## Demo Flow

```
1. Press CAPTURE button (or type CAPTURE) → records a measurement
2. Repeat 3-5 times at different potentiometer positions
3. Type EXPORT → copies JSON to Serial Monitor
4. Paste JSON into a file: examples/captured.json
5. Verify:  python verifier/verify.py verify examples/captured.json
6. Edit one value in captured.json
7. Verify again → TAMPERED detected!
```

## Wiring Reference

| Component | GPIO | Notes |
|---|---|---|
| Potentiometer wiper | 34 | Via 1kΩ, 100µF cap to GND |
| Capture button | 18 | To GND, INPUT_PULLUP |
| LED test button | 19 | To GND, INPUT_PULLUP |
| Green LED (Ready) | 25 | Via 330Ω |
| Yellow LED (Capture) | 26 | Via 330Ω |
| Red LED (Warning) | 27 | Via 330Ω |
