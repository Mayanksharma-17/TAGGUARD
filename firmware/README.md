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

## Wireless WebSocket Operation (Standalone Power)

The ESP32 firmware includes a built-in Wi-Fi SoftAP and RFC-6455 WebSocket server:
- **Standalone Wi-Fi Hotspot**: `TAGGUARD-HOTSPOT` (Password: `tagguard123`)
- **Default IP Address**: `192.168.4.1`
- **WebSocket URL**: `ws://192.168.4.1:81`

### Running Untethered (Wall Adapter / Power Bank):
1. Flash the firmware while connected to USB.
2. Unplug the ESP32 from your computer.
3. Power the ESP32 with **any external power source** (phone charger, power bank, or 5V wall adapter).
4. On your laptop/computer:
   - Connect Wi-Fi to **`TAGGUARD-HOTSPOT`** (password: `tagguard123`).
   - Open `dashboard.html` in Chrome or Edge.
   - Click **`🌐 Connect Wi-Fi (WebSocket)`**.
5. Turn the potentiometer on the breadboard and press the physical button (GPIO18) across the room.
   - The ESP32 signs each record with hash-chained HMAC-SHA256.
   - The measurement streams wirelessly in real time to your dashboard!

## Wiring Reference

| Component | GPIO | Notes |
|---|---|---|
| Potentiometer wiper | 34 | Via 1kΩ, 100µF cap to GND |
| Capture button | 18 | To GND, INPUT_PULLUP |
| LED test button | 19 | To GND, INPUT_PULLUP |
| Green LED (Ready) | 25 | Via 330Ω |
| Yellow LED (Capture) | 26 | Via 330Ω |
| Red LED (Warning) | 27 | Via 330Ω |
