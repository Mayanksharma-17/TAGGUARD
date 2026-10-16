"""TAGGUARD Live Serial Bridge & Auto-Saver
Connects to ESP32 over USB. Automatically intercepts EXPORT_CSV and EXPORT_JSON
streams, writes them directly to disk in the 'captures/' folder, and instantly
verifies their cryptographic integrity.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import threading
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("Error: pyserial is required. Run: pip install pyserial")
    sys.exit(1)

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "verifier"))
try:
    import verify
except ImportError:
    verify = None

CAPTURES_DIR = PROJECT_ROOT / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)


def find_esp32_port() -> str | None:
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        return None
    # Prefer common ESP32 USB-UART adapters or COM3
    for p in ports:
        desc = (p.description or "").lower()
        if "ch340" in desc or "cp210" in desc or "usb-serial" in desc or "uart" in desc:
            return p.device
        if p.device.upper() == "COM3":
            return p.device
    # Otherwise return the first available COM port
    return ports[0].device


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else find_esp32_port()
    if not port:
        print("No serial ports found! Please connect your ESP32 via USB.")
        sys.exit(1)

    baud = 115200
    print("=" * 60)
    print("  TAGGUARD Live Serial Bridge & Auto-Saver")
    print(f"  Target Port : {port} @ {baud} baud")
    print(f"  Saving to   : {CAPTURES_DIR}")
    print("=" * 60)
    print("Commands you can type here:")
    print("  EXPORT_CSV -> grabs records and auto-saves to captures/")
    print("  EXPORT     -> grabs records and auto-saves JSON")
    print("  CAPTURE    -> triggers a sensor reading")
    print("  TIME       -> automatically syncs ESP32 clock with current UTC")
    print("  KEY        -> automatically sends project secret key to ESP32")
    print("  STATUS     -> shows ESP32 hardware status")
    print("  QUIT       -> exits bridge")
    print("=" * 60)
    print(f"Connecting to {port}... (Close Arduino Serial Monitor if it's open!)")

    try:
        ser = serial.Serial(port, baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"\n[ERROR] Could not open {port}: {e}")
        print("Make sure you CLOSE the Serial Monitor in Arduino IDE first so the port is free!")
        sys.exit(1)

    print(f"[CONNECTED] Listening to {port}...\n")

    collecting_csv = False
    collecting_json = False
    csv_lines: list[str] = []
    json_lines: list[str] = []
    running = True

    def reader_loop():
        nonlocal collecting_csv, collecting_json, csv_lines, json_lines, running
        buffer = ""
        while running:
            try:
                raw = ser.read(256)
                if not raw:
                    time.sleep(0.02)
                    continue
                text = raw.decode("utf-8", errors="replace")
                buffer += text
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip("\r")
                    clean_line = line.strip()

                    # Check for CSV export markers
                    if clean_line == "--- BEGIN CSV ---":
                        collecting_csv = True
                        csv_lines = []
                        print("\n[AUTO-SAVER] Intercepting CSV export stream from ESP32...")
                        continue
                    elif clean_line == "--- END CSV ---" and collecting_csv:
                        collecting_csv = False
                        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                        target_file = CAPTURES_DIR / f"telemetry_{ts}.csv"
                        latest_file = CAPTURES_DIR / "latest.csv"
                        csv_content = "\n".join(csv_lines).strip() + "\n"
                        target_file.write_text(csv_content, encoding="utf-8")
                        latest_file.write_text(csv_content, encoding="utf-8")
                        print(f"[AUTO-SAVER] ✅ File successfully saved: {target_file}")
                        print(f"[AUTO-SAVER] ✅ Also updated: {latest_file}")

                        # Trigger verification
                        if verify:
                            print("\n[VERIFIER] Running automatic cryptographic verification...")
                            try:
                                key = verify.load_key(PROJECT_ROOT / ".tagguard.key")
                                verify.verify_file(target_file, key)
                            except Exception as ex:
                                print(f"[VERIFIER] Verification error: {ex}")
                        csv_lines = []
                        print("\n> ", end="", flush=True)
                        continue

                    # Check for JSON export markers
                    if clean_line == "--- BEGIN JSON ---":
                        collecting_json = True
                        json_lines = []
                        print("\n[AUTO-SAVER] Intercepting JSON export stream from ESP32...")
                        continue
                    elif clean_line == "--- END JSON ---" and collecting_json:
                        collecting_json = False
                        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                        target_file = CAPTURES_DIR / f"telemetry_{ts}.json"
                        latest_file = CAPTURES_DIR / "latest.json"
                        json_content = "\n".join(json_lines).strip() + "\n"
                        target_file.write_text(json_content, encoding="utf-8")
                        latest_file.write_text(json_content, encoding="utf-8")
                        print(f"[AUTO-SAVER] ✅ File successfully saved: {target_file}")
                        print(f"[AUTO-SAVER] ✅ Also updated: {latest_file}")

                        if verify:
                            print("\n[VERIFIER] Running automatic cryptographic verification...")
                            try:
                                key = verify.load_key(PROJECT_ROOT / ".tagguard.key")
                                verify.verify_file(target_file, key)
                            except Exception as ex:
                                print(f"[VERIFIER] Verification error: {ex}")
                        json_lines = []
                        print("\n> ", end="", flush=True)
                        continue

                    if collecting_csv:
                        csv_lines.append(line)
                    elif collecting_json:
                        json_lines.append(line)
                    else:
                        # Normal serial output
                        print(f"[ESP32] {line}")
            except Exception as ex:
                if running:
                    print(f"\n[READER ERROR] {ex}")
                break

    t = threading.Thread(target=reader_loop, daemon=True)
    t.start()

    try:
        while running:
            user_input = input("> ").strip()
            if not user_input:
                continue
            cmd_upper = user_input.upper()
            if cmd_upper in ("QUIT", "EXIT"):
                running = False
                break
            elif cmd_upper == "TIME":
                now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                full_cmd = f"TIME {now_iso}\n"
                ser.write(full_cmd.encode("utf-8"))
                print(f"[BRIDGE] Sent: TIME {now_iso}")
            elif cmd_upper == "KEY":
                key_path = PROJECT_ROOT / ".tagguard.key"
                if key_path.exists():
                    hex_key = key_path.read_bytes().hex()
                    full_cmd = f"KEY {hex_key}\n"
                    ser.write(full_cmd.encode("utf-8"))
                    print(f"[BRIDGE] Sent: KEY {hex_key[:8]}...{hex_key[-8:]}")
                else:
                    print(f"[BRIDGE] Error: {key_path} not found. Run verify.py init-key first.")
            else:
                ser.write((user_input + "\n").encode("utf-8"))
    except KeyboardInterrupt:
        print("\nStopping bridge...")
    finally:
        running = False
        ser.close()
        print("[CLOSED] Serial port disconnected.")


if __name__ == "__main__":
    main()
