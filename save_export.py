"""TAGGUARD Clipboard Auto-Saver
Instantly saves CSV/JSON copied from Arduino Serial Monitor to 'captures/'
and runs verification automatically. No need to close the Serial Monitor!
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys
import time
import tkinter as tk

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "verifier"))
try:
    import verify
except ImportError:
    verify = None

CAPTURES_DIR = PROJECT_ROOT / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)


def get_clipboard() -> str:
    try:
        root = tk.Tk()
        root.withdraw()
        content = root.clipboard_get()
        root.destroy()
        return content
    except Exception:
        return ""


def clean_csv(text: str) -> str | None:
    # Look for CSV content
    if "sequence,source,value" not in text:
        return None
    lines = text.strip().splitlines()
    clean = []
    recording = False
    for line in lines:
        l = line.strip()
        if "sequence,source,value" in l:
            recording = True
        if l == "--- END CSV ---":
            break
        if recording and l and not l.startswith("---"):
            clean.append(l)
    if clean:
        return "\n".join(clean) + "\n"
    return None


def clean_json(text: str) -> str | None:
    if "--- BEGIN JSON ---" in text and "--- END JSON ---" in text:
        m = re.search(r"--- BEGIN JSON ---\s*(.*?)\s*--- END JSON ---", text, re.DOTALL)
        if m:
            return m.group(1).strip() + "\n"
    elif text.strip().startswith("[") and text.strip().endswith("]") and '"sequence"' in text:
        return text.strip() + "\n"
    return None


def process_text(text: str) -> bool:
    csv_data = clean_csv(text)
    if csv_data:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        target_file = CAPTURES_DIR / f"telemetry_{ts}.csv"
        latest_file = CAPTURES_DIR / "latest.csv"
        target_file.write_text(csv_data, encoding="utf-8")
        latest_file.write_text(csv_data, encoding="utf-8")
        print("\n" + "=" * 50)
        print(f"✅ AUTO-SAVED CSV TO: {target_file}")
        print(f"✅ UPDATED: {latest_file}")
        if verify:
            print("-" * 50)
            try:
                key = verify.load_key(PROJECT_ROOT / ".tagguard.key")
                verify.verify_file(latest_file, key)
            except Exception as e:
                print(f"Verification note: {e}")
        print("=" * 50 + "\n")
        return True

    json_data = clean_json(text)
    if json_data:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        target_file = CAPTURES_DIR / f"telemetry_{ts}.json"
        latest_file = CAPTURES_DIR / "latest.json"
        target_file.write_text(json_data, encoding="utf-8")
        latest_file.write_text(json_data, encoding="utf-8")
        print("\n" + "=" * 50)
        print(f"✅ AUTO-SAVED JSON TO: {target_file}")
        print(f"✅ UPDATED: {latest_file}")
        if verify:
            print("-" * 50)
            try:
                key = verify.load_key(PROJECT_ROOT / ".tagguard.key")
                verify.verify_file(latest_file, key)
            except Exception as e:
                print(f"Verification note: {e}")
        print("=" * 50 + "\n")
        return True

    return False


def main():
    watch_mode = "--watch" in sys.argv or "-w" in sys.argv

    if not watch_mode:
        # One-shot mode: grab whatever is on clipboard right now
        clip = get_clipboard()
        if process_text(clip):
            sys.exit(0)
        else:
            print("No CSV or JSON export found on your clipboard!")
            print("Tip: In Arduino Serial Monitor, select the export text and press Ctrl+C, then run this again.")
            print("Or run: python save_export.py --watch  to auto-save in background whenever you copy!")
            sys.exit(1)

    print("=" * 60)
    print("  TAGGUARD Clipboard Auto-Saver (Live Watcher)")
    print("=" * 60)
    print("1. Keep your Arduino Serial Monitor OPEN.")
    print("2. Type EXPORT_CSV or EXPORT in Serial Monitor.")
    print("3. Highlight the text and press Ctrl+C.")
    print("   -> It will automatically save and verify the file!")
    print("Press Ctrl+C here in terminal to stop.")
    print("=" * 60 + "\n")
    print("Listening to clipboard...", flush=True)

    last_clip = ""
    while True:
        try:
            time.sleep(0.5)
            clip = get_clipboard()
            if clip and clip != last_clip:
                last_clip = clip
                process_text(clip)
        except KeyboardInterrupt:
            print("\nStopped.")
            break


if __name__ == "__main__":
    main()
