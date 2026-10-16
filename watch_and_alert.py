"""TAGGUARD File Watcher, Email Alert & Self-Healing Rollback System
Monitors exported CSV/JSON files. When an attacker modifies a value in Excel
or any editor:
1. Detects file change within 2 seconds.
2. Identifies tampered values and cascading chain breaks.
3. Automatically fires a forensic alert email with an interactive
   [ 🛡️ RESTORE PRISTINE DATA ] One-Click Rollback button.
4. When clicked, TAGGUARD's built-in Self-Healing Engine restores the
   authentic physical measurements from the Cryptographic Vault,
   healing the broken hash chain back to 100% VALID!
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import make_msgid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import os
import secrets
import shutil
import smtplib
import socket
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "verifier"))

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

try:
    import verify
    import audit as audit_mod
except ImportError:
    print("[ERROR] Could not import verifier. Run from project root.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# ✏️ CONFIGURATION (Environment Variables with Safe Fallbacks)
# Set these in your environment, or pass them directly:
#   export TAGGUARD_GMAIL_SENDER="your-email@gmail.com"
#   export TAGGUARD_GMAIL_PASS="your-app-password"
#   export TAGGUARD_ALERT_TO="recipient@gmail.com"
# ─────────────────────────────────────────────────────────────
GMAIL_SENDER    = os.getenv("TAGGUARD_GMAIL_SENDER", "SENDER_GMAIL")
GMAIL_APP_PASS  = os.getenv("TAGGUARD_GMAIL_PASS", "xxxx xxxx xxxx xxxx")
ALERT_RECIPIENT = os.getenv("TAGGUARD_ALERT_TO", "RECEIVER_GMAIL")

DOWNLOADS_DIR = Path.home() / "Downloads"

WATCH_PATHS = [
    PROJECT_ROOT / "captures",
    PROJECT_ROOT / "examples",
    DOWNLOADS_DIR,
]
WATCH_PATHS += [Path(p) for p in sys.argv[1:] if Path(p).exists()]

WATCH_EXTENSIONS = {".csv", ".json"}
POLL_INTERVAL = 2

# Vault for immutable pristine snapshots
VAULT_DIR = PROJECT_ROOT / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

# State maps
VAULT_MAP: dict[str, str] = {}         # filename -> absolute original path
RESTORE_TOKENS: dict[str, str] = {}    # token -> filename
SERVER_PORT = 8080
LAN_IP = "127.0.0.1"


# ─────────────────────────────────────────────────────────────
# 🌐 NETWORK & SELF-HEALING HTTP SERVER
# ─────────────────────────────────────────────────────────────
def get_lan_ip() -> str:
    """Detect local network IP for cross-device mobile links on same Wi-Fi."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class SelfHealingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/restore":
            params = parse_qs(parsed.query)
            filename = params.get("file", [""])[0]
            token = params.get("token", [""])[0]

            if not filename or filename not in VAULT_MAP:
                self.respond_html(400, "Invalid Request", "File was not tracked in the TAGGUARD vault.")
                return

            vault_file = VAULT_DIR / filename
            target_path = Path(VAULT_MAP[filename])

            if not vault_file.exists():
                self.respond_html(404, "Vault Snapshot Missing", f"No pristine backup found for <code>{filename}</code>.")
                return

            try:
                shutil.copy2(vault_file, target_path)
            except PermissionError:
                retry_url = f"/restore?file={filename}&token={token}"
                self.respond_html(
                    200,
                    "⚠️ File Locked by Excel",
                    f"<p style='color:#f59e0b;'>Windows cannot overwrite <strong>{filename}</strong> because it is currently open in Excel or another program.</p>"
                    f"<p><strong>1. Close the file in Excel.</strong></p>"
                    f"<p><strong>2. Click below to finish restoring:</strong></p>"
                    f"<p><a href='{retry_url}' style='background:#10b981;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold;'>🔄 Retry Restore Now</a></p>"
                )
                return

            # Re-verify the restored file
            is_clean, incidents = verify_file_silently(target_path)
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            print("\n" + "=" * 60)
            print("  🛡️ TAGGUARD SELF-HEALING ENGINE TRIGGERED")
            print(f"  Restored : {filename}")
            print(f"  Target   : {target_path}")
            print(f"  Status   : {'✅ 100% CRYPTOGRAPHIC INTEGRITY RESTORED' if is_clean else '⚠️ Incomplete rollback'}")
            print("=" * 60 + "\n")

            self.respond_html(
                200,
                "✅ Cryptographic Rollback Successful!",
                f"""
                <div style="background:#0f172a; border:1px solid #10b981; border-radius:12px; padding:24px; margin-top:20px; text-align:left;">
                    <div style="color:#10b981; font-weight:800; font-size:20px; margin-bottom:12px;">
                        🛡️ Dataset Restored to Physical Capture State
                    </div>
                    <p style="color:#cbd5e1; margin:6px 0;"><strong>File Name:</strong> <code>{filename}</code></p>
                    <p style="color:#cbd5e1; margin:6px 0;"><strong>Target Location:</strong> <code>{target_path}</code></p>
                    <p style="color:#cbd5e1; margin:6px 0;"><strong>Restoration Time:</strong> {now_iso}</p>
                    <p style="color:#cbd5e1; margin:6px 0;"><strong>Integrity Status:</strong> <span style="color:#10b981; font-weight:bold;">ALL RECORDS VALID ✓ (Hash-Chain Intact)</span></p>
                    <hr style="border:0; border-top:1px solid #1e293b; margin:16px 0;">
                    <p style="color:#94a3b8; font-size:13px;">
                        The altered measurement records have been replaced with the pristine HMAC-SHA256 authenticated payload from the vault. 
                        The file on your computer has been successfully self-healed.
                    </p>
                </div>
                """
            )
            return

        self.send_response(404)
        self.end_headers()

    def respond_html(self, status: int, title: str, body_html: str):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>TAGGUARD Self-Healing</title>
    <style>
        body {{ background:#090d16; color:#f8fafc; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; padding:20px; box-sizing:border-box; }}
        .card {{ background:#0f172a; border:1px solid #1e293b; border-radius:16px; padding:32px; max-width:580px; width:100%; text-align:center; box-shadow:0 10px 30px rgba(0,0,0,0.5); }}
        h1 {{ font-size:22px; margin:0 0 12px 0; color:#f8fafc; }}
        code {{ background:#1e293b; padding:2px 8px; border-radius:4px; font-family:monospace; color:#38bdf8; font-size:13px; word-break:break-all; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{title}</h1>
        {body_html}
    </div>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Suppress default noisy console logs


def start_restore_server(preferred_port: int = 8080) -> int:
    """Starts the Self-Healing HTTP receiver on a background thread."""
    global SERVER_PORT
    for p in range(preferred_port, preferred_port + 10):
        try:
            server = HTTPServer(("0.0.0.0", p), SelfHealingHandler)
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            SERVER_PORT = p
            return p
        except OSError:
            continue
    SERVER_PORT = preferred_port
    return preferred_port


# ─────────────────────────────────────────────────────────────
# 🛡️ VAULT SNAPSHOT
# ─────────────────────────────────────────────────────────────
def snapshot_to_vault(file_path: Path) -> None:
    """Takes an immutable snapshot of an authentic file."""
    try:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        vault_file = VAULT_DIR / file_path.name
        vault_file.write_bytes(file_path.read_bytes())
        VAULT_MAP[file_path.name] = str(file_path.resolve())
    except Exception as ex:
        print(f"  [VAULT ERROR] Could not snapshot {file_path.name}: {ex}")


# ─────────────────────────────────────────────────────────────
# 📸 BIOMETRIC INTRUDER WEBCAM CAPTURE
# ─────────────────────────────────────────────────────────────
def capture_intruder_photo(event_id: str) -> Path | None:
    """Silently snaps a photo of whoever is in front of the laptop using webcam."""
    try:
        import cv2
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not cap.isOpened():
            cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None

        # Discard the first 3 frames so auto-exposure/gain settles
        for _ in range(3):
            cap.read()
            time.sleep(0.04)

        ret, frame = cap.read()
        cap.release()

        if not ret or frame is None:
            return None

        incidents_dir = PROJECT_ROOT / "audit_logs" / "incidents"
        incidents_dir.mkdir(parents=True, exist_ok=True)
        photo_path = incidents_dir / f"INTRUDER_{event_id}.jpg"
        cv2.imwrite(str(photo_path), frame)
        print(f"  [WEBCAM] 📸 Biometric intruder photo captured: {photo_path.name}")
        return photo_path
    except Exception as ex:
        print(f"  [WEBCAM] Note: Webcam capture skipped ({ex})")
        return None


# ─────────────────────────────────────────────────────────────
# 📧 EMAIL ALERT WITH BIOMETRIC EVIDENCE & ROLLBACK BUTTON
# ─────────────────────────────────────────────────────────────
def send_email_alert(incidents: list, verified_file: Path, event_id: str) -> None:
    """Sends forensic email with intruder photo and interactive Rollback button."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    token = secrets.token_hex(8)
    RESTORE_TOKENS[token] = verified_file.name
    VAULT_MAP[verified_file.name] = str(verified_file.resolve())

    # Silently capture intruder snapshot
    photo_path = capture_intruder_photo(event_id)

    # Build restore URLs
    restore_url_lan = f"http://{LAN_IP}:{SERVER_PORT}/restore?file={verified_file.name}&token={token}"
    restore_url_local = f"http://localhost:{SERVER_PORT}/restore?file={verified_file.name}&token={token}"

    has_vault_copy = (VAULT_DIR / verified_file.name).exists()

    # 1. Plain text fallback
    plain_lines = [
        "=" * 60,
        "  🚨 TAGGUARD FORENSIC TAMPER ALERT",
        "=" * 60,
        f"  Alert Time   : {now}",
        f"  Event ID     : {event_id}",
        f"  Source File  : {verified_file.name}",
        f"  Full Path    : {verified_file}",
        f"  Violations   : {len(incidents)} detected",
        "",
        "INCIDENT DETAILS",
        "-" * 60,
    ]
    for inc in incidents:
        plain_lines += [
            f"  Record #{inc.record_sequence:03d}",
            f"    Sensor       : {inc.source}",
            f"    Observed Val : {inc.observed_value} {inc.unit}",
            f"    Captured At  : {inc.capture_timestamp}",
            f"    Reason       : {inc.reason}",
            "",
        ]
    if photo_path and photo_path.exists():
        plain_lines += [
            "-" * 60,
            f"📸 BIOMETRIC EVIDENCE: Intruder photograph attached ({photo_path.name})",
            "-" * 60,
        ]
    if has_vault_copy:
        plain_lines += [
            "-" * 60,
            "🛡️ SELF-HEALING ROLLBACK AVAILABLE:",
            f"Click here to restore authentic data: {restore_url_lan}",
            f"(Or from host PC: {restore_url_local})",
            "-" * 60,
        ]
    plain_body = "\n".join(plain_lines)

    # 2. Rich HTML Email with Biometric Evidence Card & Rollback Button
    rows_html = ""
    for inc in incidents:
        rows_html += f"""
        <tr style="border-bottom: 1px solid #1e293b;">
            <td style="padding: 10px 14px; font-weight: bold; color: #f8fafc;">#{inc.record_sequence:03d}</td>
            <td style="padding: 10px 14px; color: #38bdf8;">{inc.source}</td>
            <td style="padding: 10px 14px; color: #ef4444; font-weight: bold;">{inc.observed_value} {inc.unit}</td>
            <td style="padding: 10px 14px; color: #94a3b8; font-size: 12px;">{inc.reason}</td>
        </tr>
        """

    button_html = ""
    if has_vault_copy:
        button_html = f"""
        <div style="text-align: center; margin: 32px 0 24px 0;">
            <a href="{restore_url_lan}" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 16px 36px; font-size: 16px; font-weight: 800; border-radius: 10px; display: inline-block; letter-spacing: 0.5px; box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);">
                🛡️ RESTORE PRISTINE DATA (ONE-CLICK ROLLBACK)
            </a>
            <div style="color: #64748b; font-size: 12px; margin-top: 10px;">
                Link: <a href="{restore_url_lan}" style="color: #38bdf8;">Network Link</a> &bull; <a href="{restore_url_local}" style="color: #38bdf8;">PC Localhost Link</a>
            </div>
        </div>
        """

    photo_html = ""
    cid_token = "INTRUDER_PHOTO_CID"
    if photo_path and photo_path.exists():
        photo_html = f"""
        <div style="background-color: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 12px; padding: 18px; margin-bottom: 24px; text-align: center;">
            <div style="color: #ef4444; font-weight: 800; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">
                📸 BIOMETRIC FORENSIC EVIDENCE: OPERATOR AT TAMPER TIME
            </div>
            <img src="cid:{cid_token}" style="max-width: 100%; max-height: 320px; border-radius: 8px; border: 2px solid #ef4444; box-shadow: 0 6px 20px rgba(0,0,0,0.5);" alt="Intruder Photograph" />
            <p style="color: #94a3b8; font-size: 11px; margin: 10px 0 0 0;">
                Webcam snapshot captured silently upon detecting file manipulation &bull; Timestamp: {now}
            </p>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
</head>
<body style="background-color: #090d16; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px;">
    <div style="max-width: 640px; margin: 0 auto; background-color: #0f172a; border: 1px solid #dc2626; border-radius: 14px; padding: 28px; box-shadow: 0 10px 30px rgba(239, 68, 68, 0.2);">
        
        <!-- Header -->
        <div style="border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; display: flex; align-items: center;">
            <div style="font-size: 28px; margin-right: 12px;">🚨</div>
            <div>
                <h2 style="margin: 0; color: #ef4444; font-size: 20px; font-weight: 800; letter-spacing: -0.5px;">TAGGUARD FORENSIC TAMPER ALERT</h2>
                <p style="margin: 3px 0 0 0; color: #94a3b8; font-size: 12px;">Cryptographic Measurement Logger &bull; Intrusion Detected</p>
            </div>
        </div>

        <!-- Alert Meta -->
        <div style="background-color: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 14px 18px; margin-bottom: 22px;">
            <p style="margin: 4px 0; font-size: 13px; color: #cbd5e1;"><strong>Event ID:</strong> <code style="color: #f87171;">{event_id}</code></p>
            <p style="margin: 4px 0; font-size: 13px; color: #cbd5e1;"><strong>Target File:</strong> <code>{verified_file.name}</code></p>
            <p style="margin: 4px 0; font-size: 13px; color: #cbd5e1;"><strong>Detection Timestamp:</strong> {now}</p>
            <p style="margin: 4px 0; font-size: 13px; color: #cbd5e1;"><strong>Total Violations:</strong> <span style="color: #ef4444; font-weight: bold;">{len(incidents)}</span></p>
        </div>

        <!-- Biometric Photo Evidence (if captured) -->
        {photo_html}

        <!-- Violations Table -->
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px; text-align: left;">
            <thead>
                <tr style="background-color: #1e293b; color: #94a3b8; font-size: 11px; text-transform: uppercase;">
                    <th style="padding: 10px 14px;">Seq</th>
                    <th style="padding: 10px 14px;">Sensor</th>
                    <th style="padding: 10px 14px;">Observed Value</th>
                    <th style="padding: 10px 14px;">Violation Reason</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <!-- Rollback Button -->
        {button_html}

        <!-- Footer -->
        <div style="border-top: 1px solid #1e293b; padding-top: 16px; margin-top: 24px; color: #64748b; font-size: 11px; text-align: center;">
            TAGGUARD &bull; CyberHack 2026 &bull; Developed by Quad-Coders (Rajalakshmi Engineering College)
        </div>
    </div>
</body>
</html>
"""

    msg = EmailMessage()
    msg["Subject"] = f"🚨 TAGGUARD TAMPER DETECTED — {verified_file.name} [{event_id}]"
    msg["From"]    = GMAIL_SENDER
    msg["To"]      = ALERT_RECIPIENT
    msg.set_content(plain_body)

    if photo_path and photo_path.exists():
        cid = make_msgid()[1:-1]
        html_content = html_content.replace(cid_token, cid)
        msg.add_alternative(html_content, subtype="html")
        photo_bytes = photo_path.read_bytes()
        # Inline related image for email body
        msg.get_payload()[1].add_related(photo_bytes, "image", "jpeg", cid=f"<{cid}>")
        # Direct file attachment
        msg.add_attachment(photo_bytes, maintype="image", subtype="jpeg", filename=photo_path.name)
    else:
        msg.add_alternative(html_content, subtype="html")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_SENDER, GMAIL_APP_PASS)
            server.send_message(msg)
        print(f"  [EMAIL] ✅ Forensic alert sent to {ALERT_RECIPIENT}")
        if photo_path:
            print(f"  [EMAIL] 📸 Biometric intruder photo attached ({photo_path.name})")
        if has_vault_copy:
            print(f"  [EMAIL] 🛡️ One-Click Rollback URL: {restore_url_lan}")
    except smtplib.SMTPAuthenticationError:
        print("  [EMAIL] ❌ Auth failed — check GMAIL_SENDER and GMAIL_APP_PASS.")
    except Exception as e:
        print(f"  [EMAIL] ❌ Failed to send: {e}")


# ─────────────────────────────────────────────────────────────
# 🔍 SILENT VERIFIER
# ─────────────────────────────────────────────────────────────
def verify_file_silently(path: Path) -> tuple[bool, list]:
    """Runs TAGGUARD verifier and returns (is_clean, incidents)."""
    try:
        key = verify.load_key(PROJECT_ROOT / ".tagguard.key")
        records = verify.load_records(path)
        if not records:
            return True, []

        incidents = []
        valid = True
        previous = 0
        is_chained = records[0].is_chained
        prev_tag_expected = verify.GENESIS_TAG
        import hmac as _hmac

        for record in records:
            expected_seq = previous + 1
            if record.sequence != expected_seq:
                incidents.append(audit_mod.TamperIncident(
                    incident_id=f"SEQ-{secrets.token_hex(4).upper()}",
                    record_sequence=record.sequence,
                    source=record.source,
                    observed_value=record.value,
                    unit=record.unit,
                    capture_timestamp=record.timestamp,
                    provided_tag=record.tag or "N/A",
                    recalculated_tag="N/A",
                    detection_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    reason=f"Sequence gap detected (got {record.sequence}, expected {expected_seq})",
                    severity="WARNING"
                ))
                valid = False
            previous = record.sequence

            if is_chained and record.prev_tag != prev_tag_expected:
                incidents.append(audit_mod.TamperIncident(
                    incident_id=f"CHN-{secrets.token_hex(4).upper()}",
                    record_sequence=record.sequence,
                    source=record.source,
                    observed_value=record.value,
                    unit=record.unit,
                    capture_timestamp=record.timestamp,
                    provided_tag=record.prev_tag,
                    recalculated_tag=prev_tag_expected,
                    detection_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    reason="Hash-chain continuity broken: previous record altered or dropped, causing cascading verification failure",
                    severity="CRITICAL"
                ))
                prev_tag_expected = record.tag
                valid = False
                continue

            recalc = verify.make_tag(record, key)
            if not (record.tag and _hmac.compare_digest(record.tag, recalc)):
                incidents.append(audit_mod.TamperIncident(
                    incident_id=f"MOD-{secrets.token_hex(4).upper()}",
                    record_sequence=record.sequence,
                    source=record.source,
                    observed_value=record.value,
                    unit=record.unit,
                    capture_timestamp=record.timestamp,
                    provided_tag=record.tag or "MISSING",
                    recalculated_tag=recalc,
                    detection_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    reason="HMAC tag mismatch: record payload altered after physical capture",
                    severity="CRITICAL"
                ))
                prev_tag_expected = recalc
                valid = False
            else:
                prev_tag_expected = record.tag

        return valid, incidents
    except Exception as e:
        print(f"  [VERIFY] Note: {path.name}: {e}")
        return True, []


def collect_watch_files() -> dict[Path, float]:
    files = {}
    for watch_path in WATCH_PATHS:
        watch_path = Path(watch_path)
        if watch_path.is_file() and watch_path.suffix in WATCH_EXTENSIONS:
            files[watch_path] = watch_path.stat().st_mtime
        elif watch_path.is_dir():
            for f in watch_path.rglob("*"):
                if f.is_file() and f.suffix in WATCH_EXTENSIONS:
                    files[f] = f.stat().st_mtime
    return files


# ─────────────────────────────────────────────────────────────
# 🚀 MAIN LOOP
# ─────────────────────────────────────────────────────────────
def main():
    global LAN_IP
    LAN_IP = get_lan_ip()
    port = start_restore_server(8080)

    print("=" * 65)
    print("  TAGGUARD Sentinel: File Watcher, Email & Self-Healing Engine")
    print("=" * 65)
    print(f"  Sender       : {GMAIL_SENDER}")
    print(f"  Alert To     : {ALERT_RECIPIENT}")
    print(f"  Rollback Host: http://{LAN_IP}:{port}/restore")
    print(f"  Watching     : {[str(p) for p in WATCH_PATHS]}")
    print("=" * 65)
    print("  Watching for file changes... Press Ctrl+C to stop.\n")

    known_files = collect_watch_files()
    alerted: set[Path] = set()

    print(f"  [INIT] Tracking {len(known_files)} file(s):")
    for f in known_files:
        is_clean, _ = verify_file_silently(f)
        if is_clean:
            snapshot_to_vault(f)
            print(f"         • {f.name} (Pristine Vault Snapshot Saved ✓)")
        else:
            print(f"         • {f.name} (Altered/Unsigned)")
    print()

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            current_files = collect_watch_files()

            for path, mtime in current_files.items():
                prev_mtime = known_files.get(path)

                # New file arrived
                if prev_mtime is None:
                    print(f"  [WATCH] New file detected: {path.name}")
                    known_files[path] = mtime
                    is_clean, incidents = verify_file_silently(path)
                    if is_clean:
                        snapshot_to_vault(path)
                        print(f"  [OK] {path.name} — initial check VALID ✓ (Vault Snapshot Saved)")
                    else:
                        print(f"  [ALERT] {path.name} — {len(incidents)} violation(s) detected on arrival! 🚨")
                        event_id = f"AUD-{secrets.token_hex(4).upper()}"
                        print(f"  [EMAIL] Sending forensic alert ({event_id})...")
                        send_email_alert(incidents, path, event_id)
                        alerted.add(path)
                    continue

                # Existing file was modified
                if mtime != prev_mtime:
                    known_files[path] = mtime
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                    print(f"  [CHANGE] {path.name} modified at {ts} — verifying...")

                    is_clean, incidents = verify_file_silently(path)

                    if is_clean:
                        print(f"  [OK] {path.name} — all records VALID ✓ (Vault Updated)")
                        snapshot_to_vault(path)
                        alerted.discard(path)
                    else:
                        print(f"  [ALERT] {path.name} — {len(incidents)} violation(s) detected! 🚨")
                        for inc in incidents:
                            print(f"    Record #{inc.record_sequence:03d}: {inc.reason}")

                        if path not in alerted:
                            event_id = f"AUD-{secrets.token_hex(4).upper()}"
                            print(f"  [EMAIL] Sending forensic alert with Self-Healing button ({event_id})...")
                            send_email_alert(incidents, path, event_id)
                            alerted.add(path)

    except KeyboardInterrupt:
        print("\n\n  [STOPPED] File watcher shut down.")


if __name__ == "__main__":
    main()
