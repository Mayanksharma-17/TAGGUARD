"""TAGGUARD: sign and verify exported lab measurement records."""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEY = PROJECT_ROOT / ".tagguard.key"
# v1 format: no prev_tag. v2 format: includes prev_tag for hash-chaining.
FIELDS_V1    = ("sequence", "source", "value", "unit", "timestamp", "tag")
FIELDS_V2    = ("sequence", "source", "value", "unit", "timestamp", "prev_tag", "tag")
FIELDS       = FIELDS_V1          # default; auto-detected in load_records
SIGNED_FIELDS_V1 = FIELDS_V1[:-1]
SIGNED_FIELDS_V2 = FIELDS_V2[:-1]  # all except tag
GENESIS_TAG  = "0" * 64            # chain sentinel for Record #1
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
TAG_RE = re.compile(r"[0-9a-f]{64}\Z")

# Audit engine import
try:
    from audit import AuditLogger, VerificationAuditEvent, TamperIncident, now_utc_iso
except ImportError:
    from verifier.audit import AuditLogger, VerificationAuditEvent, TamperIncident, now_utc_iso


# ── Terminal colour helpers ──────────────────────────────────────────
def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32  # type: ignore[attr-defined]
            h = k.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            k.GetConsoleMode(h, ctypes.byref(mode))
            k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    return True


_COLOR = _supports_color()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def green(t: str) -> str: return _c("92", t)
def red(t: str) -> str: return _c("91", t)
def yellow(t: str) -> str: return _c("93", t)
def bold(t: str) -> str: return _c("1", t)


# Force UTF-8 on Windows so ✓/✗/⚠ don't crash charmap.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass

# Safe symbols (fallback to ASCII if terminal can't handle Unicode)
try:
    _test = "✓✗⚠"
    _test.encode(sys.stdout.encoding or "utf-8")
    SYM_OK, SYM_FAIL, SYM_WARN = "✓", "✗", "⚠"
except (UnicodeEncodeError, LookupError):
    SYM_OK, SYM_FAIL, SYM_WARN = "+", "X", "!"


@dataclass
class Record:
    sequence: int
    source: str
    value: str
    unit: str
    timestamp: str
    tag: str = ""
    prev_tag: str = ""    # empty = v1 format (no chaining)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], row: int) -> "Record":
        if not isinstance(raw, dict):
            raise ValueError(f"record {row}: expected an object/CSV row")
        # Auto-detect v1 vs v2 format
        is_v2 = "prev_tag" in raw
        expected = set(FIELDS_V2 if is_v2 else FIELDS_V1)
        missing = expected - set(raw)
        extra   = set(raw) - expected
        if missing or extra:
            details = []
            if missing:
                details.append("missing " + ", ".join(sorted(missing)))
            if extra:
                details.append("unexpected " + ", ".join(sorted(extra)))
            raise ValueError(f"record {row}: " + "; ".join(details))
        seq = raw["sequence"]
        if isinstance(seq, str) and re.fullmatch(r"[0-9]+", seq):
            seq = int(seq)
        prev_tag = raw.get("prev_tag", "")
        record = cls(seq, raw["source"], raw["value"], raw["unit"],
                     raw["timestamp"], raw["tag"], prev_tag)
        record.validate(row)
        return record

    def validate(self, row: int = 1) -> None:
        prefix = f"record {row}: "
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError(prefix + "sequence must be a positive whole number")
        for field in ("source", "value", "unit", "timestamp", "tag"):
            if not isinstance(getattr(self, field), str):
                raise ValueError(prefix + f"{field} must be text")
        if not self.source.strip():
            raise ValueError(prefix + "source must not be empty")
        if not self.unit.strip():
            raise ValueError(prefix + "unit must not be empty")
        try:
            number = Decimal(self.value)
            if not number.is_finite():
                raise InvalidOperation
        except InvalidOperation:
            raise ValueError(prefix + "value must be a finite decimal written as text") from None
        if not TIMESTAMP_RE.fullmatch(self.timestamp):
            raise ValueError(prefix + "timestamp must be UTC ISO 8601, e.g. 2026-10-12T09:00:00Z")
        try:
            datetime.fromisoformat(self.timestamp[:-1] + "+00:00")
        except ValueError:
            raise ValueError(prefix + "timestamp is not a valid date/time") from None
        if self.tag and not TAG_RE.fullmatch(self.tag):
            raise ValueError(prefix + "tag must be blank or 64 lowercase hex characters")
        if self.prev_tag and not TAG_RE.fullmatch(self.prev_tag):
            raise ValueError(prefix + "prev_tag must be blank or 64 lowercase hex characters")

    @property
    def is_chained(self) -> bool:
        """True when this record carries a prev_tag (v2 / hash-chained format)."""
        return bool(self.prev_tag)

    def signed_data(self) -> dict[str, Any]:
        if self.is_chained:
            # v2: include prev_tag so the chain is cryptographically enforced
            return {
                "prev_tag": self.prev_tag,
                "sequence": self.sequence,
                "source":   self.source,
                "timestamp": self.timestamp,
                "unit":     self.unit,
                "value":    self.value,
            }
        # v1 legacy: original five fields
        return {name: getattr(self, name) for name in SIGNED_FIELDS_V1}

    def as_dict(self) -> dict[str, Any]:
        d = {**self.signed_data(), "tag": self.tag}
        return d


def canonical_bytes(record: Record) -> bytes:
    """Canonical UTF-8 JSON for the signed fields; tag is always excluded."""
    encoded = json.dumps(record.signed_data(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return encoded.encode("utf-8")


def make_tag(record: Record, key: bytes) -> str:
    return hmac.new(key, canonical_bytes(record), hashlib.sha256).hexdigest()


def load_key(path: Path) -> bytes:
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        raise ValueError(f"Key not found: {path}. Run `python verifier/verify.py init-key` first.") from None
    if len(key) < 32:
        raise ValueError("key file must contain at least 32 random bytes")
    return key


def load_records(path: Path) -> list[Record]:
    try:
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8-sig") as stream:
                reader = csv.DictReader(stream)
                if reader.fieldnames is None:
                    raise ValueError("CSV file has no header row")
                if set(reader.fieldnames) != set(FIELDS):
                    raise ValueError("CSV header must contain: " + ",".join(FIELDS))
                return [Record.from_dict(row, i) for i, row in enumerate(reader, start=2)]
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise ValueError(f"input file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from None
    if not isinstance(raw, list):
        raise ValueError("JSON file must contain a list of records")
    return [Record.from_dict(item, i) for i, item in enumerate(raw, start=1)]


def save_records(records: list[Record], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(record.as_dict() for record in records)
    else:
        path.write_text(json.dumps([r.as_dict() for r in records], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def create_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(secrets.token_bytes(32))
    except FileExistsError:
        raise ValueError(f"key already exists; leaving it unchanged: {path}") from None
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(f"Created private key: {path}")
    print("Keep it secret and do not commit it. Verification needs this same key.")


def sign_file(source: Path, output: Path, key: bytes) -> None:
    records = load_records(source)
    for record in records:
        record.tag = make_tag(record, key)
    save_records(records, output)
    print(f"Signed {len(records)} record(s) -> {output}")


def verify_file(source: Path, key: bytes) -> bool:
    records = load_records(source)
    valid = True
    previous = 0
    tampered = 0
    seq_issues = 0
    chain_breaks = 0
    ok = 0
    incidents: list[TamperIncident] = []

    # Detect format from first record
    is_chained = records[0].is_chained if records else False
    format_label = green("Hash-Chained Ledger (v2)") if is_chained else yellow("Standard HMAC (v1)")

    print(bold("=" * 52))
    print(bold("  TAGGUARD  Verification Report"))
    print(bold("=" * 52))
    print(f"  File:   {source}")
    print(f"  Format: {format_label}")
    print(f"  Records: {len(records)}")
    print(bold("-" * 52))

    now_iso = now_utc_iso()
    prev_tag_expected = GENESIS_TAG  # chain sentinel for record #1

    for record in records:
        expected_seq = previous + 1
        if record.sequence != expected_seq:
            print(f"  Record {record.sequence}: {yellow(f'{SYM_WARN} SEQUENCE ISSUE')} (expected {expected_seq})")
            seq_issues += 1
            valid = False
            incidents.append(TamperIncident(
                incident_id=f"SEQ-{secrets.token_hex(4).upper()}",
                record_sequence=record.sequence,
                source=record.source,
                observed_value=record.value,
                unit=record.unit,
                capture_timestamp=record.timestamp,
                provided_tag=record.tag or "N/A",
                recalculated_tag="N/A",
                detection_timestamp=now_iso,
                reason=f"Sequence gap or duplicate detected (got {record.sequence}, expected {expected_seq})",
                severity="WARNING"
            ))
        previous = record.sequence

        # ── Chain-link continuity check (v2 only) ──────────
        if is_chained and record.prev_tag != prev_tag_expected:
            print(f"  Record {record.sequence}: {red(f'{SYM_FAIL} CHAIN BREAK')} "
                  f"(prev_tag mismatch — cascading failure from earlier tampering)")
            chain_breaks += 1
            tampered += 1
            valid = False
            incidents.append(TamperIncident(
                incident_id=f"CHN-{secrets.token_hex(4).upper()}",
                record_sequence=record.sequence,
                source=record.source,
                observed_value=record.value,
                unit=record.unit,
                capture_timestamp=record.timestamp,
                provided_tag=record.prev_tag,
                recalculated_tag=prev_tag_expected,
                detection_timestamp=now_iso,
                reason="Hash-chain continuity broken: previous record was tampered or deleted, causing cascade failure",
                severity="CRITICAL"
            ))
            # Still advance expected prev_tag from this record's tag for subsequent checks
            prev_tag_expected = record.tag
            continue

        recalc = make_tag(record, key)
        if record.tag and hmac.compare_digest(record.tag, recalc):
            print(f"  Record {record.sequence}: {green(f'{SYM_OK} VALID')}")
            ok += 1
            prev_tag_expected = record.tag   # advance chain head
        else:
            print(f"  Record {record.sequence}: {red(f'{SYM_FAIL} TAMPERED / INVALID TAG')}")
            tampered += 1
            valid = False
            # After a tamper the expected chain head changes — cascade begins here
            prev_tag_expected = recalc
            incidents.append(TamperIncident(
                incident_id=f"MOD-{secrets.token_hex(4).upper()}",
                record_sequence=record.sequence,
                source=record.source,
                observed_value=record.value,
                unit=record.unit,
                capture_timestamp=record.timestamp,
                provided_tag=record.tag or "MISSING",
                recalculated_tag=recalc,
                detection_timestamp=now_iso,
                reason="HMAC tag mismatch: record payload altered after physical capture",
                severity="CRITICAL"
            ))

    print(bold("-" * 52))
    overall = "CLEAN" if valid else ("TAMPERED_DETECTED" if tampered else "SEQUENCE_ANOMALY")
    if not records:
        print(yellow("  No records found."))
    elif valid:
        chain_note = f" (Chain Integrity: {SYM_OK})" if is_chained else ""
        print(green(f"  Result: ALL {ok} RECORD(S) VALID {SYM_OK}{chain_note}"))
    else:
        parts = []
        if tampered - chain_breaks:
            parts.append(f"{tampered - chain_breaks} TAMPERED")
        if chain_breaks:
            parts.append(f"{chain_breaks} CHAIN BREAK(S)")
        if seq_issues:
            parts.append(f"{seq_issues} SEQUENCE ISSUE(S)")
        print(red(f"  Result: {', '.join(parts)} {SYM_FAIL}"))
    print(bold("=" * 52))

    # Log to persistent audit trail & generate incident report if needed
    logger = AuditLogger()
    event = VerificationAuditEvent(
        event_id=f"AUD-{secrets.token_hex(4).upper()}",
        timestamp=now_iso,
        verified_file=str(source),
        total_records=len(records),
        valid_count=ok,
        tampered_count=tampered,
        sequence_issue_count=seq_issues,
        overall_status=overall,
        incidents=incidents
    )
    report_or_log = logger.log_event(event)
    print(f"  Audit Event Logged: {event.event_id} -> audit_logs/audit_trail.jsonl")
    if incidents:
        print(bold(red(f"  🚨 Forensic Report: {report_or_log}")))
    return valid


def show_audit_history() -> None:
    logger = AuditLogger()
    history = logger.get_history()
    print(bold("=" * 60))
    print(bold("  TAGGUARD  Verification Audit Trail History"))
    print(bold("=" * 60))
    if not history:
        print("  No audit events recorded yet.")
        return
    for item in history[-10:]:
        status = item.get("overall_status")
        badge = green("✓ CLEAN") if status == "CLEAN" else red(f"✗ {status}")
        print(f"  [{item.get('timestamp')}] {item.get('event_id')} | {badge}")
        print(f"    File: {item.get('verified_file')} | Total: {item.get('total_records')} | Tampered: {item.get('tampered_count')}")
    print(bold("=" * 60))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Sign and verify TAGGUARD JSON or CSV measurement records.")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-key", help="create a local 256-bit signing key")
    init.add_argument("--key-file", type=Path, default=DEFAULT_KEY)
    show = commands.add_parser("show-key", help="print the signing key as hex (for ESP32)")
    show.add_argument("--key-file", type=Path, default=DEFAULT_KEY)
    sign = commands.add_parser("sign", help="sign records and write a new file")
    sign.add_argument("input", type=Path)
    sign.add_argument("-o", "--output", type=Path, required=True)
    sign.add_argument("--key-file", type=Path, default=DEFAULT_KEY)
    verify = commands.add_parser("verify", help="verify record tags and sequence order")
    verify.add_argument("input", type=Path)
    verify.add_argument("--key-file", type=Path, default=DEFAULT_KEY)
    commands.add_parser("audit-history", help="display the persistent verification audit log history")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "init-key":
            create_key(args.key_file)
            return 0
        if args.command == "show-key":
            key = load_key(args.key_file)
            hex_key = key.hex()
            print(f"Hex key for ESP32 Serial:  KEY {hex_key}")
            return 0
        if args.command == "audit-history":
            show_audit_history()
            return 0
        key = load_key(args.key_file)
        if args.command == "sign":
            sign_file(args.input, args.output, key)
            return 0
        return 0 if verify_file(args.input, key) else 1
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
