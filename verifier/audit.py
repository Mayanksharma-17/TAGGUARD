"""Audit Trail & Tamper Incident Reporting Engine for TAGGUARD."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

AUDIT_DIR = Path(__file__).resolve().parent.parent / "audit_logs"


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TamperIncident:
    incident_id: str
    record_sequence: int
    source: str
    observed_value: str
    unit: str
    capture_timestamp: str
    provided_tag: str
    recalculated_tag: str
    detection_timestamp: str
    reason: str
    severity: str = "CRITICAL"


@dataclass
class VerificationAuditEvent:
    event_id: str
    timestamp: str
    verified_file: str
    total_records: int
    valid_count: int
    tampered_count: int
    sequence_issue_count: int
    overall_status: str  # "CLEAN", "TAMPERED_DETECTED", "SEQUENCE_ANOMALY"
    incidents: list[TamperIncident] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


class AuditLogger:
    def __init__(self, log_dir: Path = AUDIT_DIR):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path = self.log_dir / "audit_trail.jsonl"
        self.incident_dir = self.log_dir / "incidents"
        self.incident_dir.mkdir(parents=True, exist_ok=True)

    def log_event(self, event: VerificationAuditEvent) -> Path:
        """Appends verification event to the persistent JSONL audit trail."""
        line = json.dumps(event.to_dict(), ensure_ascii=False)
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

        # If incidents occurred, generate standalone forensic incident report markdown
        if event.incidents:
            return self._generate_markdown_report(event)
        return self.audit_log_path

    def _generate_markdown_report(self, event: VerificationAuditEvent) -> Path:
        report_path = self.incident_dir / f"INCIDENT_{event.event_id}.md"
        lines = [
            f"# 🚨 FORENSIC TAMPER INCIDENT REPORT: {event.event_id}",
            f"**Generated at:** {event.timestamp}  ",
            f"**Inspected Source:** `{event.verified_file}`  ",
            f"**Verdict:** <span style='color:red;'>**{event.overall_status}**</span>  ",
            "",
            "## 📊 Summary",
            f"- **Total Inspected Records:** {event.total_records}",
            f"- **Valid Records:** {event.valid_count}",
            f"- **Tampered Records:** {event.tampered_count}",
            f"- **Sequence Anomalies:** {event.sequence_issue_count}",
            "",
            "## 🔍 Incident Breakdown",
        ]

        for inc in event.incidents:
            lines.extend([
                f"### Record #{inc.record_sequence:03d} — Violation Detected",
                f"- **Sensor Source:** `{inc.source}`",
                f"- **Observed Value in File:** `{inc.observed_value} {inc.unit}`",
                f"- **Original Capture Timestamp:** `{inc.capture_timestamp}`",
                f"- **Detection Timestamp:** `{inc.detection_timestamp}`",
                f"- **Failure Reason:** {inc.reason}",
                f"- **Provided Integrity Tag:** `{inc.provided_tag}`",
                f"- **Recalculated Tag:** `{inc.recalculated_tag}`",
                "",
                "> ⚠️ **Cryptographic Proof of Modification:**  ",
                f"> The SHA-256 digest over the canonical payload does not match the tag emitted at physical capture time.",
                ""
            ])

        lines.extend([
            "---",
            "*Report generated automatically by TAGGUARD Forensic Audit Engine.*"
        ])

        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path

    def get_history(self) -> list[dict[str, Any]]:
        """Reads all past verification audit events."""
        if not self.audit_log_path.exists():
            return []
        events = []
        with self.audit_log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
        return events
