"""
Create a v2 hash-chained sample dataset and test cascade failure on tamper.
"""
import hashlib
import hmac
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "verifier"))
import verify

KEY = Path(__file__).parent.parent / ".tagguard.key"
OUT_CLEAN   = Path(__file__).parent.parent / "examples" / "signed_chained.json"
OUT_TAMPERED = Path(__file__).parent.parent / "examples" / "tampered_chained.json"

GENESIS = "0" * 64

raw_records = [
    {"sequence": 1, "source": "POT_SENSOR", "value": "2.614", "unit": "V",
     "timestamp": "2026-10-14T09:00:00Z"},
    {"sequence": 2, "source": "POT_SENSOR", "value": "1.203", "unit": "V",
     "timestamp": "2026-10-14T09:00:15Z"},
    {"sequence": 3, "source": "POT_SENSOR", "value": "0.487", "unit": "V",
     "timestamp": "2026-10-14T09:00:30Z"},
    {"sequence": 4, "source": "POT_SENSOR", "value": "3.156", "unit": "V",
     "timestamp": "2026-10-14T09:00:45Z"},
    {"sequence": 5, "source": "POT_SENSOR", "value": "1.850", "unit": "V",
     "timestamp": "2026-10-14T09:01:00Z"},
]

key_bytes = KEY.read_bytes()
prev_tag = GENESIS
signed = []

for r in raw_records:
    rec = verify.Record(
        sequence=r["sequence"],
        source=r["source"],
        value=r["value"],
        unit=r["unit"],
        timestamp=r["timestamp"],
        prev_tag=prev_tag,
    )
    rec.tag = verify.make_tag(rec, key_bytes)
    prev_tag = rec.tag
    signed.append(rec.as_dict())

OUT_CLEAN.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
print(f"Written: {OUT_CLEAN}")

# Create a tampered version: change record #1 value but leave tag intact
import copy
tampered = copy.deepcopy(signed)
tampered[0]["value"] = "9.614"   # altered value — tag no longer matches
OUT_TAMPERED.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
print(f"Written: {OUT_TAMPERED}")
print("\nDone. Now run:\n  python verifier/verify.py verify examples/signed_chained.json")
print("  python verifier/verify.py verify examples/tampered_chained.json")
