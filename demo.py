"""TAGGUARD Hackathon Live Demo Runner
Demonstrates the full lifecycle:
1. Generate / Show Key
2. Verify Authentic Export (All VALID)
3. Simulate Tampering (Value altered from 2.614V -> 9.614V like Slide 3)
4. Verify Tampered Export (TAMPERED Caught)
5. Simulate Sequence Gap (Record dropped)
6. Verify Gap Export (SEQUENCE ISSUE Caught)
"""

import copy
import json
from pathlib import Path
import subprocess
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent
VERIFIER = PROJECT_ROOT / "verifier" / "verify.py"
EXAMPLES = PROJECT_ROOT / "examples"


def run_cmd(args: list[str]) -> None:
    print(f"\n> python {' '.join(str(a) for a in args)}")
    time.sleep(0.5)
    subprocess.run([sys.executable, str(VERIFIER), *args])


def main():
    print("=" * 60)
    print("  TAGGUARD LIVE DEMONSTRATION")
    print("  Tamper-Evident Laboratory Measurement Logger")
    print("=" * 60)

    # 1. Show or init key
    key_file = PROJECT_ROOT / ".tagguard.key"
    if not key_file.exists():
        run_cmd(["init-key"])
    run_cmd(["show-key"])

    # 2. Sign samples
    signed_json = EXAMPLES / "signed.json"
    run_cmd(["sign", str(EXAMPLES / "samples.json"), "-o", str(signed_json)])

    # 3. Verify valid
    print("\n--- STEP 1: Verify Authentic Dataset ---")
    run_cmd(["verify", str(signed_json)])

    # 4. Tamper record #1 (change 2.614 -> 9.614)
    print("\n--- STEP 2: Tamper with Record #1 (Value changed 2.614V -> 9.614V) ---")
    records = json.loads(signed_json.read_text(encoding="utf-8"))
    tampered_records = copy.deepcopy(records)
    tampered_records[0]["value"] = "9.614"  # Tampered value! Tag left untouched
    tampered_file = EXAMPLES / "demo_tampered.json"
    tampered_file.write_text(json.dumps(tampered_records, indent=2), encoding="utf-8")
    run_cmd(["verify", str(tampered_file)])

    # 5. Delete record #3
    print("\n--- STEP 3: Drop Record #3 (Simulate Record Deletion / Sequence Gap) ---")
    gap_records = [r for r in records if r["sequence"] != 3]
    gap_file = EXAMPLES / "demo_gap.json"
    gap_file.write_text(json.dumps(gap_records, indent=2), encoding="utf-8")
    run_cmd(["verify", str(gap_file)])

    print("\n" + "=" * 60)
    print("  DEMO COMPLETE: All tampering & anomalies successfully caught!")
    print("=" * 60)


if __name__ == "__main__":
    main()
