# TAGGUARD Verifier CLI

The `verifier/verify.py` script provides an offline cryptographic utility to generate signing keys, sign laboratory measurement exports, and verify their cryptographic integrity using HMAC-SHA256.

## Requirements

- Python 3.10+
- Standard library only (no external pip dependencies needed)

## Commands

### 1. Initialize Signing Key
Generates a cryptographically secure 256-bit (32-byte) key and saves it to `.tagguard.key`:
```sh
python verifier/verify.py init-key
```

### 2. Show Key (for ESP32 Sync)
Prints the key formatted for copy-pasting directly into the ESP32 Serial Monitor:
```sh
python verifier/verify.py show-key
```
Output:
```text
Hex key for ESP32 Serial:  KEY b63b5f9184e53d13d021d9124d32b36a89f2834c3012cd0b2612616ab524197b
```

### 3. Sign Measurement Records
Signs raw/unsigned measurement records (JSON or CSV) and writes signed output:
```sh
python verifier/verify.py sign examples/samples.json --output examples/signed.json
python verifier/verify.py sign examples/samples.json --output examples/signed.csv
```

### 4. Verify Records (Integrity & Sequence)
Verifies record tags against recalculated HMAC-SHA256 and checks sequence consistency:
```sh
python verifier/verify.py verify examples/signed.json
python verifier/verify.py verify examples/signed.csv
```

## Report Output

The verifier produces a color-coded terminal report:
- `✓ VALID`: Record HMAC matches and sequence is in order.
- `✗ TAMPERED / INVALID TAG`: The record content (value, source, unit, timestamp) was modified.
- `⚠ SEQUENCE ISSUE`: Sequence number has a gap or duplicate.
