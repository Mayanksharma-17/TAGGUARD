# TAGGUARD

[![Skylos Grade](https://img.shields.io/badge/Skylos-A%2B%20%28100%29-brightgreen)](https://github.com/duriantaco/skylos)
![Dead Code Free](https://img.shields.io/badge/Dead_Code-Free-brightgreen?logo=moleculer&logoColor=white)

Offline Python software for signing and verifying tamper-evident laboratory measurement exports with HMAC-SHA256. Python 3.10+; no third-party packages required.

## Run it

Run these commands from the project root:

```sh
python verifier/verify.py init-key
python verifier/verify.py sign examples/samples.json --output examples/signed.json
python verifier/verify.py verify examples/signed.json
```

The verifier prints `VALID` for each matching record. Change a signed field in a copy of the export and verify it again to see the tamper warning. Sequence gaps and duplicates are also reported.

Input and output format are selected by file extension: `.json` or `.csv`. Example CSV header:

```csv
sequence,source,value,unit,timestamp,tag
1,POT_SENSOR,2.614,V,2026-10-12T09:00:00Z,
```

The signing key is generated locally at `.tagguard.key`. Never commit or share it. HMAC verification requires the same secret key as signing, so this prototype supports verification by a trusted party who has that key; anyone with the key can also create valid tags. `init-key` refuses to overwrite an existing key.

See [docs/record-format.md](docs/record-format.md) for the exact schema and canonicalization rules. This software validates integrity and sequence order; it cannot prove sensor calibration or truthful manual input. Device firmware and sensor acquisition are not included yet.
