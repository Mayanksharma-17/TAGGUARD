# TAGGUARD record format

A JSON export is a list of measurement objects. CSV uses one record per row and matching column names.

## Schema Specifications

### Format v2 (Hash-Chained Edge Ledger — Current)

| Field | Type | Rule |
|---|---|---|
| `sequence` | positive integer | Starts at 1 and increases monotonically by one per record. |
| `source` | string | Sensor identifier, e.g. `POT_SENSOR`. |
| `value` | decimal string | Exact measurement, e.g. `2.614`. |
| `unit` | string | Measurement unit, e.g. `V`. |
| `timestamp` | string | UTC ISO 8601, `YYYY-MM-DDTHH:MM:SSZ`. |
| `prev_tag` | string | Lowercase 64-character hex tag of previous record; `0000...0000` (64 zeros) for genesis (record #1). |
| `tag` | string | Lowercase 64-character hex HMAC-SHA256 digest over the canonical payload. |

The tag covers `prev_tag`, `sequence`, `source`, `timestamp`, `unit`, and `value` (sorted alphabetically).

### Format v1 (Legacy Isolated HMAC)
Legacy format without `prev_tag`. Supported seamlessly by `verify.py` and `dashboard.html` for backward compatibility.

## Canonicalization Rules

Payload fields are serialized as UTF-8 JSON with:
- Alphabetically sorted keys
- Compact separators (`","` and `":"`, zero whitespace)
- No ASCII escaping (`ensure_ascii=False`)

## Cascade Tamper Proof
In Format v2, if an attacker alters Record $N$, its recalculated tag changes. Because Record $N+1$ binds Record $N$'s tag inside its own signature, the chain continuity breaks immediately at Record $N+1$ (`CHAIN BREAK`), producing a cascading failure downstream.

