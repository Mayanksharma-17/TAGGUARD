# TAGGUARD record format

A JSON export is a list of measurement objects. CSV uses one record per row and the same six column names.

| Field | Type | Rule |
|---|---|---|
| `sequence` | positive integer | Starts at 1 and increases by one per captured record. |
| `source` | string | Sensor/input identifier, such as `POT_SENSOR`. |
| `value` | decimal string | Keep the exact decimal spelling, such as `2.614`. |
| `unit` | string | Measurement unit, such as `V`. |
| `timestamp` | string | UTC ISO 8601, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`. |
| `tag` | string | Lowercase 64-character hex HMAC-SHA256; blank before signing. |

The tag covers `sequence`, `source`, `value`, `unit`, and `timestamp`; it does not cover itself. These fields are encoded as UTF-8 JSON with sorted keys, no spaces between separators, and no ASCII escaping. Both the signer and verifier must use these exact rules.

Sequence anomalies are reported separately from the HMAC result. A correct HMAC shows that signed fields match the tag; it does not prove sensor calibration, truthful input, or that no records were deleted before signing.
