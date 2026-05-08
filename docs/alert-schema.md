# Alert Schema Changelog

## 1.0

Initial stable JSON alert schema.

Fields:

- `schema_version`
- `id`
- `timestamp`
- `source_ip`
- `threat_type`
- `level`
- `raw_log`
- `risk_score`
- `message`
- `rule_id`
- `rule_version`
- `confidence`
- `evidence`
- `metadata`

Compatibility notes:

- `raw_log` may be an empty string when `output.json.include_raw_log=false`.
- `evidence.fragment`, `metadata` and `raw_log` are subject to truncation/redaction policy before JSON output.
- Additive fields require golden JSON test updates and a changelog entry here.

