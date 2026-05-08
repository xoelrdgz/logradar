# Detection

LogRadar emits active alerts from the supported detectors: signatures, behavioral signals and threat intelligence.

## Alert Fields

Detections can enrich alerts with:

- `rule_id`: stable rule or signal identifier.
- `rule_version`: rule version string.
- `confidence`: detector confidence from `0.0` to `1.0`.
- `evidence.field`: analyzed field that matched.
- `evidence.fragment`: bounded matching fragment, redacted by JSON output when `output.json.redact_sensitive=true`.

Truncation policy:

- `raw_log` is truncated to the domain maximum line length before alert creation.
- `evidence.fragment` is capped to 256 bytes.
- JSON output can reject oversized encoded alerts with `output.json.max_alert_bytes`.
- JSON output redacts sensitive values from `raw_log`, `evidence.fragment` and metadata when `output.json.redact_sensitive=true`.

## Signature Rules

External rules live in a versioned YAML file:

```yaml
version: "1"
rules:
  - id: example-rce
    version: "1"
    name: Example RCE Marker
    pattern: "(?i)example_exec"
    threat_type: RCE
    level: CRITICAL
    risk_score: 10
    confidence: 0.95
    audit: false
    keywords:
      - example_exec
    requires_query_string: false
```

Use `audit: true` to evaluate a rule without emitting active alerts. Audit detections are counted as audit processing results but do not increment emitted alert counters.

## Experimental Detectors

`SQLTokenizerDetector` and `UAEntropyDetector` are internal/experimental components. They are not part of the supported runtime until they have config flags, tests, documentation and operational defaults.

## Threat Intelligence Feeds

The supported runtime loads local files at startup. Prometheus exposes loaded entries, last reload timestamp and feed load errors.

Signed feed verification and incremental remote updates are intentionally out of scope while LogRadar only accepts local feed files. Revisit both together if remote or third-party managed feeds are added.
