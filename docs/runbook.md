# Runbook

## Health Checks

- Readiness: `curl -fsS http://127.0.0.1:9090/ready`
- Liveness: `curl -fsS http://127.0.0.1:9090/live`
- Metrics: `curl -fsS http://127.0.0.1:9090/metrics`
- Service status: `systemctl status logradar`
- Recent logs: `journalctl -u logradar -n 100 --no-pager`

## Common Incidents

### No Alerts

1. Confirm the configured log path exists and is readable by the LogRadar user.
2. Confirm `log.format` matches the source format; use `auto` while investigating.
3. Confirm at least one detector is enabled.
4. Temporarily run demo mode to verify detectors and outputs.

### Parser Errors

1. Compare a raw log line against the documented Combined or JSON format.
2. Use JSON logs when headers, cookies or body inspection are required.
3. Check for truncated or multiline log entries from the upstream server.

### Pipeline Stalled

1. Check `/ready`; it returns `503` if the analyzer is not running.
2. Check `logradar:red:rate_1m` and parser error metrics in Prometheus.
3. Check file rotation behavior and whether the checkpoint points to an old file.
4. Restart the service if the input file was replaced unexpectedly.

### Too Many Alerts

1. Enable or tune `output.dedup`.
2. Add safe health checks, trusted scanners or internal CIDRs to `detection.allowlist`.
3. Review whether a rule is too broad before disabling a detector.

### Threat Intel Feed Problems

1. Validate each feed line: `ip[,source[,confidence[,category|category[,ttl_or_expiry]]]]`.
2. Check expiration values; expired entries are skipped at load time.
3. Use `threat_intel.feed_files` to merge multiple local feeds.
4. Restart LogRadar after feed changes; automatic remote feed fetching is intentionally out of scope.

### Sensitive Data In Alerts

1. Keep `output.json.redact_sensitive=true`.
2. Prefer JSON logs that separate headers, cookies and body fields.
3. Rotate any secret that was emitted before redaction was enabled.

## Recovery Actions

- Restart: `sudo systemctl restart logradar`
- Disable checkpoint for full replay: run once with `--full`, or set `log.checkpoint.enabled=false`.
- Reset checkpoint: stop LogRadar, remove the configured checkpoint file, then start LogRadar.
- Preserve overflow/quarantine files for incident review before deleting them.
