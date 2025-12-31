# LogRadar

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Features](#features) | [Quick Start](#quick-start) | [Log Formats](#log-formats) | [Configuration](#configuration) | [Hot Reload](#hot-reload) | [Deployment](#docker-deployment) | [Troubleshooting](#troubleshooting)

---

## Overview

LogRadar is a high-performance, real-time threat detection system designed for HTTP access logs. It monitors log files, detects attack patterns using multi-layered analysis, and displays results through an interactive terminal interface or JSON output.

**Key Capabilities:**

- 50,000+ lines/second throughput on commodity hardware
- Sub-millisecond detection latency
- Zero-downtime configuration hot-reload
- Memory-efficient for 24/7 operation

---

## Features

| Detection Layer | Capabilities |
| --------------- | ------------ |
| Signature Analysis | SQLi (tokenization-based), XSS, Path Traversal, RCE, LFI |
| Behavioral Analysis | Brute Force, Rate Limiting, Bot Detection, UA Anomalies |
| Threat Intelligence | IP reputation, malicious IP correlation |
| Deep Inspection | POST body analysis, Header injection (Log4Shell), Cookie manipulation |

---

## Quick Start

### Prerequisites

- Go 1.23+
- Docker (optional)

### Installation

```bash
git clone https://github.com/xoelrdgz/logradar.git
cd logradar
make build
```

### Demo Mode

Test LogRadar with synthetic attack traffic:

```bash
# Interactive TUI with 10K events/sec
./bin/logradar analyze --demo --demo-rate 10000

# Console mode (no TUI)
./bin/logradar analyze --demo --demo-rate 5000 --no-tui

# JSON output
./bin/logradar analyze --demo --json
```

### Real Mode

Monitor actual log files:

```bash
# Tail nginx access log (real-time)
./bin/logradar analyze --log /var/log/nginx/access.log

# Analyze from beginning of file
./bin/logradar analyze --log /var/log/apache2/access.log --full

# Custom worker count
./bin/logradar analyze --log /var/log/nginx/access.log --workers 32
```

---

## Log Formats

LogRadar supports two log formats: Combined Log Format (CLF) and JSON.

### Combined Log Format (Apache/Nginx default)

```text
192.168.1.100 - - [31/Dec/2024:10:15:30 +0000] "GET /api/users?id=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

Nginx config:

```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

### JSON Format (Recommended for full visibility)

JSON format enables deep inspection of POST bodies, headers, and cookies.

```json
{
  "timestamp": "2024-12-31T10:15:30Z",
  "remote_addr": "192.168.1.100",
  "request_method": "POST",
  "request_uri": "/api/login",
  "status": 401,
  "body_bytes_sent": 45,
  "http_user_agent": "Mozilla/5.0",
  "request_body": "username=admin&password=' OR '1'='1",
  "http_headers": {
    "X-Forwarded-For": "10.0.0.1",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "http_cookie": "session=abc123; tracking=xyz"
}
```

Nginx JSON config:

```nginx
log_format json_combined escape=json '{'
  '"timestamp":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"request_method":"$request_method",'
  '"request_uri":"$request_uri",'
  '"status":$status,'
  '"body_bytes_sent":$body_bytes_sent,'
  '"http_user_agent":"$http_user_agent",'
  '"request_body":"$request_body",'
  '"http_cookie":"$http_cookie"'
'}';
```

---

## Alert Output

When a threat is detected, LogRadar generates alerts in the following format:

```json
{
  "id": "20241231101530-1-a1b2c3d4",
  "timestamp": "2024-12-31T10:15:30Z",
  "source_ip": "192.168.1.100",
  "threat_type": "SQL_INJECTION",
  "level": "CRITICAL",
  "risk_score": 9,
  "message": "SQL Injection - OR 1=1",
  "raw_log": "192.168.1.100 - - [31/Dec/2024:10:15:30 +0000] \"GET /api/users?id=1'+OR+'1'='1 HTTP/1.1\" 200 1234",
  "metadata": {
    "detector": "signature",
    "pattern": "(?i)(\\bor\\b\\s+\\d+\\s*=\\s*\\d+)"
  }
}
```

### Alert Levels

| Level | Risk Score | Description |
| ----- | ---------- | ----------- |
| CRITICAL | 8-10 | Active exploitation attempt, immediate action required |
| WARNING | 5-7 | Suspicious activity, investigation recommended |
| INFO | 1-4 | Reconnaissance or low-confidence detection |

### Threat Types

- `SQL_INJECTION` - SQL injection attempts
- `XSS` - Cross-site scripting
- `PATH_TRAVERSAL` - Directory traversal attacks
- `RCE` - Remote code execution
- `LFI` - Local file inclusion
- `LOG4SHELL` - Log4j JNDI injection
- `BRUTE_FORCE` - Authentication brute force
- `RATE_LIMIT_DOS` - Layer 7 DoS via rate abuse
- `BOT_DETECTION` - Automated scanner/bot behavior
- `MALICIOUS_IP` - Known malicious IP address

---

## Configuration

### Config File Location

LogRadar searches for configuration in this order:

1. `--config /path/to/config.yaml` (CLI flag)
2. `./configs/config.yaml` (local)
3. `/etc/logradar/config.yaml` (system-wide)

### Full Configuration Reference

```yaml
log:
  path: "/var/log/nginx/access.log"
  format: "auto"  # auto, combined, json

workers:
  count: 32           # Match CPU cores
  buffer_size: 100000 # Queue size for bursty traffic

detection:
  signatures:
    enabled: true
  behavioral:
    enabled: true
    brute_force:
      threshold: 10     # Failed attempts before alert
      window_seconds: 60
      status_code: 401  # HTTP status indicating failure
    rate_limit:
      threshold: 200    # Requests per IP
      window_seconds: 10

threat_intel:
  enabled: true
  malicious_ips_file: "/etc/logradar/malicious_ips.txt"
  bloom_filter_size: 100000
  bloom_false_positive_rate: 0.01

output:
  json:
    enabled: true
    path: "/var/log/logradar/alerts.json"
  metrics:
    enabled: true
    port: ":9090"

logging:
  level: "info"       # debug, info, warn, error
  format: "json"      # json, console
```

### Environment Variables

All config values can be overridden with `LOGRADAR_` prefix:

```bash
export LOGRADAR_LOG_PATH=/var/log/nginx/access.log
export LOGRADAR_WORKERS_COUNT=64
export LOGRADAR_DETECTION_BEHAVIORAL_BRUTE_FORCE_THRESHOLD=5
```

---

## Hot Reload

LogRadar supports zero-downtime configuration changes. Edit the config file while LogRadar is running and changes are applied automatically.

### What Can Be Hot-Reloaded

- Detection thresholds (brute force, rate limit)
- Threat intelligence file path
- Signature patterns
- Behavioral analysis settings

### What Requires Restart

- Log file path
- Worker count
- Buffer size
- Output paths

### How It Works

1. LogRadar watches the config file using filesystem notifications
2. On change, the new config is validated
3. If valid, new detector instances are created
4. Atomic pointer swap replaces old detectors
5. Old detectors drain for 2 seconds, then stop
6. No requests are dropped during reload

### Manual Reload

Send SIGHUP to trigger manual reload:

```bash
kill -HUP $(pidof logradar)
```

---

## Docker Deployment

### Quick Run

```bash
# Demo mode
docker run --rm -it ghcr.io/xoelrdgz/logradar:latest

# With real log file
docker run --rm -it \
  -v /var/log/nginx:/logs:ro \
  ghcr.io/xoelrdgz/logradar:latest \
  analyze --log /logs/access.log --no-tui
```

### Docker Compose

```yaml
version: '3.8'
services:
  logradar:
    image: ghcr.io/xoelrdgz/logradar:latest
    restart: unless-stopped
    volumes:
      - /var/log/nginx:/logs:ro
      - ./config.yaml:/etc/logradar/config.yaml:ro
      - ./alerts:/var/log/logradar
    ports:
      - "9090:9090"
    command: ["analyze", "--log", "/logs/access.log", "--no-tui"]
```

---

## Metrics and Monitoring

### Prometheus Endpoint

Metrics available at `http://localhost:9090/metrics`:

```text
logradar_lines_total
logradar_lines_per_second
logradar_alerts_total
logradar_alerts_by_type{type="SQL_INJECTION"}
logradar_alerts_by_level{level="CRITICAL"}
logradar_detection_latency_seconds
logradar_queue_utilization
logradar_memory_bytes
```

### Grafana Dashboard

Import the provided dashboard: `./configs/grafana-dashboard.json`

---

## CLI Reference

```text
logradar analyze [flags]

Flags:
  -l, --log string      Log file path to analyze
      --demo            Demo mode with synthetic traffic
      --demo-rate int   Events per second in demo mode (default 1000)
      --full            Analyze entire file from beginning
  -w, --workers int     Number of worker goroutines (default 16)
      --no-tui          Disable TUI, output to stdout
      --json            Output alerts as JSON
      --config string   Config file path

Examples:
  logradar analyze --log /var/log/nginx/access.log
  logradar analyze --demo --demo-rate 50000
  logradar analyze --log ./access.log --full --json
```

---

## Troubleshooting

### No Alerts Generated

1. Verify log format matches config (`auto` tries both formats)
2. Check log file path is accessible
3. Run with `--log-level debug` to see parsing results
4. Test with `--demo` mode to verify detection works

### High Memory Usage

1. Reduce `workers.buffer_size` in config
2. Check if threat intel file is unexpectedly large
3. Limit tracked IPs via behavioral config

### TUI Not Displaying

1. Ensure terminal supports 256 colors
2. Try `--no-tui` for console output
3. Check if stdout is a TTY (`[ -t 1 ]`)

### Slow Performance

1. Increase worker count to match CPU cores
2. Use JSON log format for structured parsing
3. Check disk I/O for log file access
4. Profile with `LOGRADAR_LOG_LEVEL=debug`

### False Positives

1. Adjust detection thresholds in config
2. Check if legitimate traffic matches attack patterns
3. Use `AlertLevelWarning` threshold for investigation
4. Review specific detector tuning in config

### Hot Reload Not Working

1. Verify config file is valid YAML (`yq . config.yaml`)
2. Check file permissions
3. Run with debug logging to see reload events
4. Ensure filesystem notifications are supported (not NFS)

---

## Development

### Make Targets

```bash
make build          # Build binary
make test           # Run tests
make bench          # Run benchmarks
make lint           # Run linter
make fuzz           # Run fuzz tests
```

### Project Structure

```text
cmd/logradar/       # CLI entrypoint
internal/
  adapters/
    detection/      # Detection engines
    input/          # Log parsers
    output/         # Alerters
  app/              # Core application
  domain/           # Domain models
  ports/            # Interface definitions
  tui/              # Terminal UI
pkg/                # Reusable packages
configs/            # Configuration files
testdata/           # Test fixtures
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
