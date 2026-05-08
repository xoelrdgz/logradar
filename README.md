# LogRadar

LogRadar analyzes HTTP access logs and emits alerts for patterns such as SQLi, XSS, path traversal, RCE, LFI, Log4Shell, brute force attempts, rate-limit abuse, and malicious IPs loaded from local files.

![TUI](assets/ss1.png)

## Quick Start

```bash
make build
./bin/logradar analyze --demo --demo-rate 1000
./bin/logradar analyze --log /var/log/nginx/access.log --no-tui
journalctl -u nginx -o cat | ./bin/logradar analyze --stdin --no-tui
./bin/logradar analyze --log ./access.log --batch --json
```

`--batch` exits at EOF and returns code `2` when active alerts were emitted.

## Formats

- `combined`: IP, method, path, status, bytes, and User-Agent.
- `json`: includes headers, cookies, and body.
- `auto`: tries JSON first and falls back to combined.

See [docs/log-formats.md](docs/log-formats.md).

## Configuration

LogRadar looks for configuration in:

1. `--config /path/config.yaml`
2. `./configs/config.yaml`
3. `/etc/logradar/config.yaml`

`LOGRADAR_*` environment variables can override configuration keys. See [docs/configuration.md](docs/configuration.md).

## Outputs

- Interactive TUI by default.
- JSON Lines with `--json` or `output.json.enabled=true`.
- Prometheus metrics on `/metrics`, readiness on `/ready`, and liveness on `/live`.

![IPs](assets/ss2.png) ![Alert detail](assets/ss3.png)

The alert schema is documented in [docs/alert-schema.md](docs/alert-schema.md).

## Docker

```bash
docker compose --profile demo up --build
LOGRADAR_LOG_FILE=/var/log/nginx/access.log docker compose --profile file up --build
docker compose --profile demo --profile monitoring up --build
```

Grafana is not part of the maintained deployment. The maintained monitoring path is Prometheus. See [docs/monitoring.md](docs/monitoring.md).

## Documentation

- [Configuration](docs/configuration.md)
- [Log formats](docs/log-formats.md)
- [Detection](docs/detection.md)
- [Monitoring](docs/monitoring.md)
- [Deployment](docs/deployment.md)
- [Runbook](docs/runbook.md)
- [Development](docs/development.md)

## Development

```bash
make test
make lint
make fuzz
make docker
```

## License

GPL-3.0-only. See [LICENSE](LICENSE).
