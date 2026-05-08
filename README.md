# LogRadar

LogRadar analiza logs HTTP y emite alertas para patrones como SQLi, XSS, path traversal, RCE, LFI, Log4Shell, fuerza bruta, abuso de rate limit e IPs maliciosas cargadas desde ficheros locales.

## Uso Rapido

```bash
make build
./bin/logradar analyze --demo --demo-rate 1000
./bin/logradar analyze --log /var/log/nginx/access.log --no-tui
journalctl -u nginx -o cat | ./bin/logradar analyze --stdin --no-tui
./bin/logradar analyze --log ./access.log --batch --json
```

`--batch` termina al llegar a EOF y devuelve codigo `2` si se emitieron alertas activas.

## Formatos

- `combined`: IP, metodo, path, status, bytes y User-Agent.
- `json`: anade headers, cookies y body.
- `auto`: intenta JSON y cae a combined.

Ver [docs/log-formats.md](docs/log-formats.md).

## Configuracion

LogRadar busca configuracion en:

1. `--config /path/config.yaml`
2. `./configs/config.yaml`
3. `/etc/logradar/config.yaml`

Las variables `LOGRADAR_*` pueden sobrescribir claves de configuracion. Ver [docs/configuration.md](docs/configuration.md).

## Salidas

- TUI interactiva por defecto.
- JSON Lines con `--json` o `output.json.enabled=true`.
- Prometheus en `/metrics`, readiness en `/ready` y liveness en `/live`.

El esquema de alerta esta en [docs/alert-schema.md](docs/alert-schema.md).

## Docker

```bash
docker compose --profile demo up --build
LOGRADAR_LOG_FILE=/var/log/nginx/access.log docker compose --profile file up --build
docker compose --profile demo --profile monitoring up --build
```

Grafana no forma parte del despliegue mantenido. La monitorizacion mantenida es Prometheus. Ver [docs/monitoring.md](docs/monitoring.md).

## Documentacion

- [Configuracion](docs/configuration.md)
- [Formatos de log](docs/log-formats.md)
- [Deteccion](docs/detection.md)
- [Monitorizacion](docs/monitoring.md)
- [Despliegue](docs/deployment.md)
- [Runbook](docs/runbook.md)
- [Desarrollo](docs/development.md)

## Desarrollo

```bash
make test
make lint
make fuzz
make docker
```

## Licencia

GPL-3.0-only. Ver [LICENSE](LICENSE).
