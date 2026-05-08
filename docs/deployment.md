# Deployment

## Systemd Service

Create a dedicated user and directories:

```bash
sudo useradd --system --home /var/lib/logradar --shell /usr/sbin/nologin logradar
sudo install -d -o logradar -g logradar -m 0750 /var/lib/logradar /var/log/logradar /etc/logradar
sudo install -m 0755 bin/logradar /usr/local/bin/logradar
sudo install -m 0640 configs/config.production.yaml /etc/logradar/config.yaml
```

Example unit:

```ini
[Unit]
Description=LogRadar HTTP log threat detector
Documentation=https://github.com/xoelrdgz/logradar
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=logradar
Group=logradar
ExecStart=/usr/local/bin/logradar analyze --config /etc/logradar/config.yaml --no-tui
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/logradar /var/lib/logradar
ReadOnlyPaths=/var/log/nginx /etc/logradar
Environment=LOGRADAR_LOG_PATH=/var/log/nginx/access.log

[Install]
WantedBy=multi-user.target
```

Install and start:

```bash
sudo install -m 0644 logradar.service /etc/systemd/system/logradar.service
sudo systemctl daemon-reload
sudo systemctl enable --now logradar
sudo systemctl status logradar
```

## Production Notes

- Run with `--no-tui` under service managers.
- Keep `log.checkpoint.enabled=true` for long-running file tailing.
- Keep `output.json.redact_sensitive=true`.
- Keep `output.json.include_raw_log=false` when raw request logs may contain sensitive data.
- Keep `output.json.max_alert_bytes` bounded to avoid oversized alert payloads.
- Mount or grant read-only access to the input log directory.
- Keep alert, overflow, quarantine and checkpoint files under a writable LogRadar-owned directory.
- Prometheus is optional; expose `output.metrics.port` only on trusted networks.
