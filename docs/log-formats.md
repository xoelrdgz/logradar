# Log Formats

## Combined

Use `log.format=combined` for Apache/Nginx combined access logs:

```text
192.0.2.10 - - [01/Jan/2026:00:00:00 +0000] "GET /search?q=test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

Available detection fields: IP, method, path, status code, bytes sent and User-Agent.

## JSON

Use `log.format=json` for structured logs. JSON is recommended when LogRadar should inspect headers, cookies or request body.

```json
{
  "timestamp": "2026-01-01T00:00:00Z",
  "remote_addr": "192.0.2.10",
  "request_method": "POST",
  "request_uri": "/login",
  "status": 401,
  "body_bytes_sent": 45,
  "http_user_agent": "Mozilla/5.0",
  "request_body": "username=admin",
  "http_headers": {
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "http_cookie": "session=abc123"
}
```

## Auto

Use `log.format=auto` when a source may contain both combined and JSON lines. Auto detection tries JSON first and falls back to combined parsing.

## Finite Input

`--stdin` reads from standard input until EOF. `--batch` processes a finite file and exits when done. Batch mode returns exit code `2` when active alerts are emitted, which makes it useful for CI or offline checks.

