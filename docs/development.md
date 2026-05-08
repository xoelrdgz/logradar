# Development

## Checks

```bash
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
go test -race ./...
go test -run=^$ -fuzz=Fuzz -fuzztime=10s ./internal/adapters/input
go test -run=^$ -fuzz=Fuzz -fuzztime=10s ./internal/adapters/detection
```

## Useful Targets

```bash
make build
make test
make lint
make fuzz
make vulncheck
make sbom
make docker
```

`make lint` runs `golangci-lint` when installed.

## Docker Smoke Test

```bash
docker build -t logradar:local .
docker run --rm -d --name logradar-smoke -p 19090:9090 logradar:local analyze --demo --demo-rate 10 --no-tui
curl -fsS http://127.0.0.1:19090/ready
docker stop logradar-smoke
```

## Release Notes

- Generate an SBOM with `make sbom`.
- Keep alert schema changes documented in `docs/alert-schema.md`.
- Multi-arch image publishing is not enabled in this repository yet; keep normal `linux/amd64` builds unless a release workflow is added.

