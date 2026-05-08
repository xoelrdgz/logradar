# Benchmarks

## Methodology

Benchmark results should always include:

- Git commit and build flags.
- CPU model, core count and memory.
- Go version.
- Log format: `combined`, `json` or `auto`.
- Detector configuration.
- Worker count and buffer size.
- Whether JSON output, deduplication, Prometheus and checkpointing were enabled.
- Input type: demo generator, file replay or live tail.

## Commands

Go microbenchmarks:

```bash
go test -bench=. -benchmem -run=^$ ./...
```

Race-safe correctness check:

```bash
go test -race ./...
```

Demo throughput smoke test:

```bash
make build-prod
./bin/logradar analyze --demo --demo-rate 185000 --workers 12 --no-tui --json
```

Observed demo throughput: about 185k events/s with 12 workers.

File replay:

```bash
./bin/logradar analyze --log ./access.log --full --no-tui --json
```

## Reporting Template

```text
Commit:
Go:
CPU:
Memory:
Command:
Log format:
Workers:
Output:
Metrics:
Throughput:
P50/P90/P99 processing latency:
Parser errors:
Alerts generated:
Notes:
```
