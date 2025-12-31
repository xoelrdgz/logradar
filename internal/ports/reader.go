package ports

import (
	"context"

	"github.com/xoelrdgz/logradar/internal/domain"
)

type LogReader interface {
	Start(ctx context.Context) (<-chan *domain.LogEntry, <-chan error)
	Stop() error
}

type LogParser interface {
	Parse(line string) (*domain.LogEntry, error)
	Format() string
}
