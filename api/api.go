package api

import (
	"context"
)

type Migrator interface {
	IsPathMigrated(ctx context.Context, path, username string) (bool, error)
}
