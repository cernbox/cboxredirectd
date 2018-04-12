package api

import (
	"context"
)

type Migrator interface {
	IsUserMigrated(ctx context.Context, username string) (bool, error)
	MigrateUser(ctx context.Context, username string) error
}
