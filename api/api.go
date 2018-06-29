package api

import (
	"context"
)

type DefaultProxyKey string
type IDoNotKnowWhatToDoKey string

const (
	OldProxyKey DefaultProxyKey = "old-proxy"
	NewProxyKey DefaultProxyKey = "new-proxy"

	IDoNotKnowOldProxyKey IDoNotKnowWhatToDoKey = "old-proxy"
	IDoNotKnowNewProxyKey IDoNotKnowWhatToDoKey = "new-proxy"
	IDoNotKnowPanicKey    IDoNotKnowWhatToDoKey = "panic"
)

type Migrator interface {
	IsPathMigrated(ctx context.Context, path, username string) (bool, error)
	GetDefaultKey(ctx context.Context) (DefaultProxyKey, error)
	GetIDoNotKnowWhatToDoKey(ctx context.Context) (IDoNotKnowWhatToDoKey, error)
}
