package api

import (
	"context"
)

type DefaultProxyKey string
type IDoNotKnowWhatToDoKey string

type DefaultGenericOrUnAuthenticatedDAVRequest string
type DefaultUserNotFound string
type DefaultProjectNotFound string
type DefaultNonDAVRequest string

type RedisKeyType string

const (
	REDIS_KEY_DEFAULT_GENERIC_OR_UNAUTHENTICATED_DAV_REQUEST = "default-generic-or-unauthenticated-dav-request"
	REDIS_KEY_DEFAULT_USER_NOT_FOUND                         = "default-user-not-found"
	REDIS_KEY_DEFAULT_PROJECT_NOT_FOUND                      = "default-project-not-found"
	REDIS_KEY_DEFAULT_NON_DAV_REQUEST                        = "default-non-dav-request"

	MIGRATED    = "migrated"
	NOTMIGRATED = "not-migrated"

	DefaultGenericOrUnAuthenticatedDAVRequestOldProxy = "old-proxy"
	DefaultGenericOrUnAuthenticatedDAVRequestNewProxy = "new-proxy"

	DefaultUserNotFoundOldProxy = "old-proxy"
	DefaultUserNotFoundNewProxy = "new-proxy"

	DefaultProjectNotFoundOldProxy = "old-proxy"
	DefaultProjectNotFoundNewProxy = "new-proxy"

	DefaultNonDAVRequestOldProxy = "old-proxy"
	DefaultNonDAVRequestNewProxy = "new-proxy"

	RedisKeyUser    RedisKeyType = "user"
	RedisKeyProject RedisKeyType = "project"
)

type Migrator interface {
	IsKeyMigrated(ctx context.Context, key string) (bool, bool)
	GetDefaultGenericOrUnAuthenticatedDAVRequest(ctx context.Context) DefaultGenericOrUnAuthenticatedDAVRequest
	GetDefaultUserNotFound(ctx context.Context) DefaultUserNotFound
	GetDefaultProjectNotFound(ctx context.Context) DefaultProjectNotFound
	GetDefaultNonDAVRequest(ctx context.Context) DefaultNonDAVRequest
}
