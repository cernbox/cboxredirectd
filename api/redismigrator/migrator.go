package redismigrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cernbox/cboxredirectd/api"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
)

type Options struct {
	Address            string
	PoolSize           int
	PoolTimeout        int
	IdleTimeout        int
	IdleCheckFrequency int
	DialTimeout        int
	ReadTimeout        int
	WriteTimeout       int
	MaxRetries         int
	Password           string
	Logger             *zap.Logger
}

func (opts *Options) init() {
	if opts.Address == "" {
		opts.Address = "localhost:6379"
	}
	if opts.Logger == nil {
		l, _ := zap.NewProduction()
		opts.Logger = l
	}
}

type migrator struct {
	client *redis.Client
	logger *zap.Logger
}

func New(opts *Options) (api.Migrator, error) {
	opts.init()
	redisOpts := &redis.Options{
		Network:            "tcp",
		Addr:               opts.Address,
		DialTimeout:        time.Duration(opts.DialTimeout) * time.Second,
		PoolSize:           opts.PoolSize,
		PoolTimeout:        time.Duration(opts.PoolTimeout) * time.Second,
		IdleTimeout:        time.Duration(opts.IdleTimeout) * time.Second,
		IdleCheckFrequency: time.Duration(opts.IdleCheckFrequency) * time.Second,
		ReadTimeout:        time.Duration(opts.ReadTimeout) * time.Second,
		WriteTimeout:       time.Duration(opts.WriteTimeout) * time.Second,
		MaxRetries:         opts.MaxRetries,
	}

	if opts.Password != "" {
		redisOpts.Password = opts.Password
	}

	redisClient := redis.NewClient(redisOpts)
	m := &migrator{
		client: redisClient,
		logger: opts.Logger,
	}
	return m, nil
}

func (m *migrator) GetDefaultGenericOrUnAuthenticatedDAVRequest(ctx context.Context) api.DefaultGenericOrUnAuthenticatedDAVRequest {
	val, err := m.client.Get(api.REDIS_KEY_DEFAULT_GENERIC_OR_UNAUTHENTICATED_DAV_REQUEST).Result()
	if err != nil {
		m.logger.Error("error getting default key", zap.String("key", api.REDIS_KEY_DEFAULT_GENERIC_OR_UNAUTHENTICATED_DAV_REQUEST), zap.Error(err))
		panic(err)
	}

	if val == string(api.DefaultGenericOrUnAuthenticatedDAVRequestOldProxy) {
		return api.DefaultGenericOrUnAuthenticatedDAVRequestOldProxy
	}

	if val == string(api.DefaultGenericOrUnAuthenticatedDAVRequestNewProxy) {
		return api.DefaultGenericOrUnAuthenticatedDAVRequestNewProxy
	}

	// val is not known
	err = errors.New(fmt.Sprintf("val for %s is not known: %s", api.REDIS_KEY_DEFAULT_GENERIC_OR_UNAUTHENTICATED_DAV_REQUEST, val))
	panic(err)
}

func (m *migrator) GetDefaultNonDAVRequest(ctx context.Context) api.DefaultNonDAVRequest {
	val, err := m.client.Get(api.REDIS_KEY_DEFAULT_NON_DAV_REQUEST).Result()
	if err != nil {
		m.logger.Error("error getting default key", zap.String("key", api.REDIS_KEY_DEFAULT_NON_DAV_REQUEST), zap.Error(err))
		panic(err)
	}

	if val == string(api.DefaultNonDAVRequestOldProxy) {
		return api.DefaultNonDAVRequestOldProxy
	}

	if val == string(api.DefaultNonDAVRequestNewProxy) {
		return api.DefaultNonDAVRequestNewProxy
	}

	// val is not known
	err = errors.New(fmt.Sprintf("val for %s is not known: %s", api.REDIS_KEY_DEFAULT_NON_DAV_REQUEST, val))
	panic(err)
}

func (m *migrator) GetDefaultProjectNotFound(ctx context.Context) api.DefaultProjectNotFound {
	val, err := m.client.Get(api.REDIS_KEY_DEFAULT_PROJECT_NOT_FOUND).Result()
	if err != nil {
		m.logger.Error("error getting default key", zap.String("key", api.REDIS_KEY_DEFAULT_PROJECT_NOT_FOUND), zap.Error(err))
		panic(err)
	}

	if val == string(api.DefaultProjectNotFoundOldProxy) {
		return api.DefaultProjectNotFoundOldProxy
	}

	if val == string(api.DefaultProjectNotFoundNewProxy) {
		return api.DefaultProjectNotFoundNewProxy
	}

	// val is not known
	err = errors.New(fmt.Sprintf("val for %s is not known: %s", api.REDIS_KEY_DEFAULT_PROJECT_NOT_FOUND, val))
	panic(err)
}

func (m *migrator) GetDefaultUserNotFound(ctx context.Context) api.DefaultUserNotFound {
	val, err := m.client.Get(api.REDIS_KEY_DEFAULT_USER_NOT_FOUND).Result()
	if err != nil {
		m.logger.Error("error getting default key", zap.String("key", api.REDIS_KEY_DEFAULT_USER_NOT_FOUND), zap.Error(err))
		panic(err)
	}

	if val == string(api.DefaultUserNotFoundOldProxy) {
		return api.DefaultUserNotFoundOldProxy
	}

	if val == string(api.DefaultUserNotFoundNewProxy) {
		return api.DefaultUserNotFoundNewProxy
	}

	err = errors.New(fmt.Sprintf("val for %s is not known: %s", api.REDIS_KEY_DEFAULT_USER_NOT_FOUND, val))
	panic(err)
}

func (m *migrator) IsKeyMigrated(ctx context.Context, key string) (bool, bool) {
	val, err := m.client.Get(key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, false
		}
		panic(err)
	}

	if val == api.MIGRATED {
		return true, true
	}
	if val == api.NOTMIGRATED {
		return false, true
	}
	err = fmt.Errorf("value for key(%s) is not valid (%s)", key, val)
	panic(err)
}
