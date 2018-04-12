package redismigrator

import (
	"context"
	"fmt"
	"time"

	"github.com/cernbox/cboxredirectd/api"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
)

const (
	migrated     = "migrated"
	not_migrated = "not-migrated"
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
	redisClient := redis.NewClient(redisOpts)
	m := &migrator{
		client: redisClient,
		logger: opts.Logger,
	}
	return m, nil
}

func (m *migrator) IsUserMigrated(ctx context.Context, username string) (bool, error) {
	val, err := m.client.Get(username).Result()
	if err != nil {
		m.logger.Error("", zap.Error(err))
		// user is not in the database, so it is a new user
		// as should be forwarded to the new instance.
		if err == redis.Nil {
			return true, nil
		}
		return false, err
	}
	if val == migrated {
		return true, nil
	}
	if val == not_migrated {
		return false, nil
	}
	return false, fmt.Errorf("value for username(%s) is not valid (%s)", username, val)
}

func (m *migrator) MigrateUser(ctx context.Context, username string) error {
	err := m.client.Set(username, migrated, 0).Err()
	if err != nil {
		m.logger.Error("", zap.Error(err))
		return err
	}
	return nil
}
