package redismigrator

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
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

// isPathMigrated decides if the user has to be migrated to the new proxy or not.
// path is always a valid path after the remote.php/webdav/ endopoint, like:
// - /home/Photos/...
// - /eos/user/l/labradorsvc/Docs/...
// - /eos/project/c/cbox/Manual/...
func (m *migrator) IsPathMigrated(ctx context.Context, path, username string) (bool, error) {

	m.logger.Debug("migration check for", zap.String("path", path), zap.String("username", username))

	// if the path is a /home path, relative to the user, we check in Redis has an entry for
	// u-gonzalhu
	if strings.HasPrefix(path, "/home") {
		m.logger.Debug("/home rule triggered", zap.String("path", path), zap.String("username", username))
		key := "/eos/user/" + string(username[0]) + "/" + username
		val, err := m.client.Get(key).Result()
		if err != nil {

			// user is not in the database, so it is a new user
			// and should be forwarded to the new instance.
			if err == redis.Nil {
				m.logger.Debug("user not found in Redis", zap.String("path", path), zap.String("username", username))
				return true, nil
			}
			m.logger.Error("", zap.Error(err))
			return false, err
		}
		if val == migrated {
			m.logger.Debug("user found in Redis, path is migrated", zap.String("path", path), zap.String("username", username))
			return true, nil
		}
		if val == not_migrated {
			m.logger.Debug("user found in Redis, path is not-migrated", zap.String("path", path), zap.String("username", username))
			return false, nil
		}
		return false, fmt.Errorf("value for username(%s) is not valid (%s)", username, val)
	}

	// the path does not start with /home, so we compare it agains all the path prefixes stored on Redis.
	prefix := m.getMigrationPrefix(ctx, path)
	if prefix == "" {
		// redirect back to old server for paths we don't know about to be safe
		err := errors.New("prefix is empty")
		m.logger.Error("", zap.Error(err), zap.String("path", path))
		return false, nil
	}

	val, err := m.client.Get(prefix).Result()
	if err != nil {
		// prefix is not in the database, so it is a new path/user
		// and should be forwarded to the new instance.
		if err == redis.Nil {
			m.logger.Debug("path prefix not found in Redis", zap.String("path", path), zap.String("prefix", prefix), zap.String("username", username))
			return true, nil
		}
		m.logger.Error("", zap.Error(err))
		return false, err
	}
	if val == migrated {
		m.logger.Debug("path prefix found in Redis, path is migrated", zap.String("path", path), zap.String("username", username))
		return true, nil
	}
	if val == not_migrated {
		m.logger.Debug("path prefix found in Redis, path is not-migrated", zap.String("path", path), zap.String("username", username))
		return false, nil
	}
	return false, fmt.Errorf("value for prefix(%s) is not valid (%s)", prefix, val)

}

const (
	eosUserPrefix    string = "/eos/user/"
	eosProjectPrefix string = "/eos/project/"
)

func (m *migrator) getMigrationPrefix(ctx context.Context, p string) string {
	var prefix string
	if strings.HasPrefix(p, eosUserPrefix) {
		prefix = eosUserPrefix
	} else if strings.HasPrefix(p, eosProjectPrefix) {
		prefix = eosProjectPrefix
	}

	if prefix == "" {
		return prefix // url does not match /eos/user or /eos/project, like /eos/lhcb

	}

	right := strings.Trim(strings.TrimPrefix(p, prefix), "/") // l/labrador or l/labradorsvc or l or l/labradorsvc/Docs or csc or c/cbox or csc/Docs or c/cbox/Docs
	tokens := strings.Split(right, "/")
	if len(tokens) > 1 {
		if len(tokens[0]) == 1 { // l/labradorsvc
			prefix = path.Join(prefix, path.Join(tokens[0:2]...))
		} else {
			prefix = path.Join(prefix, tokens[0]) // csc/Docs
		}
	}
	if len(tokens) == 1 {
		prefix = path.Join(prefix, tokens[0])
	}

	m.logger.Debug(fmt.Sprintf("%s => %s", p, prefix))
	return prefix

}

// path can be:
// /eos/user/g/gonzalhu/
// /eos/project/csc
// /eos/project/c/cbox
/*
func (m *migrator) getPathPrefixMap(ctx context.Context, path string) (map[string]bool, error) {
	prefixMap := map[string]bool{}
	prefixes := []string{}

	var cursor uint64
	for {
		var keys []string
		var err error

		keys, cursor, err = m.client.Scan(cursor, "/", 10).Result()
		if err != nil {
			return nil, err
		}

		prefixes = append(prefixes, keys...)

		if cursor == 0 {
			break
		}
	}

	// iterate over the list of prefixes and get their migration value (migrated/not-migrated)

	vals, err := m.client.MGet(prefixes...).Result()
	if err != nil {
		return nil, err
	}

	if len(prefixes) != len(vals) {
		// the value array does not match one to one to the list of prefixes
		return nil, errors.New(fmt.Sprintf("redis mget returned %d where it should have returned %s entries", len(vals), len(prefixes)))
	}

	for i, v := range vals {
		migStatus, ok := v.(string) // redis value is a string
		if !ok {
			return nil, errors.New(fmt.Sprintf("redis value for prefix %s is not a string: %+v", prefixes[i], v))
		}

		var isMigrated bool
		if migStatus == "isMigrated" {
			isMigrated = true
		}

		prefixMap[prefixes[i]] = isMigrated
	}

	return prefixMap, nil
}
*/

/*
func (m *migrator) MigrateUser(ctx context.Context, username string) error {
	err := m.client.Set(username, migrated, 0).Err()
	if err != nil {
		m.logger.Error("", zap.Error(err))
		return err
	}
	return nil
}
*/
