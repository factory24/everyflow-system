package cache

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache is a thin wrapper around go-redis used for caching hot-path
// lookups (e.g. GetByID/GetBySerialNumber) across services. Connection
// follows the shared env var convention: REDIS_HOST, REDIS_PORT,
// REDIS_PASSWORD, REDIS_DB — same instance FlowSupport and other services
// already point at.
type RedisCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Connect()
}

type redisCache struct {
	client *redis.Client
}

func NewRedisCache() RedisCache {
	return &redisCache{}
}

func (c *redisCache) Connect() {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "redis-master"
	}
	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}
	password := os.Getenv("REDIS_PASSWORD")

	db := 0
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		if parsed, err := strconv.Atoi(dbStr); err == nil {
			db = parsed
		}
	}

	c.client = redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.client.Ping(ctx).Err(); err != nil {
		log.Printf("warning: failed to connect to redis at %s:%s: %v", host, port, err)
	} else {
		log.Printf("connected to redis at %s:%s", host, port)
	}
}

func (c *redisCache) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, key).Result()
}

func (c *redisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return c.client.Set(ctx, key, value, ttl).Err()
}

func (c *redisCache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

// TTLFromEnv parses a Go duration from the given env var, falling back to def
// when unset or invalid. Just an env-parsing helper for the const TTLs each
// service defines next to its cache-aside code (see
// learns/shared-redis-cache-flow-system.md) — not a generic cache wrapper.
func TTLFromEnv(envVar string, def time.Duration) time.Duration {
	if v := os.Getenv(envVar); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
