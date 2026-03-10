package domain

import (
	"context"
	"time"
)

type CacheRepository interface {
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	Get(ctx context.Context, key string, dest any) error
	MGet(ctx context.Context, keys []string, destType any) (map[string]any, error)
	Delete(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, key string) (bool, error)
	SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error)
	Increment(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	TTL(ctx context.Context, key string) (time.Duration, error)
	DeleteByPrefix(ctx context.Context, prefix string) error
}

type CacheKey struct {
	Prefix string
}

func NewCacheKey(prefix string) *CacheKey {
	return &CacheKey{Prefix: prefix}
}

func (ck *CacheKey) build(parts ...string) string {
	key := ck.Prefix
	for _, part := range parts {
		key += ":" + part
	}
	return key
}

func (ck *CacheKey) IoC(id string) string {
	return ck.build("ioc", id)
}
func (ck *CacheKey) IoCByValue(iocType IoCType, value string) string {
	return ck.build("ioc", "value", string(iocType), value)
}
func (ck *CacheKey) IoCPrefix() string {
	return ck.build("ioc")
}

func (ck *CacheKey) Threat(id string) string {
	return ck.build("threat", id)
}

func (ck *CacheKey) ThreatByName(name string) string {
	return ck.build("threat", "name", name)
}

func (ck *CacheKey) ThreatList() string {
	return ck.build("threat", "list")
}

func (ck *CacheKey) EnrichLock(iocID string) string {
	return ck.build("enrichment", "lock", iocID)
}

func (ck *CacheKey) RateLimit(id string) string {
	return ck.build("ratelimit", id)
}

type IoCCacheRepository interface {
	Get(ctx context.Context, id string) (*IoC, error)
	GetByValue(ctx context.Context, iocType IoCType, value string) (*IoC, error)
	Set(ctx context.Context, ioc *IoC, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
	InvalidateAllLists(ctx context.Context) error
}

type ThreatCacheRepository interface {
	Get(ctx context.Context, id string) (*Threat, error)
	GetByName(ctx context.Context, name string) (*Threat, error)
	Set(ctx context.Context, threat *Threat, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
	InvalidateAllLists(ctx context.Context) error
}
