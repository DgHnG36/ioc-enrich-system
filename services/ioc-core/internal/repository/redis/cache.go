package redis

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/redis/go-redis/v9"
)

type CacheRepo struct {
	client *redis.Client
}

func NewCacheRepository(client *redis.Client) domain.CacheRepository {
	return &CacheRepo{
		client: client,
	}
}

func (r *CacheRepo) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to marshal value to JSON").WithDetail("error", err.Error())
	}

	err = r.client.Set(ctx, key, jsonData, ttl).Err()
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to set cache").WithDetail("error", err.Error())
	}

	return nil
}

func (r *CacheRepo) Get(ctx context.Context, key string, dest any) error {
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return errors.ErrNotFound.Clone().WithMessage("key not found in cache")
	}
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to get cache").WithDetail("error", err.Error())
	}

	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to unmarshal JSON").WithDetail("error", err.Error())
	}

	return nil
}

func (r *CacheRepo) MGet(ctx context.Context, keys []string, destType any) (map[string]any, error) {
	result := make(map[string]any)
	if len(keys) == 0 {
		return result, nil
	}

	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage("failed to MGET").WithDetail("error", err.Error())
	}

	t := reflect.TypeOf(destType)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	for i, val := range vals {
		if val == nil {
			continue
		}

		strVal, ok := val.(string)
		if !ok {
			continue
		}

		destObj := reflect.New(t).Interface()
		if err := json.Unmarshal([]byte(strVal), destObj); err == nil {
			result[keys[i]] = destObj
		}
	}

	return result, nil
}

func (r *CacheRepo) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	err := r.client.Del(ctx, keys...).Err()
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to delete cache").WithDetail("error", err)
	}

	return nil
}

func (r *CacheRepo) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, errors.ErrInternal.Clone().WithMessage("failed to check existence").WithDetail("error", err.Error())
	}

	return count > 0, nil
}

func (r *CacheRepo) SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error) {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return false, errors.ErrInternal.Clone().WithMessage("failed to marshal value to JSON").WithDetail("error", err.Error())
	}

	ok, err := r.client.SetNX(ctx, key, jsonData, ttl).Result()
	if err != nil {
		return false, errors.ErrInternal.Clone().WithMessage("failed to set cache with NX").WithDetail("error", err.Error())
	}

	return ok, nil
}

func (r *CacheRepo) Increment(ctx context.Context, key string) (int64, error) {
	val, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, errors.ErrInternal.Clone().WithMessage("failed to increment").WithDetail("error", err.Error())
	}
	return val, nil
}

func (r *CacheRepo) Expire(ctx context.Context, key string, ttl time.Duration) error {
	err := r.client.Expire(ctx, key, ttl).Err()
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to set expiration").WithDetail("error", err.Error())
	}

	return nil
}

func (r *CacheRepo) TTL(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, errors.ErrInternal.Clone().WithMessage("failed to get TTL").WithDetail("error", err.Error())
	}

	return ttl, nil
}

func (r *CacheRepo) DeleteByPrefix(ctx context.Context, prefix string) error {
	var cursor uint64
	match := prefix + "*"
	for {
		keys, cursorVal, err := r.client.Scan(ctx, cursor, match, 100).Result()
		if err != nil {
			return errors.ErrInternal.Clone().WithMessage("failed to scan keys for deletion").WithDetail("error", err)
		}
		cursor := cursorVal
		if len(keys) > 0 {
			if err := r.client.Del(ctx, keys...); err != nil {
				return errors.ErrInternal.Clone().WithMessage("failed to delete chunk").WithDetail("error", err)
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}
