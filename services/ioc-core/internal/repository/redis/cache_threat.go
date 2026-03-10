package redis

import (
	"context"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
)

type threatCacheRepo struct {
	baseCache domain.CacheRepository
	prefix    string
	ttl       time.Duration
}

func NewThreatCacheRepository(base domain.CacheRepository, ttl time.Duration) domain.ThreatCacheRepository {
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	return &threatCacheRepo{
		baseCache: base,
		prefix:    "ioc-core",
		ttl:       ttl,
	}
}

func (r *threatCacheRepo) keyID(id string) string {
	return domain.NewCacheKey(r.prefix).Threat(id)
}

func (r *threatCacheRepo) keyName(name string) string {
	return domain.NewCacheKey(r.prefix).ThreatByName(name)
}

func (r *threatCacheRepo) Get(ctx context.Context, id string) (*domain.Threat, error) {
	var threat domain.Threat
	err := r.baseCache.Get(ctx, r.keyID(id), &threat)
	if err != nil {
		return nil, err
	}

	return &threat, nil
}

func (r *threatCacheRepo) GetByName(ctx context.Context, name string) (*domain.Threat, error) {
	var id string
	err := r.baseCache.Get(ctx, r.keyName(name), &id)
	if err != nil {
		return nil, err
	}

	return r.Get(ctx, id)
}

func (r *threatCacheRepo) Set(ctx context.Context, threat *domain.Threat, ttl time.Duration) error {
	if threat == nil {
		return nil
	}

	expiration := ttl
	if expiration == 0 {
		expiration = r.ttl
	}

	if err := r.baseCache.Set(ctx, r.keyID(threat.ID), threat, expiration); err != nil {
		return err
	}

	if threat.Name != "" {
		_ = r.baseCache.Set(ctx, r.keyName(threat.Name), threat.ID, expiration)
	}
	return nil
}

func (r *threatCacheRepo) Delete(ctx context.Context, id string) error {
	threat, _ := r.Get(ctx, id)
	keysToDelete := []string{r.keyID(id)}

	if threat != nil && threat.Name != "" {
		keysToDelete = append(keysToDelete, r.keyName(threat.Name))
	}

	return r.baseCache.Delete(ctx, keysToDelete...)
}

func (r *threatCacheRepo) InvalidateAllLists(ctx context.Context) error {
	listPrefix := domain.NewCacheKey(r.prefix).ThreatList()
	return r.baseCache.DeleteByPrefix(ctx, listPrefix)
}
