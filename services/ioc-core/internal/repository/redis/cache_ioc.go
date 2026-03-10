package redis

import (
	"context"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
)

type iocCacheRepo struct {
	baseCache domain.CacheRepository
	prefix    string
	ttl       time.Duration
}

func NewIoCCacheRepository(base domain.CacheRepository, ttl time.Duration) domain.IoCCacheRepository {
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	return &iocCacheRepo{
		baseCache: base,
		prefix:    "ioc-core",
		ttl:       ttl,
	}
}

func (r *iocCacheRepo) keyID(id string) string {
	return domain.NewCacheKey(r.prefix).IoC(id)
}

func (r *iocCacheRepo) keyByValue(iocType domain.IoCType, value string) string {
	return domain.NewCacheKey(r.prefix).IoCByValue(iocType, value)
}

func (r *iocCacheRepo) Get(ctx context.Context, id string) (*domain.IoC, error) {
	var ioc domain.IoC
	err := r.baseCache.Get(ctx, r.keyID(id), &ioc)
	if err != nil {
		return nil, err
	}

	return &ioc, nil
}

func (r *iocCacheRepo) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	var id string
	err := r.baseCache.Get(ctx, r.keyByValue(iocType, value), &id)
	if err != nil {
		return nil, err
	}

	return r.Get(ctx, id)
}

func (r *iocCacheRepo) Set(ctx context.Context, ioc *domain.IoC, ttl time.Duration) error {
	if ioc == nil {
		return nil
	}

	expiration := ttl
	if expiration == 0 {
		expiration = r.ttl
	}
	err := r.baseCache.Set(ctx, r.keyID(ioc.ID), ioc, expiration)
	if err != nil {
		return err
	}
	return r.baseCache.Set(ctx, r.keyByValue(ioc.Type, ioc.Value), ioc.ID, expiration)
}

func (r *iocCacheRepo) Delete(ctx context.Context, id string) error {
	ioc, _ := r.Get(ctx, id)
	keysToDelete := []string{r.keyID(id)}

	if ioc != nil && ioc.Type != domain.IoCTypeUnspecified && ioc.Value != "" {
		keysToDelete = append(keysToDelete, domain.NewCacheKey(r.prefix).IoCByValue(ioc.Type, ioc.Value))
	}

	return r.baseCache.Delete(ctx, keysToDelete...)
}

func (r *iocCacheRepo) InvalidateAllLists(ctx context.Context) error {
	prefix := domain.NewCacheKey(r.prefix).IoCPrefix()
	return r.baseCache.Delete(ctx, prefix)
}
