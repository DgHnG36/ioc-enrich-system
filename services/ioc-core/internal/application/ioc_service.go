package application

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"github.com/google/uuid"
)

type IoCServiceConfig struct {
	EnableCache      bool
	EnableEnrichment bool
	CacheTTL         time.Duration
}

type IoCService struct {
	repo          domain.IoCRepository
	relatedRepo   domain.RelatedIoCRepository
	cache         domain.IoCCacheRepository
	enrichAdapter *EnrichAdapter
	logger        *logger.Logger
	config        *IoCServiceConfig

	// In-memory cache for statistics to reduce DB pressure under high concurrency
	statsCache     *domain.IoCStatistics
	statsCacheTime time.Time
	statsCacheMu   sync.RWMutex
	statsFetchMu   sync.Mutex // prevents thundering herd on cache miss
}

func NewIoCService(repo domain.IoCRepository, relatedRepo domain.RelatedIoCRepository, cache domain.IoCCacheRepository, enrichAdapter *EnrichAdapter, logger *logger.Logger, config *IoCServiceConfig) *IoCService {
	if config == nil {
		config = &IoCServiceConfig{
			EnableCache:      true,
			EnableEnrichment: true,
			CacheTTL:         1 * time.Hour,
		}
	}

	return &IoCService{
		repo:          repo,
		relatedRepo:   relatedRepo,
		cache:         cache,
		enrichAdapter: enrichAdapter,
		logger:        logger,
		config:        config,
	}

}

func (s *IoCService) BatchUpsertIoCs(ctx context.Context, iocs []*domain.IoC, autoEnrich bool) ([]string, error) {
	if len(iocs) == 0 {
		return nil, nil
	}

	upsertedIDs := make([]string, 0, len(iocs))
	for _, ioc := range iocs {
		if err := ioc.Validate(); err != nil {
			return nil, errors.WrapError(err, errors.ErrInvalidInput.Code, fmt.Sprintf("validation failed for IoC: %s", ioc.Value))
		}
		if ioc.ID == "" {
			ioc.ID = uuid.New().String()
		}
		upsertedIDs = append(upsertedIDs, ioc.ID)
	}

	if err := s.repo.Create(ctx, iocs...); err != nil {
		return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to batch upsert IoCs")
	}

	// Async (cache and enrichment) - parallelized with bounded concurrency
	go func() {
		bgCtx := context.Background()
		if s.config.EnableCache && s.cache != nil {
			_ = s.cache.InvalidateAllLists(bgCtx)
		}

		const maxConcurrency = 10
		sem := make(chan struct{}, maxConcurrency)
		var wg sync.WaitGroup

		for _, ioc := range iocs {
			wg.Add(1)
			sem <- struct{}{}
			go func(ioc *domain.IoC) {
				defer wg.Done()
				defer func() { <-sem }()

				if s.config.EnableCache && s.cache != nil {
					_ = s.cache.Set(bgCtx, ioc, s.config.CacheTTL)
				}
				if autoEnrich && s.config.EnableEnrichment && s.enrichAdapter != nil {
					_, err := s.enrichAdapter.EnrichIoC(bgCtx, ioc)
					if err != nil {
						s.logger.Warn("Auto-enrichment failed", logger.Fields{
							"ioc_id": ioc.ID,
							"error":  err.Error(),
						})
					}
				}
			}(ioc)
		}
		wg.Wait()
	}()
	s.logger.Info("Batch upsert completed", logger.Fields{
		"count": len(iocs),
	})
	return upsertedIDs, nil
}

func (s *IoCService) DeleteIoCs(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	if err := s.repo.Delete(ctx, ids...); err != nil {
		return errors.WrapError(err, errors.ErrInternal.Code, "failed to delete IoCs")
	}

	if s.config.EnableCache && s.cache != nil {
		go func() {
			bgCtx := context.Background()
			var wg sync.WaitGroup
			for _, id := range ids {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					_ = s.cache.Delete(bgCtx, id)
				}(id)
			}
			wg.Wait()
		}()
	}

	s.logger.Info("IoCs deleted successfully", logger.Fields{
		"count": len(ids),
	})

	return nil
}

func (s *IoCService) GetIoC(ctx context.Context, id string, includeRelated bool, options ...domain.RelationType) (*domain.IoC, []*domain.RelatedIoC, error) {
	var ioc *domain.IoC
	var err error

	// Try cache first
	if s.config.EnableCache && s.cache != nil {
		ioc, err = s.cache.Get(ctx, id)
		if err == nil && ioc != nil {
			s.logger.Info("IoC cache hit", logger.Fields{
				"ioc_id": id,
			})
		}
	}

	// Cache miss or disabled, get from repo
	if ioc == nil {
		ioc, err = s.repo.Get(ctx, id)
		if err != nil {
			return nil, nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get IoC")
		}

		if s.config.EnableCache && s.cache != nil {
			go s.cache.Set(context.Background(), ioc, s.config.CacheTTL)
		}
	}

	// If includeRelated is true, fetch related IoCs
	var relatedIoCs []*domain.RelatedIoC
	if includeRelated {
		relatedIoCs = s.fetchRelatedIoCs(ctx, ioc.ID, options)
	}

	return ioc, relatedIoCs, nil
}

func (s *IoCService) GetByValue(ctx context.Context, iocType domain.IoCType, value string, includeRelated bool, options ...domain.RelationType) (*domain.IoC, []*domain.RelatedIoC, error) {
	var ioc *domain.IoC
	var err error

	// Cache miss or disabled, get from repo
	if s.config.EnableCache && s.cache != nil {
		ioc, err = s.cache.GetByValue(ctx, iocType, value)
		if err == nil && ioc != nil {
			s.logger.Info("IoC cache hit", logger.Fields{
				"ioc_type": iocType,
				"value":    value,
			})
		}
	}

	if ioc == nil {
		ioc, err = s.repo.GetByValue(ctx, iocType, value)
		if err != nil {
			return nil, nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get IoC by value")
		}
	}

	if s.config.EnableCache && s.cache != nil {
		go s.cache.Set(context.Background(), ioc, s.config.CacheTTL)
	}

	var relatedIoCs []*domain.RelatedIoC
	if includeRelated {
		relatedIoCs = s.fetchRelatedIoCs(ctx, ioc.ID, options)
	}

	return ioc, relatedIoCs, nil
}

func (s *IoCService) FindIoCs(ctx context.Context, filter *domain.IoCFilter, page *domain.Pagination) ([]*domain.IoC, int64, error) {
	iocs, total, err := s.repo.Find(ctx, filter, page)
	if err != nil {
		s.logger.Error("Failed to find IoCs", err, logger.Fields{
			"error": err.Error(),
		})
		return nil, 0, errors.WrapError(err, errors.ErrInternal.Code, "failed to find IoCs")
	}
	return iocs, total, nil
}

func (s *IoCService) GetStatistics(ctx context.Context, filter *domain.IoCFilter) (*domain.IoCStatistics, error) {
	useCache := filter == nil || (filter.SearchQuery == "" && filter.Type == domain.IoCTypeUnspecified && filter.Severity == domain.SeverityUnspecified &&
		filter.Verdict == domain.VerdictUnspecified && filter.Source == "" && len(filter.Tags) == 0 &&
		filter.IsActive == nil && filter.StartDate == nil && filter.EndDate == nil)

	if useCache {
		// Fast path: check cache with read lock
		s.statsCacheMu.RLock()
		if s.statsCache != nil && time.Since(s.statsCacheTime) < 5*time.Second {
			cached := s.statsCache
			s.statsCacheMu.RUnlock()
			return cached, nil
		}
		s.statsCacheMu.RUnlock()

		// Slow path: serialize DB fetches to prevent thundering herd
		s.statsFetchMu.Lock()
		defer s.statsFetchMu.Unlock()

		// Double-check: another goroutine may have populated cache while we waited
		s.statsCacheMu.RLock()
		if s.statsCache != nil && time.Since(s.statsCacheTime) < 5*time.Second {
			cached := s.statsCache
			s.statsCacheMu.RUnlock()
			return cached, nil
		}
		s.statsCacheMu.RUnlock()

		stats, err := s.repo.GetStatistics(ctx, filter)
		if err != nil {
			s.logger.Error("Failed to get IoC statistics", err, logger.Fields{
				"error": err.Error(),
			})
			return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get IoC statistics")
		}

		s.statsCacheMu.Lock()
		s.statsCache = stats
		s.statsCacheTime = time.Now()
		s.statsCacheMu.Unlock()

		return stats, nil
	}

	stats, err := s.repo.GetStatistics(ctx, filter)
	if err != nil {
		s.logger.Error("Failed to get IoC statistics", err, logger.Fields{
			"error": err.Error(),
		})
		return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get IoC statistics")
	}
	return stats, nil
}

func (s *IoCService) IncrementDetectionCount(ctx context.Context, id string) error {
	if err := s.repo.IncrementDetectionCount(ctx, id); err != nil {
		s.logger.Error("Failed to increment IoC detection count", err, logger.Fields{
			"error": err.Error(),
		})
		return errors.WrapError(err, errors.ErrInternal.Code, "failed to increment IoC detection count")
	}
	if s.config.EnableCache && s.cache != nil {
		go s.cache.Delete(context.Background(), id)
	}
	return nil
}

func (s *IoCService) GetExpiredIoCs(ctx context.Context, limit int) ([]*domain.IoC, error) {
	iocs, err := s.repo.GetExpired(ctx, limit)
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get expired IoCs")
	}
	return iocs, nil
}

func (s *IoCService) EnrichIoC(ctx context.Context, id string, iocType domain.IoCType, value string, sources []string, forceRefresh bool) (*domain.IoC, error) {
	if !s.config.EnableEnrichment || s.enrichAdapter == nil {
		return nil, errors.ErrInternal.Clone().WithMessage("enrichment is disabled")
	}

	opts := s.NewOptionsEnrichRequest(id, iocType, value, sources, forceRefresh)
	var ioc *domain.IoC
	var err error
	// Enrich with ID if provided
	if opts.IoCID != "" {
		s.logger.Info("Enriching IoC with ID", logger.Fields{
			"ioc_id": opts.IoCID,
		})

		ioc, err = s.repo.Get(ctx, opts.IoCID)
		if err != nil {
			return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get IoC for enrichment")
		}
	} else if opts.IoCType != domain.IoCTypeUnspecified && opts.Value != "" {
		s.logger.Info("Enriching IoC with type and value", logger.Fields{
			"ioc_type": opts.IoCType,
			"value":    opts.Value,
		})

		ioc, err = s.repo.GetByValue(ctx, opts.IoCType, opts.Value)
		if err != nil {
			s.logger.Info("IoC not found in DB, creating a temporary one for enrichment", logger.Fields{
				"type":  opts.IoCType,
				"value": opts.Value,
			})

			ioc = &domain.IoC{
				ID:        uuid.New().String(),
				Type:      opts.IoCType,
				Value:     opts.Value,
				CreatedAt: time.Now(),
				IsActive:  true,
			}
		}
	} else {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("either IoC ID or type and value must be provided for enrichment")
	}

	if !opts.ForceRefresh && ioc.ThreatContext != nil && ioc.EnrichmentSummary != nil {
		lastEnriched := ioc.EnrichmentSummary.LastEnriched
		if time.Since(lastEnriched) < 1*time.Hour {
			s.logger.Debug("Using cached enrichment result", logger.Fields{"ioc_id": ioc.ID})
			return ioc, nil
		}
	}

	s.logger.Info("Triggering enrichment adapter", logger.Fields{
		"ioc_id":  ioc.ID,
		"sources": opts.Sources,
	})

	enrichedIoC, err := s.enrichAdapter.EnrichIoCWithSources(ctx, ioc, opts.Sources)
	if err != nil {
		s.logger.Error("Enrichment failed", err, logger.Fields{
			"ioc_id": ioc.ID,
			"error":  err.Error(),
		})
		return nil, errors.WrapError(err, errors.ErrInternal.Code, "enrichment failed")
	}

	_, err = s.BatchUpsertIoCs(ctx, []*domain.IoC{enrichedIoC}, false)
	if err != nil {
		s.logger.Error("Failed to save enriched IoC to DB", err, logger.Fields{
			"error": err.Error(),
		})
		return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to save enriched IoC to DB")
	}
	s.logger.Info("Enriched IoC saved to DB", logger.Fields{
		"ioc_id": enrichedIoC.ID,
	})
	return enrichedIoC, nil
}

// GetEnrichmentStatus

func (s *IoCService) GetRelatedIoCs(ctx context.Context, relationType domain.RelationType) ([]*domain.RelatedIoC, error) {
	relatedIoCs, err := s.relatedRepo.GetRelations(ctx, "", relationType)
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrInternal.Code, "failed to get related IoCs")
	}
	return relatedIoCs, nil
}

/* HELPER STRUCT FOR ENRICHMENT REQUEST */
type optionsEnrichRequest struct {
	IoCID        string
	IoCType      domain.IoCType
	Value        string
	Sources      []string
	ForceRefresh bool
}

func (s *IoCService) NewOptionsEnrichRequest(iocID string, iocType domain.IoCType, value string, sources []string, forceRefresh bool) *optionsEnrichRequest {
	return &optionsEnrichRequest{
		IoCID:        iocID,
		IoCType:      iocType,
		Value:        value,
		Sources:      sources,
		ForceRefresh: forceRefresh,
	}
}

/* HELPER METHODS */
func (s *IoCService) fetchRelatedIoCs(ctx context.Context, iocID string, options []domain.RelationType) []*domain.RelatedIoC {
	var relatedIoCs []*domain.RelatedIoC
	if len(options) == 0 {
		related, err := s.relatedRepo.GetRelations(ctx, iocID, "")
		if err != nil {
			s.logger.Warn("Failed to get all related IoCs", logger.Fields{
				"ioc_id": iocID,
				"error":  err.Error(),
			})
			return []*domain.RelatedIoC{}
		}
		return related
	}

	seen := make(map[string]bool)
	for _, opt := range options {
		if opt == "" {
			continue
		}
		related, err := s.relatedRepo.GetRelations(ctx, iocID, opt)
		if err != nil {
			s.logger.Warn("Failed to get related IoCs by type", logger.Fields{
				"ioc_id":        iocID,
				"relation_type": opt,
				"error":         err.Error(),
			})
			continue
		}

		for _, r := range related {
			uniqueKey := r.IoCID + string(r.RelationType)
			if !seen[uniqueKey] {
				relatedIoCs = append(relatedIoCs, r)
				seen[uniqueKey] = true
			}
		}
	}

	if relatedIoCs == nil {
		relatedIoCs = []*domain.RelatedIoC{}
	}
	return relatedIoCs
}
