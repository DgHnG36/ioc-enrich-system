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

type ThreatServiceConfig struct {
	EnableCache bool
	CacheTTL    time.Duration
}

type ThreatService struct {
	repo    domain.ThreatRepository
	iocRepo domain.IoCRepository
	cache   domain.ThreatCacheRepository
	config  *ThreatServiceConfig
	logger  *logger.Logger

	// In-memory cache for statistics
	statsCache     *domain.ThreatStatistics
	statsCacheTime time.Time
	statsCacheMu   sync.RWMutex
	statsFetchMu   sync.Mutex
}

func NewThreatService(repo domain.ThreatRepository, iocRepo domain.IoCRepository, cache domain.ThreatCacheRepository, config *ThreatServiceConfig, logger *logger.Logger) *ThreatService {
	if config == nil {
		config = &ThreatServiceConfig{
			EnableCache: true,
			CacheTTL:    1 * time.Hour,
		}
	}

	return &ThreatService{
		repo:    repo,
		iocRepo: iocRepo,
		cache:   cache,
		config:  config,
		logger:  logger,
	}
}

func (s *ThreatService) BatchUpsertThreats(ctx context.Context, threats []*domain.Threat) ([]string, error) {
	if len(threats) == 0 {
		return nil, nil
	}

	upsertedIDs := make([]string, 0, len(threats))

	for _, threat := range threats {
		if err := threat.Validate(); err != nil {
			return nil, errors.ErrInvalidInput.Clone().WithMessage(fmt.Sprintf("validation failed for threat: %s", threat.Name))
		}

		if threat.ID == "" {
			threat.ID = uuid.New().String()
		}

		upsertedIDs = append(upsertedIDs, threat.ID)
	}

	if err := s.repo.Upsert(ctx, threats...); err != nil {
		s.logger.Error("Failed to batch upsert threats", err)
		return nil, err
	}

	if s.config.EnableCache && s.cache != nil {
		go func() {
			bgCtx := context.Background()
			var wg sync.WaitGroup
			for _, threat := range threats {
				wg.Add(1)
				go func(t *domain.Threat) {
					defer wg.Done()
					_ = s.cache.Set(bgCtx, t, s.config.CacheTTL)
				}(threat)
			}
			wg.Wait()
		}()
	}

	s.logger.Info("Batch upsert threats completed", logger.Fields{
		"count": len(threats),
	})
	return upsertedIDs, nil
}

func (s *ThreatService) DeleteThreats(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	if err := s.repo.Delete(ctx, ids...); err != nil {
		return err
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

	s.logger.Info("Threats deleted successfully", logger.Fields{
		"count": len(ids),
	})
	return nil
}

func (s *ThreatService) GetThreat(ctx context.Context, id string, name string, includeIndicators bool) (*domain.Threat, error) {
	var threat *domain.Threat
	var err error

	if id != "" {
		if s.config.EnableCache && s.cache != nil {
			threat, _ = s.cache.Get(ctx, id)
		}
		if threat == nil {
			threat, err = s.repo.Get(ctx, id)
		}
	} else if name != "" {
		threat, err = s.repo.GetByName(ctx, name)
	} else {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("must provide either ID or Name")
	}

	if err != nil {
		return nil, err
	}

	// 2. Fetch danh sách IoCs nếu được yêu cầu (Tận dụng batch Get của IoCRepo)
	// Lưu ý: Dù mảng IndicatorIDs không còn nằm ở struct DB, nó có thể được populate từ logic khác,
	// hoặc bạn có thể gọi thẳng iocRepo.GetByThreat(threat.ID)
	// Để đơn giản, ta coi như repo.GetThreat đã join mảng ID hoặc ta gọi thêm query.
	if includeIndicators {
		// Gọi hàm lấy danh sách IoC thuộc về Threat này (Cần thêm vào IoCRepo)
		// iocs, _ := s.iocRepo.GetByThreat(ctx, threat.ID)
		// threat.Indicators = iocs
	}

	// 3. Cache lại nếu là Miss Cache
	if s.config.EnableCache && s.cache != nil && id != "" {
		go s.cache.Set(context.Background(), threat, s.config.CacheTTL)
	}

	return threat, nil
}

func (s *ThreatService) FindThreats(ctx context.Context, filter *domain.ThreatFilter, page *domain.Pagination) ([]*domain.Threat, int64, error) {
	return s.repo.Find(ctx, filter, page)
}

func (s *ThreatService) GetThreatStatistics(ctx context.Context, filter *domain.ThreatFilter) (*domain.ThreatStatistics, error) {
	useCache := filter == nil || (filter.SearchQuery == "" && filter.Category == domain.ThreatCategoryUnspecified && filter.Severity == domain.SeverityUnspecified &&
		filter.Campaign == "" && filter.ThreatActor == "" && filter.IsActive == nil &&
		filter.StartDate == nil && filter.EndDate == nil)

	if useCache {
		s.statsCacheMu.RLock()
		if s.statsCache != nil && time.Since(s.statsCacheTime) < 5*time.Second {
			cached := s.statsCache
			s.statsCacheMu.RUnlock()
			return cached, nil
		}
		s.statsCacheMu.RUnlock()

		s.statsFetchMu.Lock()
		defer s.statsFetchMu.Unlock()

		// Double-check after acquiring lock
		s.statsCacheMu.RLock()
		if s.statsCache != nil && time.Since(s.statsCacheTime) < 5*time.Second {
			cached := s.statsCache
			s.statsCacheMu.RUnlock()
			return cached, nil
		}
		s.statsCacheMu.RUnlock()

		stats, err := s.repo.GetStatistics(ctx, filter)
		if err != nil {
			return nil, err
		}

		s.statsCacheMu.Lock()
		s.statsCache = stats
		s.statsCacheTime = time.Now()
		s.statsCacheMu.Unlock()

		return stats, nil
	}

	return s.repo.GetStatistics(ctx, filter)
}

func (s *ThreatService) LinkIoCs(ctx context.Context, threatID string, iocIDs []string) error {
	if len(iocIDs) == 0 {
		return nil
	}

	// Dựa vào Foreign Key constraint của PostgreSQL để validate.
	// Nếu threatID hoặc iocID không tồn tại, DB sẽ tự văng lỗi FK Violation.
	// Ta không cần Get() từng cái lên để check tồn tại, tiết kiệm N query!
	if err := s.repo.LinkIoCs(ctx, threatID, iocIDs...); err != nil {
		s.logger.Error("Failed to link IoCs to Threat", err)
		return errors.ErrInternal.Clone().WithMessage("failed to link IoCs (maybe invalid IDs)")
	}

	// Xóa Cache của Threat để lần sau Get lên nó load data mới
	if s.config.EnableCache && s.cache != nil {
		go s.cache.Delete(context.Background(), threatID)
	}

	s.logger.Info("IoCs linked to threat", logger.Fields{
		"threat_id":    threatID,
		"linked_count": len(iocIDs),
	})
	return nil
}

func (s *ThreatService) UnlinkIoCs(ctx context.Context, threatID string, iocIDs []string) error {
	if len(iocIDs) == 0 {
		return nil
	}

	if err := s.repo.UnlinkIoCs(ctx, threatID, iocIDs...); err != nil {
		return err
	}

	if s.config.EnableCache && s.cache != nil {
		go s.cache.Delete(context.Background(), threatID)
	}

	return nil
}

func (s *ThreatService) GetThreatsByIoC(ctx context.Context, iocID string) ([]*domain.Threat, error) {
	return s.repo.GetByIoC(ctx, iocID)
}

func (s *ThreatService) GetThreatsByTTP(ctx context.Context, ttps []string) ([]*domain.Threat, error) {
	if len(ttps) == 0 {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("TTPs list cannot be empty")
	}
	return s.repo.GetByTTP(ctx, ttps)
}

func (s *ThreatService) CorrelateThreat(ctx context.Context, iocID string, minConfidence float32) ([]*domain.ThreatCorrelation, int32, error) {
	correlations, err := s.repo.CorrelateThreat(ctx, iocID, minConfidence)
	if err != nil {
		return nil, 0, err
	}

	return correlations, int32(len(correlations)), nil
}

// FIX LATER
