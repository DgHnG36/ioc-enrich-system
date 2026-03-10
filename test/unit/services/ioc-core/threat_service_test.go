package ioccoreunit

import (
	"context"
	"testing"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/application"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockThreatRepository struct {
	mock.Mock
}

func (m *MockThreatRepository) Upsert(ctx context.Context, threats ...*domain.Threat) error {
	args := m.Called(ctx, threats)
	return args.Error(0)
}

func (m *MockThreatRepository) Delete(ctx context.Context, ids ...string) error {
	args := m.Called(ctx, ids)
	return args.Error(0)
}

func (m *MockThreatRepository) Get(ctx context.Context, id string) (*domain.Threat, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *MockThreatRepository) GetByName(ctx context.Context, name string) (*domain.Threat, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *MockThreatRepository) Find(ctx context.Context, filter *domain.ThreatFilter, page *domain.Pagination) ([]*domain.Threat, int64, error) {
	args := m.Called(ctx, filter, page)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*domain.Threat), args.Get(1).(int64), args.Error(2)
}

func (m *MockThreatRepository) GetStatistics(ctx context.Context, filter *domain.ThreatFilter) (*domain.ThreatStatistics, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ThreatStatistics), args.Error(1)
}

func (m *MockThreatRepository) LinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error {
	args := m.Called(ctx, threatID, iocIDs)
	return args.Error(0)
}

func (m *MockThreatRepository) UnlinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error {
	args := m.Called(ctx, threatID, iocIDs)
	return args.Error(0)
}

func (m *MockThreatRepository) GetByIoC(ctx context.Context, iocID string) ([]*domain.Threat, error) {
	args := m.Called(ctx, iocID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Threat), args.Error(1)
}

func (m *MockThreatRepository) GetByTTP(ctx context.Context, ttps []string) ([]*domain.Threat, error) {
	args := m.Called(ctx, ttps)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Threat), args.Error(1)
}

func (m *MockThreatRepository) CorrelateThreat(ctx context.Context, iocID string, minConfidence float32) ([]*domain.ThreatCorrelation, error) {
	args := m.Called(ctx, iocID, minConfidence)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.ThreatCorrelation), args.Error(1)
}

type MockThreatCacheRepository struct {
	mock.Mock
}

func (m *MockThreatCacheRepository) Get(ctx context.Context, id string) (*domain.Threat, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *MockThreatCacheRepository) GetByName(ctx context.Context, name string) (*domain.Threat, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *MockThreatCacheRepository) Set(ctx context.Context, threat *domain.Threat, ttl time.Duration) error {
	args := m.Called(ctx, threat, ttl)
	return args.Error(0)
}

func (m *MockThreatCacheRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockThreatCacheRepository) InvalidateAllLists(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

/* SERVICE CREATION HELPER */

func newThreatServiceForTest(repo domain.ThreatRepository, iocRepo domain.IoCRepository, cache domain.ThreatCacheRepository) *application.ThreatService {
	config := &application.ThreatServiceConfig{
		EnableCache: false,
		CacheTTL:    1 * time.Hour,
	}
	log := logger.New()
	return application.NewThreatService(repo, iocRepo, cache, config, log)
}

/* BATCH UPSERT TESTS */

func TestThreatService_BatchUpsertThreats_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(threats []*domain.Threat) bool {
		return len(threats) == 2
	})).Return(nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	threats := []*domain.Threat{
		{
			Name:     "APT28",
			Category: domain.ThreatCategoryMalware,
			Severity: domain.SeverityHigh,
		},
		{
			Name:     "APT29",
			Category: domain.ThreatCategoryBotnet,
			Severity: domain.SeverityHigh,
		},
	}

	ids, err := service.BatchUpsertThreats(context.Background(), threats)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(ids))
	mockRepo.AssertExpectations(t)
}

func TestThreatService_BatchUpsertThreats_EmptyList(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	ids, err := service.BatchUpsertThreats(context.Background(), []*domain.Threat{})

	assert.NoError(t, err)
	assert.Nil(t, ids)
}

func TestThreatService_BatchUpsertThreats_RepositoryError(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(threats []*domain.Threat) bool {
		return len(threats) > 0
	})).Return(assert.AnError)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	threats := []*domain.Threat{
		{Name: "Threat1", Category: domain.ThreatCategoryMalware, Severity: domain.SeverityHigh},
	}

	_, err := service.BatchUpsertThreats(context.Background(), threats)

	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

/* GET THREAT TESTS */

func TestThreatService_GetThreat_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	threat := &domain.Threat{
		ID:       "threat-id",
		Name:     "APT28",
		Category: domain.ThreatCategoryMalware,
		Severity: domain.SeverityHigh,
	}

	mockRepo.On("Get", mock.Anything, "threat-id").Return(threat, nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	result, err := service.GetThreat(context.Background(), "threat-id", "", false)

	assert.NoError(t, err)
	assert.Equal(t, threat.ID, result.ID)
	assert.Equal(t, threat.Name, result.Name)
	mockRepo.AssertExpectations(t)
}

func TestThreatService_GetThreat_NotFound(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	mockRepo.On("Get", mock.Anything, "nonexistent").Return(nil, assert.AnError)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	_, err := service.GetThreat(context.Background(), "nonexistent", "", false)

	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

/* GET BY NAME TESTS */

func TestThreatService_GetByName_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	threat := &domain.Threat{
		ID:       "threat-id",
		Name:     "APT28",
		Category: domain.ThreatCategoryMalware,
		Severity: domain.SeverityHigh,
	}

	mockRepo.On("GetByName", mock.Anything, "APT28").Return(threat, nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	result, err := service.GetThreat(context.Background(), "", "APT28", false)

	assert.NoError(t, err)
	assert.Equal(t, threat.Name, result.Name)
	mockRepo.AssertExpectations(t)
}

/* DELETE TESTS */

func TestThreatService_DeleteThreats_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	ids := []string{"id1", "id2"}
	mockRepo.On("Delete", mock.Anything, ids).Return(nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	err := service.DeleteThreats(context.Background(), ids)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

/* FIND TESTS */

func TestThreatService_FindThreats_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	threats := []*domain.Threat{
		{ID: "id1", Name: "APT28", Category: domain.ThreatCategoryMalware, Severity: domain.SeverityHigh},
		{ID: "id2", Name: "APT29", Category: domain.ThreatCategoryBotnet, Severity: domain.SeverityHigh},
	}

	filter := &domain.ThreatFilter{}
	pagination := &domain.Pagination{Page: 1, PageSize: 10}

	mockRepo.On("Find", mock.Anything, filter, pagination).Return(threats, int64(2), nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	results, total, err := service.FindThreats(context.Background(), filter, pagination)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(results))
	assert.Equal(t, int64(2), total)
	mockRepo.AssertExpectations(t)
}

/* STATISTICS TESTS */

func TestThreatService_GetStatistics_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	stats := &domain.ThreatStatistics{
		TotalThreats:  50,
		ActiveThreats: 50,
		ByCategory: map[string]int32{
			domain.ThreatCategoryMalware.String(): 20,
		},
	}

	filter := &domain.ThreatFilter{}
	mockRepo.On("GetStatistics", mock.Anything, filter).Return(stats, nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	result, err := service.GetThreatStatistics(context.Background(), filter)

	assert.NoError(t, err)
	assert.Equal(t, int32(50), result.TotalThreats)
	assert.Equal(t, int32(50), result.ActiveThreats)
	assert.Equal(t, int32(20), result.ByCategory[domain.ThreatCategoryMalware.String()])
	mockRepo.AssertExpectations(t)
}

/* LINK IOC TESTS */

func TestThreatService_LinkIoCs_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	iocIDs := []string{"ioc-id-1", "ioc-id-2"}
	mockRepo.On("LinkIoCs", mock.Anything, "threat-id", iocIDs).Return(nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	err := service.LinkIoCs(context.Background(), "threat-id", iocIDs)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

/* UNLINK IOC TESTS */

func TestThreatService_UnlinkIoCs_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	iocIDs := []string{"ioc-id-1"}
	mockRepo.On("UnlinkIoCs", mock.Anything, "threat-id", iocIDs).Return(nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	err := service.UnlinkIoCs(context.Background(), "threat-id", iocIDs)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

/* GET BY IOC TESTS */

func TestThreatService_GetByIoC_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	threats := []*domain.Threat{
		{ID: "threat-id", Name: "APT28", Category: domain.ThreatCategoryMalware, Severity: domain.SeverityHigh},
	}

	mockRepo.On("GetByIoC", mock.Anything, "ioc-id").Return(threats, nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	results, err := service.GetThreatsByIoC(context.Background(), "ioc-id")

	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	mockRepo.AssertExpectations(t)
}

/* GET BY TTP TESTS */

func TestThreatService_GetByTTP_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	threats := []*domain.Threat{
		{ID: "threat-id", Name: "APT28", Category: domain.ThreatCategoryMalware, Severity: domain.SeverityHigh},
	}

	ttps := []string{"T1001", "T1002"}
	mockRepo.On("GetByTTP", mock.Anything, ttps).Return(threats, nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	results, err := service.GetThreatsByTTP(context.Background(), ttps)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	mockRepo.AssertExpectations(t)
}

/* CORRELATE TESTS */

func TestThreatService_CorrelateThreat_Success(t *testing.T) {
	mockRepo := new(MockThreatRepository)
	mockIoCRepo := new(MockIoCRepository)
	mockCache := new(MockThreatCacheRepository)

	correlations := []*domain.ThreatCorrelation{
		{ThreatID: "threat-id", IoCID: "ioc-id", Source: "test", CreatedAt: time.Now()},
	}

	mockRepo.On("CorrelateThreat", mock.Anything, "ioc-id", float32(0.75)).Return(correlations, nil)

	service := newThreatServiceForTest(mockRepo, mockIoCRepo, mockCache)

	results, totalResults, err := service.CorrelateThreat(context.Background(), "ioc-id", 0.75)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	assert.Equal(t, int32(1), totalResults)
	mockRepo.AssertExpectations(t)
}
