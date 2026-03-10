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
	"github.com/stretchr/testify/require"
)

// Mock repositories
type MockIoCRepository struct {
	mock.Mock
}

func (m *MockIoCRepository) Create(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *MockIoCRepository) Update(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *MockIoCRepository) Upsert(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *MockIoCRepository) Delete(ctx context.Context, ids ...string) error {
	args := m.Called(ctx, ids)
	return args.Error(0)
}

func (m *MockIoCRepository) Get(ctx context.Context, id string) (*domain.IoC, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *MockIoCRepository) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	args := m.Called(ctx, iocType, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *MockIoCRepository) Find(ctx context.Context, filter *domain.IoCFilter, page *domain.Pagination) ([]*domain.IoC, int64, error) {
	args := m.Called(ctx, filter, page)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*domain.IoC), args.Get(1).(int64), args.Error(2)
}

func (m *MockIoCRepository) GetStatistics(ctx context.Context, filter *domain.IoCFilter) (*domain.IoCStatistics, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoCStatistics), args.Error(1)
}

func (m *MockIoCRepository) GetExpired(ctx context.Context, limit int) ([]*domain.IoC, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.IoC), args.Error(1)
}

func (m *MockIoCRepository) IncrementDetectionCount(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type MockRelatedIoCRepository struct {
	mock.Mock
}

func (m *MockRelatedIoCRepository) UpsertRelation(ctx context.Context, sourceID, targetID string, relationType domain.RelationType, score float32) error {
	args := m.Called(ctx, sourceID, targetID, relationType, score)
	return args.Error(0)
}

func (m *MockRelatedIoCRepository) DeleteRelation(ctx context.Context, sourceID string, targetIDs ...string) error {
	args := m.Called(ctx, sourceID, targetIDs)
	return args.Error(0)
}

func (m *MockRelatedIoCRepository) GetRelations(ctx context.Context, sourceID string, relationType domain.RelationType) ([]*domain.RelatedIoC, error) {
	args := m.Called(ctx, sourceID, relationType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.RelatedIoC), args.Error(1)
}

type MockIoCCacheRepository struct {
	mock.Mock
}

func (m *MockIoCCacheRepository) Get(ctx context.Context, id string) (*domain.IoC, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *MockIoCCacheRepository) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	args := m.Called(ctx, iocType, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *MockIoCCacheRepository) Set(ctx context.Context, ioc *domain.IoC, ttl time.Duration) error {
	args := m.Called(ctx, ioc, ttl)
	return args.Error(0)
}

func (m *MockIoCCacheRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockIoCCacheRepository) Invalidate(ctx context.Context, iocType domain.IoCType, value string) error {
	args := m.Called(ctx, iocType, value)
	return args.Error(0)
}

func (m *MockIoCCacheRepository) InvalidateAllLists(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

/* SERVICE CREATION HELPER */

func newIoCServiceForTest(repo domain.IoCRepository, relatedRepo domain.RelatedIoCRepository, cache domain.IoCCacheRepository) *application.IoCService {
	config := &application.IoCServiceConfig{
		EnableCache:      false,
		EnableEnrichment: false,
		CacheTTL:         1 * time.Hour,
	}
	log := logger.New()
	return application.NewIoCService(repo, relatedRepo, cache, nil, log, config)
}

/* BATCH UPSERT TESTS */

func TestIoCService_BatchUpsertIoCs_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(iocs []*domain.IoC) bool {
		return len(iocs) == 2
	})).Return(nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	iocs := []*domain.IoC{
		{
			Type:        domain.IoCTypeIP,
			Value:       "192.168.1.1",
			Severity:    domain.SeverityHigh,
			Source:      "test",
			Description: "Test IP",
		},
		{
			Type:        domain.IoCTypeDomain,
			Value:       "example.com",
			Severity:    domain.SeverityMedium,
			Source:      "test",
			Description: "Unknown domain",
		},
	}

	ids, err := service.BatchUpsertIoCs(context.Background(), iocs, false)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(ids))
	mockRepo.AssertExpectations(t)
}

func TestIoCService_BatchUpsertIoCs_EmptyList(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	ids, err := service.BatchUpsertIoCs(context.Background(), []*domain.IoC{}, false)

	assert.NoError(t, err)
	assert.Nil(t, ids)
}

func TestIoCService_BatchUpsertIoCs_RepositoryError(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(iocs []*domain.IoC) bool {
		return len(iocs) > 0
	})).Return(assert.AnError)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	iocs := []*domain.IoC{
		{
			Type:        domain.IoCTypeIP,
			Value:       "192.168.1.1",
			Source:      "test",
			Severity:    domain.SeverityHigh,
			Description: "Test IP",
		},
	}

	_, err := service.BatchUpsertIoCs(context.Background(), iocs, false)

	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

/* GET IOC TESTS */

func TestIoCService_GetIoC_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	ioc := &domain.IoC{
		ID:     "test-id",
		Type:   domain.IoCTypeIP,
		Value:  "192.168.1.1",
		Source: "test",
	}

	mockRepo.On("Get", mock.Anything, "test-id").Return(ioc, nil)
	mockRelatedRepo.On("GetRelations", mock.Anything, "test-id", mock.Anything).Return([]*domain.RelatedIoC{}, nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	result, _, err := service.GetIoC(context.Background(), "test-id", false)

	assert.NoError(t, err)
	assert.Equal(t, ioc.ID, result.ID)
	assert.Equal(t, ioc.Value, result.Value)
	mockRepo.AssertExpectations(t)
}

func TestIoCService_GetIoC_NotFound(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	mockRepo.On("Get", mock.Anything, "nonexistent").Return(nil, assert.AnError)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	_, _, err := service.GetIoC(context.Background(), "nonexistent", false)

	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

/* GET BY VALUE TESTS */

func TestIoCService_GetByValue_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	ioc := &domain.IoC{
		ID:     "test-id",
		Type:   domain.IoCTypeIP,
		Value:  "192.168.1.1",
		Source: "test",
	}

	mockRepo.On("GetByValue", mock.Anything, domain.IoCTypeIP, "192.168.1.1").Return(ioc, nil)
	mockRelatedRepo.On("GetRelations", mock.Anything, ioc.ID, mock.Anything).Return([]*domain.RelatedIoC{}, nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	result, _, err := service.GetByValue(context.Background(), domain.IoCTypeIP, "192.168.1.1", false)

	assert.NoError(t, err)
	assert.Equal(t, ioc.Value, result.Value)
	mockRepo.AssertExpectations(t)
}

/* DELETE TESTS */

func TestIoCService_DeleteIoCs_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	ids := []string{"id1", "id2", "id3"}
	mockRepo.On("Delete", mock.Anything, ids).Return(nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	err := service.DeleteIoCs(context.Background(), ids)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestIoCService_DeleteIoCs_RepositoryError(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	ids := []string{"id1"}
	mockRepo.On("Delete", mock.Anything, ids).Return(assert.AnError)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	err := service.DeleteIoCs(context.Background(), ids)

	assert.Error(t, err)
	mockRepo.AssertExpectations(t)
}

/* FIND TESTS */

func TestIoCService_FindIoCs_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	iocs := []*domain.IoC{
		{ID: "id1", Type: domain.IoCTypeIP, Value: "192.168.1.1", Source: "test"},
		{ID: "id2", Type: domain.IoCTypeDomain, Value: "example.com", Source: "test"},
	}

	filter := &domain.IoCFilter{}
	pagination := &domain.Pagination{Page: 1, PageSize: 10}

	mockRepo.On("Find", mock.Anything, filter, pagination).Return(iocs, int64(2), nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	results, total, err := service.FindIoCs(context.Background(), filter, pagination)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(results))
	assert.Equal(t, int64(2), total)
	mockRepo.AssertExpectations(t)
}

/* STATISTICS TESTS */

func TestIoCService_GetStatistics_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	stats := &domain.IoCStatistics{
		TotalIoCs:  100,
		ActiveIoCs: 100,
		ByType: map[string]int32{
			domain.IoCTypeIP.String(): 30,
		},
		BySeverity: map[string]int32{
			domain.SeverityHigh.String(): 50,
		},
		ByVerdict: map[string]int32{
			domain.VerdictBenign.String(): 95,
		},
		GeneratedAt: time.Now(),
	}

	filter := &domain.IoCFilter{}
	mockRepo.On("GetStatistics", mock.Anything, filter).Return(stats, nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	result, err := service.GetStatistics(context.Background(), filter)

	assert.NoError(t, err)
	assert.Equal(t, int32(100), result.TotalIoCs)
	mockRepo.AssertExpectations(t)
}

/* EXPIRED TESTS */

func TestIoCService_GetExpiredIoCs_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	expiredTime := time.Now().AddDate(-1, 0, 0)
	iocs := []*domain.IoC{
		{ID: "id1", Type: domain.IoCTypeIP, Value: "192.168.1.1", Source: "test", ExpiresAt: &expiredTime},
	}

	mockRepo.On("GetExpired", mock.Anything, 100).Return(iocs, nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	results, err := service.GetExpiredIoCs(context.Background(), 100)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	mockRepo.AssertExpectations(t)
}

/* DETECTION COUNT TESTS */

func TestIoCService_IncrementDetectionCount_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	mockRepo.On("IncrementDetectionCount", mock.Anything, "test-id").Return(nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	err := service.IncrementDetectionCount(context.Background(), "test-id")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

/* RELATIONS TESTS */

func TestIoCService_GetRelatedIoCs_Success(t *testing.T) {
	mockRepo := new(MockIoCRepository)
	mockRelatedRepo := new(MockRelatedIoCRepository)
	mockCache := new(MockIoCCacheRepository)

	relatedIoCs := []*domain.RelatedIoC{
		{IoCID: "source-id", RelationType: domain.RelationTypeSameCampaign, SimilarityScore: 0.9},
	}

	mockRelatedRepo.On("GetRelations", mock.Anything, "", domain.RelationTypeSameCampaign).Return(relatedIoCs, nil)

	service := newIoCServiceForTest(mockRepo, mockRelatedRepo, mockCache)

	results, err := service.GetRelatedIoCs(context.Background(), domain.RelationTypeSameCampaign)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(results))
	require.NotNil(t, results[0])
	assert.Equal(t, "source-id", results[0].IoCID)
	mockRelatedRepo.AssertExpectations(t)
}
