package ioccoreunit

import (
	"context"
	"testing"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/application"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/transport/grpc/handler"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type iocHandlerMockIoCRepository struct {
	mock.Mock
}

func (m *iocHandlerMockIoCRepository) Create(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *iocHandlerMockIoCRepository) Update(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *iocHandlerMockIoCRepository) Upsert(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *iocHandlerMockIoCRepository) Delete(ctx context.Context, ids ...string) error {
	args := m.Called(ctx, ids)
	return args.Error(0)
}

func (m *iocHandlerMockIoCRepository) Get(ctx context.Context, id string) (*domain.IoC, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *iocHandlerMockIoCRepository) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	args := m.Called(ctx, iocType, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *iocHandlerMockIoCRepository) Find(ctx context.Context, filter *domain.IoCFilter, page *domain.Pagination) ([]*domain.IoC, int64, error) {
	args := m.Called(ctx, filter, page)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*domain.IoC), args.Get(1).(int64), args.Error(2)
}

func (m *iocHandlerMockIoCRepository) GetStatistics(ctx context.Context, filter *domain.IoCFilter) (*domain.IoCStatistics, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoCStatistics), args.Error(1)
}

func (m *iocHandlerMockIoCRepository) GetExpired(ctx context.Context, limit int) ([]*domain.IoC, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.IoC), args.Error(1)
}

func (m *iocHandlerMockIoCRepository) IncrementDetectionCount(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type iocHandlerMockRelatedIoCRepository struct {
	mock.Mock
}

func (m *iocHandlerMockRelatedIoCRepository) UpsertRelation(ctx context.Context, sourceID, targetID string, relationType domain.RelationType, score float32) error {
	args := m.Called(ctx, sourceID, targetID, relationType, score)
	return args.Error(0)
}

func (m *iocHandlerMockRelatedIoCRepository) DeleteRelation(ctx context.Context, sourceID string, targetIDs ...string) error {
	args := m.Called(ctx, sourceID, targetIDs)
	return args.Error(0)
}

func (m *iocHandlerMockRelatedIoCRepository) GetRelations(ctx context.Context, sourceID string, relationType domain.RelationType) ([]*domain.RelatedIoC, error) {
	args := m.Called(ctx, sourceID, relationType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.RelatedIoC), args.Error(1)
}

type iocHandlerMockIoCCacheRepository struct {
	mock.Mock
}

func (m *iocHandlerMockIoCCacheRepository) Get(ctx context.Context, id string) (*domain.IoC, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *iocHandlerMockIoCCacheRepository) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	args := m.Called(ctx, iocType, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *iocHandlerMockIoCCacheRepository) Set(ctx context.Context, ioc *domain.IoC, ttl time.Duration) error {
	args := m.Called(ctx, ioc, ttl)
	return args.Error(0)
}

func (m *iocHandlerMockIoCCacheRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *iocHandlerMockIoCCacheRepository) Invalidate(ctx context.Context, iocType domain.IoCType, value string) error {
	args := m.Called(ctx, iocType, value)
	return args.Error(0)
}

func (m *iocHandlerMockIoCCacheRepository) InvalidateAllLists(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func newIoCServiceForHandlerTest(repo domain.IoCRepository, relatedRepo domain.RelatedIoCRepository, cache domain.IoCCacheRepository) *application.IoCService {
	config := &application.IoCServiceConfig{
		EnableCache:      false,
		EnableEnrichment: false,
		CacheTTL:         1 * time.Hour,
	}
	log := logger.New()
	return application.NewIoCService(repo, relatedRepo, cache, nil, log, config)
}

/* HANDLER CREATION HELPER */

func newIoCHandlerForTest(service *application.IoCService) *handler.IoCHandler {
	log := logger.New()
	converter := handler.NewConverter()
	return handler.NewIoCHandler(service, log, converter)
}

/* BATCH UPSERT TESTS */

func TestIoCHandler_BatchUpsertIoCs_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(iocs []*domain.IoC) bool {
		return len(iocs) >= 1
	})).Return(nil)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.BatchUpsertIoCsRequest{
		Iocs: []*iocpb.IoC{
			{
				Type:     iocpb.IoCType_IOC_TYPE_IP,
				Value:    "192.168.1.1",
				Severity: iocpb.Severity_SEVERITY_HIGH,
				Source:   "test",
			},
		},
		AutoEnrich: false,
	}

	resp, err := h.BatchUpsertIoCs(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), resp.TotalSuccess)
	mockRepo.AssertExpectations(t)
}

func TestIoCHandler_BatchUpsertIoCs_EmptyRequest(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.BatchUpsertIoCsRequest{
		Iocs: nil,
	}

	_, err := h.BatchUpsertIoCs(context.Background(), req)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	require.False(t, ok)
	assert.Equal(t, codes.Unknown, st.Code())
}

/* GET IOC TESTS */

func TestIoCHandler_GetIoC_ByID_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	ioc := &domain.IoC{
		ID:     "test-id",
		Type:   domain.IoCTypeIP,
		Value:  "192.168.1.1",
		Source: "test",
	}

	mockRepo.On("Get", mock.Anything, "test-id").Return(ioc, nil)
	mockRelatedRepo.On("GetRelations", mock.Anything, "test-id", mock.Anything).Return([]*domain.RelatedIoC{}, nil)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.GetIoCRequest{
		Identifier: &iocpb.GetIoCRequest_Id{
			Id: "test-id",
		},
		IncludeRelated: false,
	}

	resp, err := h.GetIoC(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Ioc)
	assert.Equal(t, "192.168.1.1", resp.Ioc.Value)
	mockRepo.AssertExpectations(t)
}

func TestIoCHandler_GetIoC_NoIdentifier(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.GetIoCRequest{
		Identifier:     nil,
		IncludeRelated: false,
	}

	_, err := h.GetIoC(context.Background(), req)

	assert.Error(t, err)
}

/* GET BY VALUE TESTS */

func TestIoCHandler_GetByValue_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	ioc := &domain.IoC{
		ID:     "test-id",
		Type:   domain.IoCTypeIP,
		Value:  "192.168.1.1",
		Source: "test",
	}

	mockRepo.On("GetByValue", mock.Anything, domain.IoCTypeIP, "192.168.1.1").Return(ioc, nil)
	mockRelatedRepo.On("GetRelations", mock.Anything, ioc.ID, mock.Anything).Return([]*domain.RelatedIoC{}, nil)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.GetByValueRequest{
		Type:           iocpb.IoCType_IOC_TYPE_IP,
		Value:          "192.168.1.1",
		IncludeRelated: false,
	}

	resp, err := h.GetByValue(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "192.168.1.1", resp.Ioc.Value)
	mockRepo.AssertExpectations(t)
}

/* DELETE TESTS */

func TestIoCHandler_DeleteIoCs_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	ids := []string{"id1", "id2"}
	mockRepo.On("Delete", mock.Anything, ids).Return(nil)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.DeleteIoCsRequest{
		Ids:    ids,
		Reason: "Test deletion",
	}

	resp, err := h.DeleteIoCs(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}

/* FIND TESTS */

func TestIoCHandler_FindIoCs_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	iocs := []*domain.IoC{
		{ID: "id1", Type: domain.IoCTypeIP, Value: "192.168.1.1", Source: "test"},
	}

	mockRepo.On("Find", mock.Anything, mock.Anything, mock.Anything).Return(iocs, int64(1), nil)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.FindIoCsRequest{
		Pagination: &iocpb.Pagination{Page: 1, PageSize: 10},
	}

	resp, err := h.FindIoCs(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), resp.Pagination.TotalCount)
	mockRepo.AssertExpectations(t)
}

/* STATISTICS TESTS */

func TestIoCHandler_GetStatistics_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	stats := &domain.IoCStatistics{
		TotalIoCs:  100,
		ActiveIoCs: 30,
		ByType: map[string]int32{
			domain.IoCTypeIP.String(): int32(50),
		},
		BySeverity: map[string]int32{
			domain.SeverityHigh.String(): int32(20),
		},
		ByVerdict: map[string]int32{
			domain.VerdictBenign.String(): int32(95),
		},
		GeneratedAt: time.Now(),
	}

	mockRepo.On("GetStatistics", mock.Anything, mock.Anything).Return(stats, nil)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.GetIoCStatisticsRequest{}

	resp, err := h.GetIoCStatistics(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(100), resp.Statistics.TotalIocs)
	mockRepo.AssertExpectations(t)
}

/* HEALTH CHECK TESTS */

func TestIoCHandler_CheckSourceHealth_Success(t *testing.T) {
	mockRepo := new(iocHandlerMockIoCRepository)
	mockRelatedRepo := new(iocHandlerMockRelatedIoCRepository)
	mockCache := new(iocHandlerMockIoCCacheRepository)

	service := newIoCServiceForHandlerTest(mockRepo, mockRelatedRepo, mockCache)
	h := newIoCHandlerForTest(service)

	req := &iocpb.GetEnrichmentStatusRequest{}

	resp, err := h.GetEnrichmentStatus(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}
