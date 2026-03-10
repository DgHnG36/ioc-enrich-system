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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type threatHandlerMockIoCRepository struct {
	mock.Mock
}

func (m *threatHandlerMockIoCRepository) Create(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *threatHandlerMockIoCRepository) Update(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *threatHandlerMockIoCRepository) Upsert(ctx context.Context, iocs ...*domain.IoC) error {
	args := m.Called(ctx, iocs)
	return args.Error(0)
}

func (m *threatHandlerMockIoCRepository) Delete(ctx context.Context, ids ...string) error {
	args := m.Called(ctx, ids)
	return args.Error(0)
}

func (m *threatHandlerMockIoCRepository) Get(ctx context.Context, id string) (*domain.IoC, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *threatHandlerMockIoCRepository) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	args := m.Called(ctx, iocType, value)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoC), args.Error(1)
}

func (m *threatHandlerMockIoCRepository) Find(ctx context.Context, filter *domain.IoCFilter, page *domain.Pagination) ([]*domain.IoC, int64, error) {
	args := m.Called(ctx, filter, page)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*domain.IoC), args.Get(1).(int64), args.Error(2)
}

func (m *threatHandlerMockIoCRepository) GetStatistics(ctx context.Context, filter *domain.IoCFilter) (*domain.IoCStatistics, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IoCStatistics), args.Error(1)
}

func (m *threatHandlerMockIoCRepository) GetExpired(ctx context.Context, limit int) ([]*domain.IoC, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.IoC), args.Error(1)
}

func (m *threatHandlerMockIoCRepository) IncrementDetectionCount(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type threatHandlerMockThreatRepository struct {
	mock.Mock
}

func (m *threatHandlerMockThreatRepository) Upsert(ctx context.Context, threats ...*domain.Threat) error {
	args := m.Called(ctx, threats)
	return args.Error(0)
}

func (m *threatHandlerMockThreatRepository) Delete(ctx context.Context, ids ...string) error {
	args := m.Called(ctx, ids)
	return args.Error(0)
}

func (m *threatHandlerMockThreatRepository) Get(ctx context.Context, id string) (*domain.Threat, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *threatHandlerMockThreatRepository) GetByName(ctx context.Context, name string) (*domain.Threat, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *threatHandlerMockThreatRepository) Find(ctx context.Context, filter *domain.ThreatFilter, page *domain.Pagination) ([]*domain.Threat, int64, error) {
	args := m.Called(ctx, filter, page)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*domain.Threat), args.Get(1).(int64), args.Error(2)
}

func (m *threatHandlerMockThreatRepository) GetStatistics(ctx context.Context, filter *domain.ThreatFilter) (*domain.ThreatStatistics, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ThreatStatistics), args.Error(1)
}

func (m *threatHandlerMockThreatRepository) LinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error {
	args := m.Called(ctx, threatID, iocIDs)
	return args.Error(0)
}

func (m *threatHandlerMockThreatRepository) UnlinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error {
	args := m.Called(ctx, threatID, iocIDs)
	return args.Error(0)
}

func (m *threatHandlerMockThreatRepository) GetByIoC(ctx context.Context, iocID string) ([]*domain.Threat, error) {
	args := m.Called(ctx, iocID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Threat), args.Error(1)
}

func (m *threatHandlerMockThreatRepository) GetByTTP(ctx context.Context, ttps []string) ([]*domain.Threat, error) {
	args := m.Called(ctx, ttps)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.Threat), args.Error(1)
}

func (m *threatHandlerMockThreatRepository) CorrelateThreat(ctx context.Context, iocID string, minConfidence float32) ([]*domain.ThreatCorrelation, error) {
	args := m.Called(ctx, iocID, minConfidence)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.ThreatCorrelation), args.Error(1)
}

type threatHandlerMockThreatCacheRepository struct {
	mock.Mock
}

func (m *threatHandlerMockThreatCacheRepository) Get(ctx context.Context, id string) (*domain.Threat, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *threatHandlerMockThreatCacheRepository) GetByName(ctx context.Context, name string) (*domain.Threat, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Threat), args.Error(1)
}

func (m *threatHandlerMockThreatCacheRepository) Set(ctx context.Context, threat *domain.Threat, ttl time.Duration) error {
	args := m.Called(ctx, threat, ttl)
	return args.Error(0)
}

func (m *threatHandlerMockThreatCacheRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *threatHandlerMockThreatCacheRepository) InvalidateAllLists(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func newThreatServiceForHandlerTest(repo domain.ThreatRepository, iocRepo domain.IoCRepository, cache domain.ThreatCacheRepository) *application.ThreatService {
	config := &application.ThreatServiceConfig{
		EnableCache: false,
		CacheTTL:    1 * time.Hour,
	}
	log := logger.New()
	return application.NewThreatService(repo, iocRepo, cache, config, log)
}

/* HANDLER CREATION HELPER */

func newThreatHandlerForTest(service *application.ThreatService) *handler.ThreatHandler {
	log := logger.New()
	converter := handler.NewConverter()
	return handler.NewThreatHandler(service, log, converter)
}

/* BATCH UPSERT TESTS */

func TestThreatHandler_BatchUpsertThreats_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(threats []*domain.Threat) bool {
		return len(threats) >= 1
	})).Return(nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.BatchUpsertThreatsRequest{
		Threats: []*iocpb.Threat{
			{
				Name:     "APT28",
				Severity: iocpb.Severity_SEVERITY_HIGH,
				Category: iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE,
			},
		},
	}

	resp, err := h.BatchUpsertThreats(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, len(resp.UpsertedIds))
	mockRepo.AssertExpectations(t)
}

func TestThreatHandler_BatchUpsertThreats_EmptyRequest(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.BatchUpsertThreatsRequest{
		Threats: nil,
	}

	_, err := h.BatchUpsertThreats(context.Background(), req)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.False(t, ok)
	assert.Equal(t, codes.Unknown, st.Code())
}

/* GET THREAT TESTS */

func TestThreatHandler_GetThreat_ByID_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	threat := &domain.Threat{
		ID:       "threat-id",
		Name:     "APT28",
		Category: domain.ThreatCategoryMalware,
		Severity: domain.SeverityHigh,
	}

	mockRepo.On("Get", mock.Anything, "threat-id").Return(threat, nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.GetThreatRequest{
		Identifier: &iocpb.GetThreatRequest_Id{
			Id: "threat-id",
		},
		IncludeIndicators: false,
	}

	resp, err := h.GetThreat(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "APT28", resp.Threat.Name)
	mockRepo.AssertExpectations(t)
}

func TestThreatHandler_GetThreat_NoIdentifier(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.GetThreatRequest{
		Identifier: nil,
	}

	_, err := h.GetThreat(context.Background(), req)

	assert.NoError(t, err)
}

/* DELETE TESTS */

func TestThreatHandler_DeleteThreats_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	ids := []string{"id1", "id2"}
	mockRepo.On("Delete", mock.Anything, ids).Return(nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.DeleteThreatsRequest{
		Ids:    ids,
		Reason: "Test deletion",
	}

	resp, err := h.DeleteThreats(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}

/* FIND TESTS */

func TestThreatHandler_FindThreats_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	threats := []*domain.Threat{
		{ID: "id1", Name: "APT28", Category: domain.ThreatCategoryMalware, Severity: domain.SeverityHigh},
	}

	mockRepo.On("Find", mock.Anything, mock.Anything, mock.Anything).Return(threats, int64(1), nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.FindThreatsRequest{
		Pagination: &iocpb.Pagination{Page: 1, PageSize: 10},
	}

	resp, err := h.FindThreats(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), resp.Pagination.TotalCount)
	mockRepo.AssertExpectations(t)
}

/* STATISTICS TESTS */

func TestThreatHandler_GetStatistics_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	stats := &domain.ThreatStatistics{

		TotalThreats:  50,
		ActiveThreats: 20,
		ByCategory: map[string]int32{
			domain.ThreatCategoryMalware.String(): int32(20),
		},
		BySeverity: map[string]int32{
			domain.SeverityHigh.String(): int32(10),
		},
		TopCampaigns: []string{"Campaign A", "Campaign B"},
		GeneratedAt:  time.Now(),
	}

	mockRepo.On("GetStatistics", mock.Anything, mock.Anything).Return(stats, nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.GetThreatStatisticsRequest{}

	resp, err := h.GetThreatStatistics(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(50), resp.Statistics.TotalThreats)
	mockRepo.AssertExpectations(t)
}

/* LINK IOCS TESTS */

func TestThreatHandler_LinkIoCs_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	iocIDs := []string{"ioc-id-1", "ioc-id-2"}
	mockRepo.On("LinkIoCs", mock.Anything, "threat-id", iocIDs).Return(nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.LinkIoCsRequest{
		ThreatId: "threat-id",
		IocIds:   iocIDs,
	}

	resp, err := h.LinkIoCs(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}

/* UNLINK IOCS TESTS */

func TestThreatHandler_UnlinkIoCs_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	iocIDs := []string{"ioc-id-1"}
	mockRepo.On("UnlinkIoCs", mock.Anything, "threat-id", iocIDs).Return(nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.UnlinkIoCsRequest{
		ThreatId: "threat-id",
		IocIds:   iocIDs,
	}

	resp, err := h.UnlinkIoCs(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}

/* CORRELATE TESTS */

func TestThreatHandler_CorrelateThreat_Success(t *testing.T) {
	mockRepo := new(threatHandlerMockThreatRepository)
	mockIoCRepo := new(threatHandlerMockIoCRepository)
	mockCache := new(threatHandlerMockThreatCacheRepository)

	correlations := []*domain.ThreatCorrelation{
		{ThreatID: "threat-id", IoCID: "ioc-id", Source: "test"},
	}

	mockRepo.On("CorrelateThreat", mock.Anything, "ioc-id", float32(0.75)).Return(correlations, nil)

	service := newThreatServiceForHandlerTest(mockRepo, mockIoCRepo, mockCache)
	h := newThreatHandlerForTest(service)

	req := &iocpb.CorrelateThreatRequest{
		IocId:         "ioc-id",
		MinConfidence: 0.75,
	}

	resp, err := h.CorrelateThreat(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}
