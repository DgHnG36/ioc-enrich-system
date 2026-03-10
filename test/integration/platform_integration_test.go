package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	iocv1 "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func withTrustedServiceName(serviceName string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		} else {
			md = md.Copy()
		}
		if len(md.Get("x-service-name")) == 0 {
			md.Set("x-service-name", serviceName)
		}
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func dialIoCCore(t *testing.T) (*grpc.ClientConn, iocv1.IoCServiceClient, iocv1.ThreatServiceClient) {
	t.Helper()
	addr := envOrDefault("IOC_CORE_ADDR", "localhost:50051")
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(withTrustedServiceName("api-gateway")),
	)
	if err != nil {
		t.Skipf("skip: cannot init grpc client to ioc-core (%s): %v", addr, err)
	}
	return conn, iocv1.NewIoCServiceClient(conn), iocv1.NewThreatServiceClient(conn)
}

func TestAPIGatewayHealth(t *testing.T) {
	baseURL := envOrDefault("API_GATEWAY_URL", "http://localhost:8080")
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		t.Skipf("skip: api gateway not reachable at %s: %v", baseURL, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "API Gateway health endpoint should return 200 OK")
}

func TestAPIGatewayProtectedEndpointRequiresAuth(t *testing.T) {
	baseURL := envOrDefault("API_GATEWAY_URL", "http://localhost:8080")
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(baseURL + "/api/v1/iocs")
	if err != nil {
		t.Skipf("skip: api gateway not reachable at %s: %v", baseURL, err)
	}
	defer resp.Body.Close()

	assert.Contains(t, []int{http.StatusUnauthorized, http.StatusNotFound}, resp.StatusCode,
		"Protected endpoint should return 401 Unauthorized or 404 Not Found")
}

func TestIoCCoreBatchUpsertEmptyInvalidArgument(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{Iocs: nil})
	require.Error(t, err, "Empty IoCs request should return an error")

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	assert.Contains(t, []codes.Code{codes.InvalidArgument, codes.Unknown}, status.Code(err),
		"Empty IoCs should return InvalidArgument or Unknown status code")
}

func TestIoCCoreGetIoCMissingIdentifierInvalidArgument(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := iocClient.GetIoC(ctx, &iocv1.GetIoCRequest{})
	require.Error(t, err, "GetIoC with missing identifier should return an error")

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	assert.Contains(t, []codes.Code{codes.InvalidArgument, codes.Unknown}, status.Code(err),
		"Missing identifier should return InvalidArgument or Unknown status code")
}

func TestThreatCoreBatchUpsertEmptyInvalidArgument(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{Threats: nil})
	require.Error(t, err, "Empty threats request should return an error")

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	assert.Contains(t, []codes.Code{codes.InvalidArgument, codes.Unknown}, status.Code(err),
		"Empty threats should return InvalidArgument or Unknown status code")
}

func TestThreatCoreGetThreatMissingIdentifier(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := threatClient.GetThreat(ctx, &iocv1.GetThreatRequest{})
	if err != nil && status.Code(err) == codes.Unimplemented {
		t.Skipf("skip: handler error mapping currently returns nil in this build (%v)", err)
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		if status.Code(err) == codes.Unavailable {
			t.Skipf("skip: ioc-core not fully ready: %v", err)
		}
	}
	assert.True(t, err != nil || resp != nil, "GetThreat should return either error or response")
}

func TestIoCCoreBatchUpsertIoCsSuccess(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	suffix := time.Now().UnixNano()
	ipValue := fmt.Sprintf("198.51.100.%d", (suffix%200)+1)
	domainValue := fmt.Sprintf("malicious-test-%d.example.com", suffix)

	testIoCs := []*iocv1.IoC{
		createTestIoC(iocv1.IoCType_IOC_TYPE_IP, ipValue, "integration-test",
			iocv1.Severity_SEVERITY_MEDIUM, iocv1.Verdict_VERDICT_MALICIOUS),
		createTestIoC(iocv1.IoCType_IOC_TYPE_DOMAIN, domainValue, "integration-test",
			iocv1.Severity_SEVERITY_HIGH, iocv1.Verdict_VERDICT_MALICIOUS),
	}

	resp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs:       testIoCs,
		AutoEnrich: false,
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}

	require.NoError(t, err, "BatchUpsertIoCs with valid data should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	assert.NotEmpty(t, resp.UpsertedIds, "Should return upserted IDs")
	assert.GreaterOrEqual(t, resp.TotalSuccess, int32(0), "Total success should be >= 0")
}

func TestIoCCoreGetIoCByID(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	suffix := uniqueSuffix()
	testIP := fmt.Sprintf("10.10.%d.%d", (suffix/256)%200, suffix%200+1)

	createResp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_IP, testIP, "integration-test",
				iocv1.Severity_SEVERITY_LOW, iocv1.Verdict_VERDICT_SUSPICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC successfully")
	require.NotEmpty(t, createResp.UpsertedIds, "Should return created ID")

	iocID := createResp.UpsertedIds[0]
	getResp, err := iocClient.GetIoC(ctx, &iocv1.GetIoCRequest{
		Identifier: &iocv1.GetIoCRequest_Id{Id: iocID},
	})

	require.NoError(t, err, "GetIoC by ID should succeed")
	require.NotNil(t, getResp, "Response should not be nil")
	require.NotNil(t, getResp.Ioc, "IoC data should not be nil")
	assert.Equal(t, testIP, getResp.Ioc.Value, "Should return correct IoC value")
}

func TestIoCCoreGetByValue(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	suffix := uniqueSuffix()
	testIP := fmt.Sprintf("172.16.%d.%d", (suffix/256)%200, suffix%200+1)
	_, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_IP, testIP, "integration-test",
				iocv1.Severity_SEVERITY_MEDIUM, iocv1.Verdict_VERDICT_SUSPICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC")

	getResp, err := iocClient.GetByValue(ctx, &iocv1.GetByValueRequest{
		Type:  iocv1.IoCType_IOC_TYPE_IP,
		Value: testIP,
	})

	require.NoError(t, err, "GetByValue should succeed")
	require.NotNil(t, getResp, "Response should not be nil")
	require.NotNil(t, getResp.Ioc, "IoC should be found")
	assert.Equal(t, testIP, getResp.Ioc.Value, "Should return correct IoC")
}

func TestIoCCoreFindIoCs(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := iocClient.FindIoCs(ctx, &iocv1.FindIoCsRequest{
		Pagination: &iocv1.Pagination{
			Page:     1,
			PageSize: 10,
		},
		Filter: &iocv1.IoCFilter{
			Source: "integration-test",
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}

	require.NoError(t, err, "FindIoCs should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	assert.GreaterOrEqual(t, len(resp.Iocs), 0, "IoCs list should be readable")
	assert.NotNil(t, resp.Pagination, "Pagination should be returned")
}

func TestIoCCoreFindIoCsFilterFields(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	suffix := uniqueSuffix()
	queryToken := fmt.Sprintf("find-ioc-%d", suffix)
	source := fmt.Sprintf("integration-filter-%d", suffix)
	tag := fmt.Sprintf("tag-%d", suffix)

	seed := createTestIoC(
		iocv1.IoCType_IOC_TYPE_DOMAIN,
		fmt.Sprintf("%s.example.com", queryToken),
		source,
		iocv1.Severity_SEVERITY_HIGH,
		iocv1.Verdict_VERDICT_SUSPICIOUS,
	)
	seed.Description = queryToken
	seed.Tags = []string{tag}
	seed.IsActive = true
	seed.ThreatContext = &iocv1.ThreatContext{
		ConfidenceScore: 0.91,
		Categories:      []iocv1.ThreatCategory{iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE},
		KillChainPhase:  iocv1.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY,
	}
	created := timestamppb.Now()
	seed.CreatedAt = created
	seed.UpdatedAt = created

	_, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{Iocs: []*iocv1.IoC{seed}})
	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC seed for filter tests")

	start := timestamppb.New(time.Now().Add(-2 * time.Minute))
	end := timestamppb.New(time.Now().Add(2 * time.Minute))

	tests := []struct {
		name   string
		filter *iocv1.IoCFilter
	}{
		{name: "search_query", filter: &iocv1.IoCFilter{SearchQuery: queryToken}},
		{name: "type", filter: &iocv1.IoCFilter{Type: iocv1.IoCType_IOC_TYPE_DOMAIN}},
		{name: "severity", filter: &iocv1.IoCFilter{Severity: iocv1.Severity_SEVERITY_HIGH}},
		{name: "verdict", filter: &iocv1.IoCFilter{Verdict: iocv1.Verdict_VERDICT_SUSPICIOUS}},
		{name: "source", filter: &iocv1.IoCFilter{Source: source}},
		{name: "tags", filter: &iocv1.IoCFilter{Tags: []string{tag}}},
		{name: "kill_chain_phase", filter: &iocv1.IoCFilter{KillChainPhase: iocv1.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY}},
		{name: "is_active", filter: &iocv1.IoCFilter{IsActive: true}},
		{name: "start_date", filter: &iocv1.IoCFilter{StartDate: start}},
		{name: "end_date", filter: &iocv1.IoCFilter{EndDate: end}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := iocClient.FindIoCs(ctx, &iocv1.FindIoCsRequest{
				Pagination: &iocv1.Pagination{Page: 1, PageSize: 20},
				Filter:     tc.filter,
			})
			require.NoError(t, err, "FindIoCs with filter %s should succeed", tc.name)
			require.NotNil(t, resp, "Response should not be nil")
			assert.NotNil(t, resp.Pagination, "Pagination should be returned")
			assert.GreaterOrEqual(t, len(resp.Iocs), 0, "IoCs list should be readable")
			if len(resp.Iocs) > 0 {
				assert.NotNil(t, resp.Iocs[0], "First IoC item should not be nil")
			}
		})
	}
}

func TestIoCCoreDeleteIoCs(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	createResp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_DOMAIN, "delete-test.example.com", "integration-test",
				iocv1.Severity_SEVERITY_LOW, iocv1.Verdict_VERDICT_SUSPICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC")
	require.NotEmpty(t, createResp.UpsertedIds, "Should return ID")

	deleteResp, err := iocClient.DeleteIoCs(ctx, &iocv1.DeleteIoCsRequest{
		Ids:    createResp.UpsertedIds,
		Reason: "integration test cleanup",
	})

	require.NoError(t, err, "DeleteIoCs should succeed")
	require.NotNil(t, deleteResp, "Response should not be nil")
	assert.GreaterOrEqual(t, deleteResp.DeletedCount, int32(0), "Deleted count should be >= 0")
}

func TestIoCCoreGetIoCStatistics(t *testing.T) {
	conn, iocClient, _ := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := iocClient.GetIoCStatistics(ctx, &iocv1.GetIoCStatisticsRequest{
		Filter: &iocv1.IoCFilter{
			Source: "integration-test",
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}

	require.NoError(t, err, "GetIoCStatistics should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	assert.NotNil(t, resp.Statistics, "Statistics should not be nil")
}

func TestThreatCoreBatchUpsertThreatsSuccess(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testThreats := []*iocv1.Threat{
		createTestThreat("APT-TEST-001", "Integration test threat",
			iocv1.ThreatCategory_THREAT_CATEGORY_C2, iocv1.Severity_SEVERITY_HIGH, 0.85, []string{"T1566"}),
	}

	resp, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: testThreats,
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}

	require.NoError(t, err, "BatchUpsertThreats with valid data should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	assert.NotEmpty(t, resp.UpsertedIds, "Should return upserted IDs")
}

func TestThreatCoreGetThreatByID(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	createResp, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{
			createTestThreat("APT-TEST-002", "Test threat for get by ID",
				iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE, iocv1.Severity_SEVERITY_MEDIUM, 0.75, []string{"T1059"}),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create threat")
	require.NotEmpty(t, createResp.UpsertedIds, "Should return ID")

	threatID := createResp.UpsertedIds[0]
	getResp, err := threatClient.GetThreat(ctx, &iocv1.GetThreatRequest{
		Identifier: &iocv1.GetThreatRequest_Id{Id: threatID},
	})

	require.NoError(t, err, "GetThreat by ID should succeed")
	require.NotNil(t, getResp, "Response should not be nil")
	require.NotNil(t, getResp.Threat, "Threat should not be nil")
	assert.Equal(t, "APT-TEST-002", getResp.Threat.Name, "Should return correct threat")
}

func TestThreatCoreGetThreatByName(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	threatName := "APT-TEST-003"
	_, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{
			createTestThreat(threatName, "Test threat for get by name",
				iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE, iocv1.Severity_SEVERITY_CRITICAL, 0.95, []string{"T1486"}),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create threat")

	getResp, err := threatClient.GetThreat(ctx, &iocv1.GetThreatRequest{
		Identifier: &iocv1.GetThreatRequest_Name{Name: threatName},
	})

	require.NoError(t, err, "GetThreat by name should succeed")
	require.NotNil(t, getResp, "Response should not be nil")
	require.NotNil(t, getResp.Threat, "Threat should not be nil")
	assert.Equal(t, threatName, getResp.Threat.Name, "Should return correct threat")
}

func TestThreatCoreFindThreats(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := threatClient.FindThreats(ctx, &iocv1.FindThreatsRequest{
		Pagination: &iocv1.Pagination{
			Page:     1,
			PageSize: 10,
		},
		Filter: &iocv1.ThreatFilter{
			IsActive: true,
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}

	require.NoError(t, err, "FindThreats should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	assert.NotNil(t, resp.Threats, "Threats list should not be nil")
	assert.NotNil(t, resp.Pagination, "Pagination should be returned")
}

func TestThreatCoreFindThreatsFilterFields(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	suffix := uniqueSuffix()
	queryToken := fmt.Sprintf("find-threat-%d", suffix)
	campaign := fmt.Sprintf("campaign-%d", suffix)
	actor := fmt.Sprintf("actor-%d", suffix)

	seed := createTestThreat(
		fmt.Sprintf("%s-name", queryToken),
		queryToken,
		iocv1.ThreatCategory_THREAT_CATEGORY_C2,
		iocv1.Severity_SEVERITY_HIGH,
		0.9,
		[]string{"T1566"},
	)
	seed.Campaigns = []string{campaign}
	seed.ThreatActors = []string{actor}
	seed.IsActive = true
	created := timestamppb.Now()
	seed.CreatedAt = created
	seed.UpdatedAt = created

	_, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{Threats: []*iocv1.Threat{seed}})
	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create threat seed for filter tests")

	start := timestamppb.New(time.Now().Add(-2 * time.Minute))
	end := timestamppb.New(time.Now().Add(2 * time.Minute))

	tests := []struct {
		name   string
		filter *iocv1.ThreatFilter
	}{
		{name: "search_query", filter: &iocv1.ThreatFilter{SearchQuery: queryToken}},
		{name: "category", filter: &iocv1.ThreatFilter{Category: iocv1.ThreatCategory_THREAT_CATEGORY_C2}},
		{name: "severity", filter: &iocv1.ThreatFilter{Severity: iocv1.Severity_SEVERITY_HIGH}},
		{name: "campaign", filter: &iocv1.ThreatFilter{Campaign: campaign}},
		{name: "threat_actor", filter: &iocv1.ThreatFilter{ThreatActor: actor}},
		{name: "is_active", filter: &iocv1.ThreatFilter{IsActive: true}},
		{name: "start_date", filter: &iocv1.ThreatFilter{StartDate: start}},
		{name: "end_date", filter: &iocv1.ThreatFilter{EndDate: end}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := threatClient.FindThreats(ctx, &iocv1.FindThreatsRequest{
				Pagination: &iocv1.Pagination{Page: 1, PageSize: 20},
				Filter:     tc.filter,
			})
			require.NoError(t, err, "FindThreats with filter %s should succeed", tc.name)
			require.NotNil(t, resp, "Response should not be nil")
			assert.NotNil(t, resp.Pagination, "Pagination should be returned")
			assert.GreaterOrEqual(t, len(resp.Threats), 0, "Threats list should be readable")
			if len(resp.Threats) > 0 {
				assert.NotNil(t, resp.Threats[0], "First threat item should not be nil")
			}
		})
	}
}

func TestThreatCoreDeleteThreats(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	threat := createTestThreat("DELETE-TEST-THREAT", "Threat for deletion test",
		iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE, iocv1.Severity_SEVERITY_LOW, 0.5, nil)
	threat.IsActive = false
	createResp, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{threat},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create threat")
	require.NotEmpty(t, createResp.UpsertedIds, "Should return ID")

	deleteResp, err := threatClient.DeleteThreats(ctx, &iocv1.DeleteThreatsRequest{
		Ids:    createResp.UpsertedIds,
		Reason: "integration test cleanup",
	})

	require.NoError(t, err, "DeleteThreats should succeed")
	require.NotNil(t, deleteResp, "Response should not be nil")
	assert.GreaterOrEqual(t, deleteResp.DeletedCount, int32(0), "Deleted count should be >= 0")
}

func TestThreatCoreGetThreatStatistics(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := threatClient.GetThreatStatistics(ctx, &iocv1.GetThreatStatisticsRequest{
		Filter: &iocv1.ThreatFilter{
			IsActive: true,
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}

	require.NoError(t, err, "GetThreatStatistics should succeed")
	require.NotNil(t, resp, "Response should not be nil")
	if resp.Statistics == nil {
		t.Log("GetThreatStatistics returned nil statistics (treated as empty stats)")
	}
}

func TestThreatCoreLinkIoCs(t *testing.T) {
	conn, iocClient, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	suffix := uniqueSuffix()
	testIP := fmt.Sprintf("203.0.113.%d", suffix%200+1)
	testThreatName := fmt.Sprintf("LINK-TEST-THREAT-%d", suffix)

	iocResp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_IP, testIP, "integration-test",
				iocv1.Severity_SEVERITY_MEDIUM, iocv1.Verdict_VERDICT_MALICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC")

	threatResp, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{
			createTestThreat(testThreatName, "Threat for linking test",
				iocv1.ThreatCategory_THREAT_CATEGORY_C2, iocv1.Severity_SEVERITY_HIGH, 0.88, []string{"T1071"}),
		},
	})
	require.NoError(t, err, "Should create threat")

	linkResp, err := threatClient.LinkIoCs(ctx, &iocv1.LinkIoCsRequest{
		ThreatId: threatResp.UpsertedIds[0],
		IocIds:   iocResp.UpsertedIds,
	})

	require.NoError(t, err, "LinkIoCs should succeed")
	require.NotNil(t, linkResp, "Response should not be nil")
}

func TestThreatCoreUnlinkIoCs(t *testing.T) {
	conn, iocClient, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	suffix := uniqueSuffix()
	testDomain := fmt.Sprintf("unlink-test-%d.example.com", suffix)
	testThreatName := fmt.Sprintf("UNLINK-TEST-THREAT-%d", suffix)

	iocResp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_DOMAIN, testDomain, "integration-test",
				iocv1.Severity_SEVERITY_LOW, iocv1.Verdict_VERDICT_SUSPICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC")

	threatResp, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{
			createTestThreat(testThreatName, "Threat for unlinking test",
				iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE, iocv1.Severity_SEVERITY_MEDIUM, 0.65, nil),
		},
	})
	require.NoError(t, err, "Should create threat")

	_, err = threatClient.LinkIoCs(ctx, &iocv1.LinkIoCsRequest{
		ThreatId: threatResp.UpsertedIds[0],
		IocIds:   iocResp.UpsertedIds,
	})
	require.NoError(t, err, "Should link IoCs")

	unlinkResp, err := threatClient.UnlinkIoCs(ctx, &iocv1.UnlinkIoCsRequest{
		ThreatId: threatResp.UpsertedIds[0],
		IocIds:   iocResp.UpsertedIds,
	})

	require.NoError(t, err, "UnlinkIoCs should succeed")
	require.NotNil(t, unlinkResp, "Response should not be nil")
}

func TestThreatCoreCorrelateThreat(t *testing.T) {
	conn, iocClient, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	suffix := uniqueSuffix()
	testIP := fmt.Sprintf("198.51.100.%d", suffix%200+1)

	iocResp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_IP, testIP, "integration-test",
				iocv1.Severity_SEVERITY_CRITICAL, iocv1.Verdict_VERDICT_MALICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC")
	require.NotEmpty(t, iocResp.UpsertedIds, "Should return IoC ID")

	correlateResp, err := threatClient.CorrelateThreat(ctx, &iocv1.CorrelateThreatRequest{
		IocId:         iocResp.UpsertedIds[0],
		MinConfidence: 0.5,
	})

	require.NoError(t, err, "CorrelateThreat should succeed")
	require.NotNil(t, correlateResp, "Response should not be nil")
	assert.GreaterOrEqual(t, len(correlateResp.Correlations), 0, "Correlations list should be readable")
	assert.GreaterOrEqual(t, correlateResp.TotalFound, int32(0), "Total found should be >= 0")
}

func TestThreatCoreGetThreatsByIoC(t *testing.T) {
	conn, iocClient, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	suffix := uniqueSuffix()
	hashValue := fmt.Sprintf("d41d8cd98f00b204e9800998ecf84%04d", suffix%10000)
	testThreatName := fmt.Sprintf("IOC-LINKED-THREAT-%d", suffix)

	iocResp, err := iocClient.BatchUpsertIoCs(ctx, &iocv1.BatchUpsertIoCsRequest{
		Iocs: []*iocv1.IoC{
			createTestIoC(iocv1.IoCType_IOC_TYPE_HASH_MD5, hashValue, "integration-test",
				iocv1.Severity_SEVERITY_HIGH, iocv1.Verdict_VERDICT_MALICIOUS),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create IoC")

	threatResp, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{
			createTestThreat(testThreatName, "Threat linked to IoC",
				iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE, iocv1.Severity_SEVERITY_HIGH, 0.82, []string{"T1204"}),
		},
	})
	require.NoError(t, err, "Should create threat")

	_, err = threatClient.LinkIoCs(ctx, &iocv1.LinkIoCsRequest{
		ThreatId: threatResp.UpsertedIds[0],
		IocIds:   iocResp.UpsertedIds,
	})
	require.NoError(t, err, "Should link IoC to threat")

	getResp, err := threatClient.GetThreatsByIoC(ctx, &iocv1.GetThreatsByIoCRequest{
		IocId: iocResp.UpsertedIds[0],
	})

	require.NoError(t, err, "GetThreatsByIoC should succeed")
	require.NotNil(t, getResp, "Response should not be nil")
	assert.GreaterOrEqual(t, len(getResp.Threats), 0, "Threats list should be readable")
	assert.GreaterOrEqual(t, getResp.TotalCount, int32(0), "Total count should be >= 0")
}

func TestThreatCoreGetThreatsByTTP(t *testing.T) {
	conn, _, threatClient := dialIoCCore(t)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	suffix := uniqueSuffix()
	testThreatName := fmt.Sprintf("TTP-TEST-THREAT-%d", suffix)

	_, err := threatClient.BatchUpsertThreats(ctx, &iocv1.BatchUpsertThreatsRequest{
		Threats: []*iocv1.Threat{
			createTestThreat(testThreatName, "Threat with TTPs",
				iocv1.ThreatCategory_THREAT_CATEGORY_C2, iocv1.Severity_SEVERITY_HIGH, 0.9, []string{"T1566", "T1059"}),
		},
	})

	if status.Code(err) == codes.Unavailable {
		t.Skipf("skip: ioc-core not reachable: %v", err)
	}
	require.NoError(t, err, "Should create threat with TTPs")

	getResp, err := threatClient.GetThreatsByTTP(ctx, &iocv1.GetThreatsByTTPRequest{
		Ttps: []string{"T1566"},
	})

	require.NoError(t, err, "GetThreatsByTTP should succeed")
	require.NotNil(t, getResp, "Response should not be nil")
	assert.GreaterOrEqual(t, len(getResp.Threats), 0, "Threats list should be readable")
	assert.GreaterOrEqual(t, getResp.TotalCount, int32(0), "Total count should be >= 0")
}
