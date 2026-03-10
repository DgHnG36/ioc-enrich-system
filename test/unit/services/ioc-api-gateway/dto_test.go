package iocapigatewayunit

import (
	"testing"
	"time"

	dto "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/dto"
	"github.com/stretchr/testify/assert"
)

/* PAGINATION DTO TESTS */

func TestPagination_ValidValues(t *testing.T) {
	pagination := dto.Pagination{
		Page:     1,
		PageSize: 10,
	}

	assert.Equal(t, int32(1), pagination.Page)
	assert.Equal(t, int32(10), pagination.PageSize)
}

func TestPagination_DefaultValues(t *testing.T) {
	pagination := dto.Pagination{}

	assert.Equal(t, int32(0), pagination.Page)
	assert.Equal(t, int32(0), pagination.PageSize)
}

func TestPagination_MaxPageSize(t *testing.T) {
	pagination := dto.Pagination{
		Page:     5,
		PageSize: 100,
	}

	assert.Equal(t, int32(100), pagination.PageSize)
}

/* SORT OPTIONS DTO TESTS */

func TestSortOptions_AscendingOrder(t *testing.T) {
	sortOptions := dto.SortOptions{
		SortBy: []string{"created_at", "severity"},
		Desc:   false,
	}

	assert.Equal(t, 2, len(sortOptions.SortBy))
	assert.Equal(t, false, sortOptions.Desc)
	assert.Equal(t, "created_at", sortOptions.SortBy[0])
}

func TestSortOptions_DescendingOrder(t *testing.T) {
	sortOptions := dto.SortOptions{
		SortBy: []string{"severity"},
		Desc:   true,
	}

	assert.Equal(t, 1, len(sortOptions.SortBy))
	assert.Equal(t, true, sortOptions.Desc)
}

func TestSortOptions_EmptySortFields(t *testing.T) {
	sortOptions := dto.SortOptions{
		SortBy: []string{},
		Desc:   false,
	}

	assert.Equal(t, 0, len(sortOptions.SortBy))
}

/* CHECK SOURCE HEALTH DTO TESTS */

func TestCheckSourceHealthDTO_SingleSource(t *testing.T) {
	healthDTO := dto.CheckSourceHealthDTO{
		Sources: []string{"virustotal"},
	}

	assert.Equal(t, 1, len(healthDTO.Sources))
	assert.Equal(t, "virustotal", healthDTO.Sources[0])
}

func TestCheckSourceHealthDTO_MultipleSources(t *testing.T) {
	healthDTO := dto.CheckSourceHealthDTO{
		Sources: []string{"virustotal", "abuseipdb", "otx"},
	}

	assert.Equal(t, 3, len(healthDTO.Sources))
	assert.Contains(t, healthDTO.Sources, "virustotal")
	assert.Contains(t, healthDTO.Sources, "abuseipdb")
	assert.Contains(t, healthDTO.Sources, "otx")
}

func TestCheckSourceHealthDTO_EmptySources(t *testing.T) {
	healthDTO := dto.CheckSourceHealthDTO{
		Sources: []string{},
	}

	assert.Equal(t, 0, len(healthDTO.Sources))
}

/* ENRICH OPTIONS DTO TESTS */

func TestEnrichOptionsDTO_AllOptions(t *testing.T) {
	enrichOptions := dto.EnrichOptionsDTO{
		HashType:            "sha256",
		IncludeFileMetadata: true,
		ForceRefresh:        true,
	}

	assert.Equal(t, "sha256", enrichOptions.HashType)
	assert.Equal(t, true, enrichOptions.IncludeFileMetadata)
	assert.Equal(t, true, enrichOptions.ForceRefresh)
}

func TestEnrichOptionsDTO_DefaultValues(t *testing.T) {
	enrichOptions := dto.EnrichOptionsDTO{}

	assert.Empty(t, enrichOptions.HashType)
	assert.Equal(t, false, enrichOptions.IncludeFileMetadata)
	assert.Equal(t, false, enrichOptions.ForceRefresh)
}

/* IOC DTO TESTS */

func TestCreateIoCRequest_ValidData(t *testing.T) {
	req := dto.CreateIoCRequest{
		Type:        "ip",
		Value:       "192.168.1.1",
		Severity:    "high",
		Source:      "virustotal",
		Description: "Malicious IP",
		Tags:        []string{"malware", "botnet"},
		Metadata: map[string]any{
			"country": "unknown",
			"asn":     "12345",
		},
	}

	assert.NotEmpty(t, req.Type)
	assert.NotEmpty(t, req.Value)
	assert.Equal(t, "high", req.Severity)
	assert.Equal(t, "virustotal", req.Source)
	assert.Equal(t, 2, len(req.Tags))
	assert.Equal(t, 2, len(req.Metadata))
}

func TestCreateIoCRequest_MinimalData(t *testing.T) {
	req := dto.CreateIoCRequest{
		Type:   "domain",
		Value:  "malicious.com",
		Source: "otx",
	}

	assert.Equal(t, "domain", req.Type)
	assert.Equal(t, "malicious.com", req.Value)
	assert.Equal(t, "otx", req.Source)
	assert.Empty(t, req.Description)
	assert.Nil(t, req.Metadata)
}

func TestCreateIoCRequest_Validate(t *testing.T) {
	req := dto.CreateIoCRequest{
		Type:   "url",
		Value:  "http://malicious.com/malware",
		Source: "hybrid_analysis",
	}

	assert.Nil(t, req.Validate())
}

func TestIoCIDUriRequest_ValidUUID(t *testing.T) {
	req := dto.IoCIDUriRequest{
		ID: "550e8400-e29b-41d4-a716-446655440000",
	}

	assert.NotEmpty(t, req.ID)
}

func TestIoCValueUriRequest_ValidValue(t *testing.T) {
	req := dto.IoCValueUriRequest{
		Value: "192.168.1.1",
	}

	assert.NotEmpty(t, req.Value)
	assert.Equal(t, "192.168.1.1", req.Value)
}

func TestGetIoCQuery_WithFilters(t *testing.T) {
	query := dto.GetIoCQuery{
		Type:           "ip",
		Value:          "10.0.0.1",
		IncludeRelated: true,
		RelationTypes:  []string{"same_campaign", "same_threat_actor"},
	}

	assert.Equal(t, "ip", query.Type)
	assert.Equal(t, "10.0.0.1", query.Value)
	assert.Equal(t, true, query.IncludeRelated)
	assert.Equal(t, 2, len(query.RelationTypes))
}

func TestGetRelatedIoCsDTO_Single(t *testing.T) {
	relatedDTO := dto.GetRelatedIoCsDTO{
		RelationType: "same_campaign",
	}

	assert.Equal(t, "same_campaign", relatedDTO.RelationType)
}

func TestGetExpiredQuery_WithLimit(t *testing.T) {
	query := dto.GetExpiredQuery{
		Limit: 50,
	}

	assert.Equal(t, int32(50), query.Limit)
}

func TestGetExpiredQuery_NoLimit(t *testing.T) {
	query := dto.GetExpiredQuery{}

	assert.Equal(t, int32(0), query.Limit)
}

func TestIoCStatsQuery_FullFilters(t *testing.T) {
	startDate := time.Now().AddDate(0, -1, 0)
	endDate := time.Now()
	isActive := true

	query := dto.IoCStatsQuery{
		SearchQuery:    "test",
		Type:           "url",
		Severity:       "high",
		Verdict:        "malicious",
		Source:         "virustotal",
		KillChainPhase: "command_and_control",
		Tags:           []string{"apt", "ransomware"},
		IsActive:       &isActive,
		StartDate:      &startDate,
		EndDate:        &endDate,
	}

	assert.Equal(t, "test", query.SearchQuery)
	assert.Equal(t, "url", query.Type)
	assert.Equal(t, "high", query.Severity)
	assert.Equal(t, "malicious", query.Verdict)
	assert.True(t, *query.IsActive)
	assert.NotNil(t, query.StartDate)
	assert.NotNil(t, query.EndDate)
}

func TestBatchUpsertDTO_ValidBatch(t *testing.T) {
	batch := dto.BatchUpsertDTO{
		IoCs: []dto.CreateIoCRequest{
			{Type: "ip", Value: "1.1.1.1", Source: "virustotal"},
			{Type: "domain", Value: "example.com", Source: "otx"},
		},
		AutoEnrich: true,
	}

	assert.Equal(t, 2, len(batch.IoCs))
	assert.Equal(t, true, batch.AutoEnrich)
}

func TestEnrichIoCDTO_WithOptions(t *testing.T) {
	enrichDTO := dto.EnrichIoCDTO{
		TargetSources: []string{"virustotal", "abuseipdb", "otx"},
		ForceRefresh:  true,
	}

	assert.Equal(t, 3, len(enrichDTO.TargetSources))
	assert.Equal(t, true, enrichDTO.ForceRefresh)
}

func TestDeleteIoCsDTO_ValidDelete(t *testing.T) {
	deleteDTO := dto.DeleteIoCsDTO{
		IDs:    []string{"id1", "id2", "id3"},
		Reason: "False positive",
	}

	assert.Equal(t, 3, len(deleteDTO.IDs))
	assert.Equal(t, "False positive", deleteDTO.Reason)
}

func TestIoCFilter_CompleteFilter(t *testing.T) {
	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now()
	isActive := true

	filter := dto.IoCFilter{
		SearchQuery:    "query",
		Type:           "md5",
		Severity:       "medium",
		Verdict:        "suspicious",
		Source:         "virustotal",
		KillChainPhase: "delivery",
		Tags:           []string{"trojan"},
		IsActive:       &isActive,
		StartDate:      &startDate,
		EndDate:        &endDate,
	}

	assert.Equal(t, "query", filter.SearchQuery)
	assert.Equal(t, "md5", filter.Type)
	assert.Equal(t, "medium", filter.Severity)
	assert.Equal(t, "suspicious", filter.Verdict)
	assert.True(t, *filter.IsActive)
}

func TestFindIoCsDTO_Complete(t *testing.T) {
	findDTO := dto.FindIoCsDTO{
		Pagination: dto.Pagination{Page: 1, PageSize: 20},
		Filter: dto.IoCFilter{
			Type:     "url",
			Severity: "high",
		},
		SortOptions: dto.SortOptions{
			SortBy: []string{"created_at"},
			Desc:   true,
		},
	}

	assert.Equal(t, int32(1), findDTO.Pagination.Page)
	assert.Equal(t, "url", findDTO.Filter.Type)
	assert.Equal(t, 1, len(findDTO.SortOptions.SortBy))
	assert.True(t, findDTO.SortOptions.Desc)
}

/* THREAT DTO TESTS */

func TestThreatUriRequest_ValidRequest(t *testing.T) {
	req := dto.ThreatUriRequest{
		ID: "550e8400-e29b-41d4-a716-446655440000",
	}

	assert.NotEmpty(t, req.ID)
}

func TestThreatIoCUriRequest_ValidRequest(t *testing.T) {
	req := dto.ThreatIoCUriRequest{
		IoCID: "550e8400-e29b-41d4-a716-446655440000",
	}

	assert.NotEmpty(t, req.IoCID)
}

func TestGetThreatQuery_Complete(t *testing.T) {
	query := dto.GetThreatQuery{
		Name:              "APT28",
		IncludeIndicators: true,
	}

	assert.Equal(t, "APT28", query.Name)
	assert.True(t, query.IncludeIndicators)
}

func TestThreatTTPQuery_Valid(t *testing.T) {
	query := dto.ThreatTTPQuery{
		TTPs: []string{"T1001", "T1002", "T1003"},
	}

	assert.Equal(t, 3, len(query.TTPs))
}

func TestThreatStatsQuery_CompleteQuery(t *testing.T) {
	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now()
	isActive := true

	query := dto.ThreatStatsQuery{
		SearchQuery: "query",
		Category:    "malware",
		Severity:    "high",
		Campaign:    "APT28",
		ThreatActor: "Russia",
		IsActive:    &isActive,
		Tags:        []string{"apt"},
		StartDate:   &startDate,
		EndDate:     &endDate,
	}

	assert.Equal(t, "query", query.SearchQuery)
	assert.Equal(t, "malware", query.Category)
	assert.Equal(t, "high", query.Severity)
	assert.Equal(t, "APT28", query.Campaign)
	assert.True(t, *query.IsActive)
}

func TestThreatMetadataDTO_Complete(t *testing.T) {
	metadata := dto.ThreatMetadataDTO{
		TTPs:       []string{"T1001", "T1002"},
		References: []string{"http://example.com"},
		CustomFields: map[string]any{
			"detection_count": 5,
			"platforms":       []string{"linux", "windows"},
		},
	}

	assert.Equal(t, 2, len(metadata.TTPs))
	assert.Equal(t, 1, len(metadata.References))
	assert.Equal(t, 2, len(metadata.CustomFields))
}

func TestCreateThreatRequest_ValidData(t *testing.T) {
	req := dto.CreateThreatRequest{
		Name:         "APT28",
		Severity:     "high",
		Description:  "Russian APT Group",
		Category:     "malware",
		Campaigns:    []string{"campaign1"},
		ThreatActors: []string{"Russia"},
		Confidence:   0.95,
		Tags:         []string{"apt", "russia"},
		Metadata: dto.ThreatMetadataDTO{
			TTPs:       []string{"T1087"},
			References: []string{"https://example.com"},
		},
	}

	assert.Equal(t, "APT28", req.Name)
	assert.Equal(t, "high", req.Severity)
	assert.Equal(t, "malware", req.Category)
	assert.Equal(t, float32(0.95), req.Confidence)
	assert.Equal(t, 2, len(req.Tags))
}

func TestCreateThreatRequest_MinimalData(t *testing.T) {
	req := dto.CreateThreatRequest{
		Name:     "Threat Name",
		Severity: "medium",
	}

	assert.Equal(t, "Threat Name", req.Name)
	assert.Equal(t, "medium", req.Severity)
	assert.Empty(t, req.Description)
	assert.Empty(t, req.Category)
}

func TestCreateThreatRequest_Validate(t *testing.T) {
	req := dto.CreateThreatRequest{
		Name:     "Test Threat",
		Severity: "high",
	}

	assert.Nil(t, req.Validate())
}

func TestBatchUpsertThreatsDTO_Valid(t *testing.T) {
	batch := dto.BatchUpsertThreatsDTO{
		Threats: []dto.CreateThreatRequest{
			{Name: "Threat1", Severity: "high"},
			{Name: "Threat2", Severity: "medium"},
		},
	}

	assert.Equal(t, 2, len(batch.Threats))
}

func TestDeleteThreatsDTO_Valid(t *testing.T) {
	deleteDTO := dto.DeleteThreatsDTO{
		IDs:    []string{"id1", "id2"},
		Reason: "Duplicate entry",
	}

	assert.Equal(t, 2, len(deleteDTO.IDs))
	assert.Equal(t, "Duplicate entry", deleteDTO.Reason)
}

func TestThreatFilter_CompleteFilter(t *testing.T) {
	isActive := true
	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now()

	filter := dto.ThreatFilter{
		SearchQuery: "query",
		Category:    "botnet",
		Severity:    "high",
		Campaign:    "campaign",
		ThreatActor: "actor",
		IsActive:    &isActive,
		StartDate:   &startDate,
		EndDate:     &endDate,
		Tags:        []string{"tag1"},
	}

	assert.Equal(t, "query", filter.SearchQuery)
	assert.Equal(t, "botnet", filter.Category)
	assert.True(t, *filter.IsActive)
}

func TestFindThreatsDTO_Complete(t *testing.T) {
	findDTO := dto.FindThreatsDTO{
		Pagination: dto.Pagination{Page: 1, PageSize: 25},
		Filter: dto.ThreatFilter{
			Category: "malware",
		},
		SortOptions: dto.SortOptions{
			SortBy: []string{"name"},
			Desc:   false,
		},
	}

	assert.Equal(t, int32(1), findDTO.Pagination.Page)
	assert.Equal(t, "malware", findDTO.Filter.Category)
}

func TestCorrelateThreatDTO_Valid(t *testing.T) {
	correlateDTO := dto.CorrelateThreatDTO{
		IoCID:         "550e8400-e29b-41d4-a716-446655440000",
		MinConfidence: 0.75,
	}

	assert.NotEmpty(t, correlateDTO.IoCID)
	assert.Equal(t, float32(0.75), correlateDTO.MinConfidence)
}

func TestLinkIoCsDTO_Valid(t *testing.T) {
	linkDTO := dto.LinkIoCsDTO{
		IoCIDs: []string{"id1", "id2", "id3"},
	}

	assert.Equal(t, 3, len(linkDTO.IoCIDs))
}

func TestLinkIoCsDTO_SingleIoC(t *testing.T) {
	linkDTO := dto.LinkIoCsDTO{
		IoCIDs: []string{"single-id"},
	}

	assert.Equal(t, 1, len(linkDTO.IoCIDs))
	assert.Equal(t, "single-id", linkDTO.IoCIDs[0])
}
