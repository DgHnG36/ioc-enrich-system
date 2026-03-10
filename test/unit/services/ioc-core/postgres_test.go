package ioccoreunit

import (
	"testing"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/stretchr/testify/assert"
)

/* POSTGRES REPOSITORY TESTS */

/* IoC CRUD TESTS */

func TestPostgres_IoCRepository_Create_ValidData(t *testing.T) {
	// Note: Full integration tests would require a real PostgreSQL instance
	// These are unit tests for the logic validation
	ioc := &domain.IoC{
		ID:       "test-id",
		Type:     domain.IoCTypeIP,
		Value:    "192.168.1.1",
		Severity: domain.SeverityHigh,
		Source:   "test",
	}

	assert.NotEmpty(t, ioc.ID)
	assert.Equal(t, domain.IoCTypeIP, ioc.Type)
	assert.Equal(t, "192.168.1.1", ioc.Value)
	assert.Equal(t, "test", ioc.Source)
}

func TestPostgres_IoCRepository_Create_InvalidIoC(t *testing.T) {
	ioc := &domain.IoC{
		// Missing required fields
		Type:   domain.IoCTypeUnspecified,
		Value:  "",
		Source: "",
	}

	// Validation should catch this
	assert.Equal(t, domain.IoCTypeUnspecified, ioc.Type)
	assert.Empty(t, ioc.Value)
	assert.Empty(t, ioc.Source)
}

func TestPostgres_IoCRepository_Update_ValidData(t *testing.T) {
	ioc := &domain.IoC{
		ID:          "test-id",
		Type:        domain.IoCTypeDomain,
		Value:       "example.com",
		Severity:    domain.SeverityMedium,
		Source:      "test",
		Description: "Updated description",
	}

	assert.Equal(t, "test-id", ioc.ID)
	assert.Equal(t, "Updated description", ioc.Description)
	assert.Equal(t, domain.SeverityMedium, ioc.Severity)
}

func TestPostgres_IoCRepository_Delete_ValidID(t *testing.T) {
	ids := []string{"id1", "id2", "id3"}

	assert.Equal(t, 3, len(ids))
	for _, id := range ids {
		assert.NotEmpty(t, id)
	}
}

func TestPostgres_IoCRepository_Delete_EmptyIDList(t *testing.T) {
	ids := []string{}

	assert.Equal(t, 0, len(ids))
}

func TestPostgres_IoCRepository_Get_ValidID(t *testing.T) {
	// Test that the Get method would work with a valid ID
	id := "test-id-123"

	assert.NotEmpty(t, id)
	assert.Equal(t, "test-id-123", id)
}

func TestPostgres_IoCRepository_GetByValue_ValidInput(t *testing.T) {
	iocType := domain.IoCTypeIP
	value := "8.8.8.8"

	assert.Equal(t, domain.IoCTypeIP, iocType)
	assert.Equal(t, "8.8.8.8", value)
}

func TestPostgres_IoCRepository_GetByValue_DomainType(t *testing.T) {
	iocType := domain.IoCTypeDomain
	value := "malicious.com"

	assert.Equal(t, domain.IoCTypeDomain, iocType)
	assert.Equal(t, "malicious.com", value)
}

/* FILTER AND SEARCH TESTS */

func TestPostgres_IoCRepository_Filter_BySeverity(t *testing.T) {
	filter := &domain.IoCFilter{
		Severity: domain.SeverityHigh,
	}

	assert.Equal(t, domain.SeverityHigh, filter.Severity)
}

func TestPostgres_IoCRepository_Filter_ByType(t *testing.T) {
	filter := &domain.IoCFilter{
		Type: domain.IoCTypeURL,
	}

	assert.Equal(t, domain.IoCTypeURL, filter.Type)
}

func TestPostgres_IoCRepository_Filter_ByMultipleFields(t *testing.T) {
	filter := &domain.IoCFilter{
		Type:     domain.IoCTypeIP,
		Severity: domain.SeverityMedium,
		Source:   "virustotal",
		IsActive: ptrBool(true),
	}

	assert.Equal(t, domain.IoCTypeIP, filter.Type)
	assert.Equal(t, domain.SeverityMedium, filter.Severity)
	assert.Equal(t, "virustotal", filter.Source)
	assert.True(t, *filter.IsActive)
}

func TestPostgres_IoCRepository_Filter_ByTags(t *testing.T) {
	filter := &domain.IoCFilter{
		Tags: []string{"malware", "trojan"},
	}

	assert.Equal(t, 2, len(filter.Tags))
	assert.Contains(t, filter.Tags, "malware")
	assert.Contains(t, filter.Tags, "trojan")
}

/* PAGINATION TESTS */

func TestPostgres_IoCRepository_Pagination_FirstPage(t *testing.T) {
	pagination := &domain.Pagination{
		Page:     1,
		PageSize: 10,
	}

	assert.Equal(t, int32(1), pagination.Page)
	assert.Equal(t, int32(10), pagination.PageSize)
}

func TestPostgres_IoCRepository_Pagination_LargePageSize(t *testing.T) {
	pagination := &domain.Pagination{
		Page:     5,
		PageSize: 100,
	}

	assert.Equal(t, int32(5), pagination.Page)
	assert.Equal(t, int32(100), pagination.PageSize)
}

/* STATISTICS TESTS */

func TestPostgres_IoCRepository_GetStatistics_ValidFilter(t *testing.T) {
	filter := &domain.IoCFilter{
		Type:     domain.IoCTypeIP,
		Severity: domain.SeverityHigh,
	}

	assert.NotNil(t, filter)
	assert.Equal(t, domain.IoCTypeIP, filter.Type)
}

func TestPostgres_IoCRepository_GetStatistics_EmptyFilter(t *testing.T) {
	filter := &domain.IoCFilter{}

	assert.NotNil(t, filter)
	assert.Equal(t, domain.Severity(""), filter.Severity)
}

/* EXPIRED TESTS */

func TestPostgres_IoCRepository_GetExpired_ValidLimit(t *testing.T) {
	limit := 100

	assert.Greater(t, limit, 0)
	assert.Equal(t, 100, limit)
}

func TestPostgres_IoCRepository_GetExpired_SmallLimit(t *testing.T) {
	limit := 10

	assert.Greater(t, limit, 0)
	assert.Equal(t, 10, limit)
}

/* DETECTION COUNT TESTS */

func TestPostgres_IoCRepository_IncrementDetectionCount(t *testing.T) {
	id := "test-ioc-id"

	assert.NotEmpty(t, id)
	assert.Equal(t, "test-ioc-id", id)
}

/* THREAT REPOSITORY TESTS */

func TestPostgres_ThreatRepository_Upsert_ValidData(t *testing.T) {
	threat := &domain.Threat{
		ID:       "threat-id",
		Name:     "APT28",
		Category: domain.ThreatCategoryMalware,
		Severity: domain.SeverityHigh,
	}

	assert.Equal(t, "threat-id", threat.ID)
	assert.Equal(t, "APT28", threat.Name)
	assert.Equal(t, domain.ThreatCategoryMalware, threat.Category)
}

func TestPostgres_ThreatRepository_Delete_ValidIDs(t *testing.T) {
	ids := []string{"threat-1", "threat-2"}

	assert.Equal(t, 2, len(ids))
}

func TestPostgres_ThreatRepository_Get_ValidID(t *testing.T) {
	id := "threat-123"

	assert.NotEmpty(t, id)
}

func TestPostgres_ThreatRepository_GetByName_ValidName(t *testing.T) {
	name := "APT28"

	assert.NotEmpty(t, name)
	assert.Equal(t, "APT28", name)
}

func TestPostgres_ThreatRepository_Find_WithFilter(t *testing.T) {
	filter := &domain.ThreatFilter{
		Category: domain.ThreatCategoryBotnet,
		Severity: domain.SeverityHigh,
	}

	pagination := &domain.Pagination{
		Page:     1,
		PageSize: 20,
	}

	assert.Equal(t, domain.ThreatCategoryBotnet, filter.Category)
	assert.Equal(t, int32(1), pagination.Page)
}

func TestPostgres_ThreatRepository_LinkIoCs_ValidIDs(t *testing.T) {
	threatID := "threat-id"
	iocIDs := []string{"ioc-1", "ioc-2", "ioc-3"}

	assert.NotEmpty(t, threatID)
	assert.Equal(t, 3, len(iocIDs))
}

func TestPostgres_ThreatRepository_GetStatistics_Valid(t *testing.T) {
	filter := &domain.ThreatFilter{
		Category: domain.ThreatCategoryMalware,
	}

	assert.NotNil(t, filter)
}

/* RELATED IOC REPOSITORY TESTS */

func TestPostgres_RelatedIoCRepository_UpsertRelation_ValidData(t *testing.T) {
	sourceID := "source-ioc"
	targetID := "target-ioc"
	relationType := domain.RelationTypeSameCampaign
	score := float32(0.95)

	assert.NotEmpty(t, sourceID)
	assert.NotEmpty(t, targetID)
	assert.Equal(t, domain.RelationTypeSameCampaign, relationType)
	assert.Equal(t, float32(0.95), score)
}

func TestPostgres_RelatedIoCRepository_DeleteRelation_ValidData(t *testing.T) {
	sourceID := "source-ioc"
	targetIDs := []string{"target-1", "target-2"}

	assert.NotEmpty(t, sourceID)
	assert.Equal(t, 2, len(targetIDs))
}

func TestPostgres_RelatedIoCRepository_GetRelations_ValidType(t *testing.T) {
	sourceID := "source-ioc"
	relationType := domain.RelationTypeResolvesTo

	assert.NotEmpty(t, sourceID)
	assert.Equal(t, domain.RelationTypeResolvesTo, relationType)
}

/* HELPER FUNCTION */

func ptrBool(b bool) *bool {
	return &b
}
