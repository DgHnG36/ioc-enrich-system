package iocapigatewayunit

import (
	"testing"
	"time"

	dto "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/dto"
	handler "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/handler"
	enrichmentpb "github.com/DgHnG36/ioc-enrich-system/shared/go/enrichment/v1"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConverterForTest() *handler.Converter {
	return handler.NewConverter()
}

/* IOC TYPE CONVERTER TESTS */

func TestConverter_ToPbIoCType_IP(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("ip")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_IP, result)
}

func TestConverter_ToPbIoCType_Domain(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("domain")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_DOMAIN, result)
}

func TestConverter_ToPbIoCType_URL(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("url")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_URL, result)
}

func TestConverter_ToPbIoCType_MD5(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("md5")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_HASH_MD5, result)
}

func TestConverter_ToPbIoCType_SHA1(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("sha1")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_HASH_SHA1, result)
}

func TestConverter_ToPbIoCType_SHA256(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("sha256")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_HASH_SHA256, result)
}

func TestConverter_ToPbIoCType_FilePath(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("file_path")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_FILE_PATH, result)
}

func TestConverter_ToPbIoCType_CaseInsensitive(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("DOMAIN")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_DOMAIN, result)
}

func TestConverter_ToPbIoCType_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("invalid_type")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_UNSPECIFIED, result)
}

func TestConverter_ToPbIoCType_Empty(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCType("")

	assert.Equal(t, iocpb.IoCType_IOC_TYPE_UNSPECIFIED, result)
}

/* SEVERITY CONVERTER TESTS */

func TestConverter_ToPbSeverity_Info(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbSeverity("info")

	assert.Equal(t, iocpb.Severity_SEVERITY_INFO, result)
}

func TestConverter_ToPbSeverity_Low(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbSeverity("low")

	assert.Equal(t, iocpb.Severity_SEVERITY_LOW, result)
}

func TestConverter_ToPbSeverity_Medium(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbSeverity("medium")

	assert.Equal(t, iocpb.Severity_SEVERITY_MEDIUM, result)
}

func TestConverter_ToPbSeverity_High(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbSeverity("high")

	assert.Equal(t, iocpb.Severity_SEVERITY_HIGH, result)
}

func TestConverter_ToPbSeverity_CaseInsensitive(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbSeverity("HIGH")

	assert.Equal(t, iocpb.Severity_SEVERITY_HIGH, result)
}

func TestConverter_ToPbSeverity_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbSeverity("critical")

	assert.Equal(t, iocpb.Severity_SEVERITY_UNSPECIFIED, result)
}

/* IOC METADATA CONVERTER TESTS */

func TestConverter_ToPbIoCMetadata_ValidMetadata(t *testing.T) {
	converter := newConverterForTest()

	metadata := map[string]any{
		"country": "US",
		"asn":     12345,
	}

	result := converter.ToPbIoCMetadata(metadata)

	assert.NotNil(t, result)
	assert.NotNil(t, result.CustomFields)
}

func TestConverter_ToPbIoCMetadata_EmptyMetadata(t *testing.T) {
	converter := newConverterForTest()

	metadata := map[string]any{}

	result := converter.ToPbIoCMetadata(metadata)

	assert.NotNil(t, result)
	assert.NotNil(t, result.CustomFields)
}

func TestConverter_ToPbIoCMetadata_NilMetadata(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCMetadata(nil)

	assert.Nil(t, result)
}

/* IOC CONVERTER TESTS */

func TestConverter_ToPbIoC_Complete(t *testing.T) {
	converter := newConverterForTest()

	request := dto.CreateIoCRequest{
		Type:        "ip",
		Value:       "192.168.1.1",
		Severity:    "high",
		Source:      "virustotal",
		Description: "Malicious IP",
		Tags:        []string{"malware"},
		Metadata: map[string]any{
			"country": "unknown",
		},
	}

	result := converter.ToPbIoC(request)

	assert.NotNil(t, result)
	assert.Equal(t, iocpb.IoCType_IOC_TYPE_IP, result.Type)
	assert.Equal(t, "192.168.1.1", result.Value)
	assert.Equal(t, iocpb.Severity_SEVERITY_HIGH, result.Severity)
	assert.Equal(t, "virustotal", result.Source)
	assert.Equal(t, "Malicious IP", result.Description)
	assert.Equal(t, 1, len(result.Tags))
}

func TestConverter_ToPbIoC_MinimalData(t *testing.T) {
	converter := newConverterForTest()

	request := dto.CreateIoCRequest{
		Type:   "domain",
		Value:  "malicious.com",
		Source: "otx",
	}

	result := converter.ToPbIoC(request)

	assert.NotNil(t, result)
	assert.Equal(t, iocpb.IoCType_IOC_TYPE_DOMAIN, result.Type)
	assert.Equal(t, "malicious.com", result.Value)
	assert.Equal(t, "otx", result.Source)
}

/* RELATION TYPE CONVERTER TESTS */

func TestConverter_ToPbRelationType_SameCampaign(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("same_campaign")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_SAME_CAMPAIGN, result)
}

func TestConverter_ToPbRelationType_SameThreatActor(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("same_threat_actor")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_SAME_THREAT_ACTOR, result)
}

func TestConverter_ToPbRelationType_SameFamily(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("same_family")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_SAME_FAMILY, result)
}

func TestConverter_ToPbRelationType_ResolvesTo(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("resolves_to")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_RESOLVES_TO, result)
}

func TestConverter_ToPbRelationType_CommunicatesWith(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("communicates_with")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_COMMUNICATES_WITH, result)
}

func TestConverter_ToPbRelationType_DownloadedFrom(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("downloaded_from")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_DOWNLOADED_FROM, result)
}

func TestConverter_ToPbRelationType_Drops(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("drops")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_DROPS, result)
}

func TestConverter_ToPbRelationType_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationType("invalid_type")

	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_UNSPECIFIED, result)
}

func TestConverter_ToPbRelationTypes_Multiple(t *testing.T) {
	converter := newConverterForTest()

	relationTypes := []string{"same_campaign", "same_threat_actor", "same_family"}

	result := converter.ToPbRelationTypes(relationTypes)

	assert.Equal(t, 3, len(result))
	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_SAME_CAMPAIGN, result[0])
	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_SAME_THREAT_ACTOR, result[1])
	assert.Equal(t, iocpb.RelationType_RELATION_TYPE_SAME_FAMILY, result[2])
}

func TestConverter_ToPbRelationTypes_Empty(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbRelationTypes([]string{})

	assert.Equal(t, 0, len(result))
}

/* PAGINATION CONVERTER TESTS */

func TestConverter_ToPbPagination_Valid(t *testing.T) {
	converter := newConverterForTest()

	pagination := &dto.Pagination{
		Page:     1,
		PageSize: 20,
	}

	result := converter.ToPbPagination(pagination)

	assert.NotNil(t, result)
	assert.Equal(t, int32(1), result.Page)
	assert.Equal(t, int32(20), result.PageSize)
}

func TestConverter_ToPbPagination_Nil(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbPagination(nil)

	assert.Nil(t, result)
}

/* VERDICT CONVERTER TESTS */

func TestConverter_ToPbVerdict_Suspicious(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbVerdict("suspicious")

	assert.Equal(t, iocpb.Verdict_VERDICT_SUSPICIOUS, result)
}

func TestConverter_ToPbVerdict_Malicious(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbVerdict("malicious")

	assert.Equal(t, iocpb.Verdict_VERDICT_MALICIOUS, result)
}

func TestConverter_ToPbVerdict_Benign(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbVerdict("benign")

	assert.Equal(t, iocpb.Verdict_VERDICT_BENIGN, result)
}

func TestConverter_ToPbVerdict_FalsePositive(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbVerdict("false_positive")

	assert.Equal(t, iocpb.Verdict_VERDICT_FALSE_POSITIVE, result)
}

func TestConverter_ToPbVerdict_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbVerdict("unknown")

	assert.Equal(t, iocpb.Verdict_VERDICT_UNSPECIFIED, result)
}

/* KILL CHAIN PHASE CONVERTER TESTS */

func TestConverter_ToPbKillChainPhase_Reconnaissance(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("reconnaissance")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_RECONNAISSANCE, result)
}

func TestConverter_ToPbKillChainPhase_Weaponization(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("weaponization")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_WEAPONIZATION, result)
}

func TestConverter_ToPbKillChainPhase_Delivery(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("delivery")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY, result)
}

func TestConverter_ToPbKillChainPhase_Exploitation(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("exploitation")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_EXPLOITATION, result)
}

func TestConverter_ToPbKillChainPhase_Installation(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("installation")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_INSTALLATION, result)
}

func TestConverter_ToPbKillChainPhase_CommandAndControl(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("command_and_control")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_COMMAND_AND_CONTROL, result)
}

func TestConverter_ToPbKillChainPhase_ActionsOnObjectives(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("actions_on_objectives")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_ACTIONS_ON_OBJECTIVES, result)
}

func TestConverter_ToPbKillChainPhase_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbKillChainPhase("invalid_phase")

	assert.Equal(t, iocpb.KillChainPhase_KILL_CHAIN_PHASE_UNSPECIFIED, result)
}

/* IOC FILTER CONVERTER TESTS */

func TestConverter_ToPbIoCFilter_Complete(t *testing.T) {
	converter := newConverterForTest()

	startDate := time.Now().AddDate(0, -1, 0)
	endDate := time.Now()
	isActive := true

	filter := &dto.IoCFilter{
		SearchQuery:    "test",
		Type:           "ip",
		Severity:       "high",
		Verdict:        "malicious",
		Source:         "virustotal",
		KillChainPhase: "delivery",
		Tags:           []string{"apt"},
		IsActive:       &isActive,
		StartDate:      &startDate,
		EndDate:        &endDate,
	}

	result := converter.ToPbIoCFilter(filter)

	assert.NotNil(t, result)
	assert.Equal(t, "test", result.SearchQuery)
	assert.Equal(t, iocpb.IoCType_IOC_TYPE_IP, result.Type)
	assert.Equal(t, iocpb.Severity_SEVERITY_HIGH, result.Severity)
	assert.Equal(t, iocpb.Verdict_VERDICT_MALICIOUS, result.Verdict)
	assert.Equal(t, "virustotal", result.Source)
	assert.True(t, result.IsActive)
	assert.NotNil(t, result.StartDate)
	assert.NotNil(t, result.EndDate)
}

func TestConverter_ToPbIoCFilter_Nil(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbIoCFilter(nil)

	assert.Nil(t, result)
}

/* ENRICHMENT SOURCE CONVERTER TESTS */

func TestConverter_ToPbEnrichmentSource_Virustotal(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbEnrichmentSource("virustotal")

	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_VIRUSTOTAL, result)
}

func TestConverter_ToPbEnrichmentSource_AbuseIPDB(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbEnrichmentSource("abuseipdb")

	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_ABUSEIPDB, result)
}

func TestConverter_ToPbEnrichmentSource_OTX(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbEnrichmentSource("otx")

	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_OTX, result)
}

func TestConverter_ToPbEnrichmentSource_HybridAnalysis(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbEnrichmentSource("hybrid_analysis")

	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_HYBRID_ANALYSIS, result)
}

func TestConverter_ToPbEnrichmentSource_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbEnrichmentSource("invalid")

	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_UNSPECIFIED, result)
}

func TestConverter_ToPbEnrichmentSources_Multiple(t *testing.T) {
	converter := newConverterForTest()

	sources := []string{"virustotal", "otx", "abuseipdb"}

	result := converter.ToPbEnrichmentSources(sources)

	assert.Equal(t, 3, len(result))
	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_VIRUSTOTAL, result[0])
	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_OTX, result[1])
	assert.Equal(t, enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_ABUSEIPDB, result[2])
}

/* THREAT CATEGORY CONVERTER TESTS */

func TestConverter_ToPbThreatCategory_Malware(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("malware")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE, result)
}

func TestConverter_ToPbThreatCategory_Botnet(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("botnet")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_BOTNET, result)
}

func TestConverter_ToPbThreatCategory_C2(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("c2")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_C2, result)
}

func TestConverter_ToPbThreatCategory_Exploit(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("exploit")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_EXPLOIT, result)
}

func TestConverter_ToPbThreatCategory_Phishing(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("phishing")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_PHISHING, result)
}

func TestConverter_ToPbThreatCategory_Spam(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("spam")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_SPAM, result)
}

func TestConverter_ToPbThreatCategory_Invalid(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatCategory("unknown")

	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_UNSPECIFIED, result)
}

/* THREAT METADATA CONVERTER TESTS */

func TestConverter_ToPbThreatMetadata_Complete(t *testing.T) {
	converter := newConverterForTest()

	metadata := &dto.ThreatMetadataDTO{
		TTPs:       []string{"T1001", "T1002"},
		References: []string{"http://example.com"},
		CustomFields: map[string]any{
			"key": "value",
		},
	}

	result := converter.ToPbThreatMetadata(metadata)

	require.NotNil(t, result)
	assert.Equal(t, 2, len(result.Ttps))
	assert.Equal(t, 1, len(result.References))
	assert.NotNil(t, result.CustomFields)
}

func TestConverter_ToPbThreatMetadata_Nil(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatMetadata(nil)

	assert.Nil(t, result)
}

func TestConverter_ToPbThreatMetadata_NoCustomFields(t *testing.T) {
	converter := newConverterForTest()

	metadata := &dto.ThreatMetadataDTO{
		TTPs:       []string{"T1001"},
		References: []string{"http://example.com"},
	}

	result := converter.ToPbThreatMetadata(metadata)

	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Ttps))
}

/* THREAT CONVERTER TESTS */

func TestConverter_ToPbCreateThreat_Complete(t *testing.T) {
	converter := newConverterForTest()

	threatReq := dto.CreateThreatRequest{
		Name:         "APT28",
		Severity:     "high",
		Category:     "malware",
		Campaigns:    []string{"campaign1"},
		ThreatActors: []string{"Russia"},
		Confidence:   0.95,
		Description:  "Russian APT",
		Tags:         []string{"apt"},
		Metadata: dto.ThreatMetadataDTO{
			TTPs:       []string{"T1087"},
			References: []string{"http://example.com"},
		},
	}

	result := converter.ToPbCreateThreat(threatReq)

	assert.NotNil(t, result)
	assert.Equal(t, "APT28", result.Name)
	assert.Equal(t, iocpb.Severity_SEVERITY_HIGH, result.Severity)
	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE, result.Category)
	assert.Equal(t, 1, len(result.Campaigns))
	assert.Equal(t, 1, len(result.ThreatActors))
	assert.Equal(t, float32(0.95), result.Confidence)
	assert.Equal(t, "Russian APT", result.Description)
	assert.Equal(t, 1, len(result.Tags))
	assert.NotNil(t, result.Metadata)
}

func TestConverter_ToPbCreateThreat_Minimal(t *testing.T) {
	converter := newConverterForTest()

	threatReq := dto.CreateThreatRequest{
		Name:     "Threat",
		Severity: "medium",
	}

	result := converter.ToPbCreateThreat(threatReq)

	assert.NotNil(t, result)
	assert.Equal(t, "Threat", result.Name)
	assert.Equal(t, iocpb.Severity_SEVERITY_MEDIUM, result.Severity)
}

/* THREAT FILTER CONVERTER TESTS */

func TestConverter_ToPbThreatFilter_Complete(t *testing.T) {
	converter := newConverterForTest()

	startDate := time.Now().AddDate(-1, 0, 0)
	endDate := time.Now()
	isActive := true

	threatFilter := &dto.ThreatFilter{
		SearchQuery: "query",
		Category:    "malware",
		Severity:    "high",
		Campaign:    "campaign",
		ThreatActor: "actor",
		IsActive:    &isActive,
		StartDate:   &startDate,
		EndDate:     &endDate,
	}

	result := converter.ToPbThreatFilter(threatFilter)

	assert.NotNil(t, result)
	assert.Equal(t, "query", result.SearchQuery)
	assert.Equal(t, iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE, result.Category)
	assert.Equal(t, iocpb.Severity_SEVERITY_HIGH, result.Severity)
	assert.Equal(t, "campaign", result.Campaign)
	assert.Equal(t, "actor", result.ThreatActor)
	assert.True(t, result.IsActive)
	assert.NotNil(t, result.StartDate)
	assert.NotNil(t, result.EndDate)
}

func TestConverter_ToPbThreatFilter_Nil(t *testing.T) {
	converter := newConverterForTest()

	result := converter.ToPbThreatFilter(nil)

	assert.Nil(t, result)
}
