package handler

import (
	"strings"

	dto "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/dto"
	enrichmentpb "github.com/DgHnG36/ioc-enrich-system/shared/go/enrichment/v1"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Converter struct{}

func NewConverter() *Converter {
	return &Converter{}
}

/* IOC CONVERTERS */
func (c *Converter) ToPbIoC(ioc dto.CreateIoCRequest) *iocpb.IoC {
	return &iocpb.IoC{
		Type:        c.ToPbIoCType(ioc.Type),
		Value:       ioc.Value,
		Severity:    c.ToPbSeverity(ioc.Severity),
		Source:      ioc.Source,
		Description: ioc.Description,
		Tags:        ioc.Tags,
		Metadata:    c.ToPbIoCMetadata(ioc.Metadata),
	}
}

func (c *Converter) ToPbIoCType(iocType string) iocpb.IoCType {
	switch strings.ToLower(iocType) {
	case "ip":
		return iocpb.IoCType_IOC_TYPE_IP
	case "domain":
		return iocpb.IoCType_IOC_TYPE_DOMAIN
	case "url":
		return iocpb.IoCType_IOC_TYPE_URL
	case "md5":
		return iocpb.IoCType_IOC_TYPE_HASH_MD5
	case "sha1":
		return iocpb.IoCType_IOC_TYPE_HASH_SHA1
	case "sha256":
		return iocpb.IoCType_IOC_TYPE_HASH_SHA256
	case "file_path":
		return iocpb.IoCType_IOC_TYPE_FILE_PATH
	default:
		return iocpb.IoCType_IOC_TYPE_UNSPECIFIED
	}
}

func (c *Converter) ToPbSeverity(severity string) iocpb.Severity {
	switch strings.ToLower(severity) {
	case "info":
		return iocpb.Severity_SEVERITY_INFO
	case "low":
		return iocpb.Severity_SEVERITY_LOW
	case "medium":
		return iocpb.Severity_SEVERITY_MEDIUM
	case "high":
		return iocpb.Severity_SEVERITY_HIGH
	case "critical":
		return iocpb.Severity_SEVERITY_CRITICAL
	default:
		return iocpb.Severity_SEVERITY_UNSPECIFIED
	}
}

func (c *Converter) ToPbIoCMetadata(metadata map[string]any) *iocpb.IoCMetadata {
	if metadata == nil {
		return nil
	}

	customFieldsStructs, err := structpb.NewStruct(metadata)
	if err != nil {
		return &iocpb.IoCMetadata{}
	}
	return &iocpb.IoCMetadata{
		CustomFields: customFieldsStructs,
	}
}

func (c *Converter) ToPbRelationTypes(relationTypes []string) []iocpb.RelationType {
	pbRelationTypes := make([]iocpb.RelationType, 0, len(relationTypes))
	for _, rt := range relationTypes {
		pbRelationTypes = append(pbRelationTypes, c.ToPbRelationType(rt))
	}
	return pbRelationTypes
}

func (c *Converter) ToPbRelationType(relationType string) iocpb.RelationType {
	switch strings.ToLower(relationType) {
	case "same_campaign":
		return iocpb.RelationType_RELATION_TYPE_SAME_CAMPAIGN
	case "same_threat_actor":
		return iocpb.RelationType_RELATION_TYPE_SAME_THREAT_ACTOR
	case "same_family":
		return iocpb.RelationType_RELATION_TYPE_SAME_FAMILY
	case "resolves_to":
		return iocpb.RelationType_RELATION_TYPE_RESOLVES_TO
	case "communicates_with":
		return iocpb.RelationType_RELATION_TYPE_COMMUNICATES_WITH
	case "downloaded_from":
		return iocpb.RelationType_RELATION_TYPE_DOWNLOADED_FROM
	case "drops":
		return iocpb.RelationType_RELATION_TYPE_DROPS
	default:
		return iocpb.RelationType_RELATION_TYPE_UNSPECIFIED
	}
}

func (c *Converter) ToPbPagination(pagination *dto.Pagination) *iocpb.Pagination {
	if pagination == nil {
		return nil
	}
	return &iocpb.Pagination{
		Page:     pagination.Page,
		PageSize: pagination.PageSize,
	}
}

func (c *Converter) ToPbIoCFilter(filter *dto.IoCFilter) *iocpb.IoCFilter {
	if filter == nil {
		return nil
	}

	pbFilter := &iocpb.IoCFilter{
		SearchQuery:    filter.SearchQuery,
		Type:           c.ToPbIoCType(filter.Type),
		Severity:       c.ToPbSeverity(filter.Severity),
		Verdict:        c.ToPbVerdict(filter.Verdict),
		Source:         filter.Source,
		KillChainPhase: c.ToPbKillChainPhase(filter.KillChainPhase),
		Tags:           filter.Tags,
	}

	if filter.IsActive != nil {
		pbFilter.IsActive = *filter.IsActive
	}

	if filter.StartDate != nil {
		pbFilter.StartDate = timestamppb.New(*filter.StartDate)
	}

	if filter.EndDate != nil {
		pbFilter.EndDate = timestamppb.New(*filter.EndDate)
	}

	return pbFilter
}

func (c *Converter) ToPbVerdict(verdict string) iocpb.Verdict {
	switch strings.ToLower(verdict) {
	case "suspicious":
		return iocpb.Verdict_VERDICT_SUSPICIOUS
	case "malicious":
		return iocpb.Verdict_VERDICT_MALICIOUS
	case "benign":
		return iocpb.Verdict_VERDICT_BENIGN
	case "false_positive":
		return iocpb.Verdict_VERDICT_FALSE_POSITIVE
	default:
		return iocpb.Verdict_VERDICT_UNSPECIFIED
	}
}

func (c *Converter) ToPbKillChainPhase(phase string) iocpb.KillChainPhase {
	switch strings.ToLower(phase) {
	case "reconnaissance":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_RECONNAISSANCE
	case "weaponization":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_WEAPONIZATION
	case "delivery":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY
	case "exploitation":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_EXPLOITATION
	case "installation":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_INSTALLATION
	case "command_and_control":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_COMMAND_AND_CONTROL
	case "actions_on_objectives":
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_ACTIONS_ON_OBJECTIVES
	default:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_UNSPECIFIED
	}
}

/* THREAT CONVERTERS */
func (c *Converter) ToPbEnrichmentSources(sources []string) []enrichmentpb.EnrichmentSource {
	var pbSources []enrichmentpb.EnrichmentSource
	for _, s := range sources {
		pbSources = append(pbSources, c.ToPbEnrichmentSource(s))
	}
	return pbSources
}

func (c *Converter) ToPbEnrichmentSource(source string) enrichmentpb.EnrichmentSource {
	switch strings.ToLower(source) {
	case "virustotal":
		return enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_VIRUSTOTAL
	case "abuseipdb":
		return enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_ABUSEIPDB
	case "otx":
		return enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_OTX
	case "hybrid_analysis":
		return enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_HYBRID_ANALYSIS
	default:
		return enrichmentpb.EnrichmentSource_ENRICHMENT_SOURCE_UNSPECIFIED
	}
}

func (c *Converter) ToPbThreatCategory(category string) iocpb.ThreatCategory {
	switch strings.ToLower(category) {
	case "malware":
		return iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE
	case "botnet":
		return iocpb.ThreatCategory_THREAT_CATEGORY_BOTNET
	case "c2":
		return iocpb.ThreatCategory_THREAT_CATEGORY_C2
	case "exploit":
		return iocpb.ThreatCategory_THREAT_CATEGORY_EXPLOIT
	case "phishing":
		return iocpb.ThreatCategory_THREAT_CATEGORY_PHISHING
	case "spam":
		return iocpb.ThreatCategory_THREAT_CATEGORY_SPAM
	default:
		return iocpb.ThreatCategory_THREAT_CATEGORY_UNSPECIFIED
	}
}

func (c *Converter) ToPbCreateThreat(dto dto.CreateThreatRequest) *iocpb.Threat {
	return &iocpb.Threat{
		Name:         dto.Name,
		Severity:     c.ToPbSeverity(dto.Severity),
		Category:     c.ToPbThreatCategory(dto.Category),
		Campaigns:    dto.Campaigns,
		ThreatActors: dto.ThreatActors,
		Confidence:   dto.Confidence,
		Metadata:     c.ToPbThreatMetadata(&dto.Metadata),
		Description:  dto.Description,
		Tags:         dto.Tags,
	}
}

func (c *Converter) ToPbThreatMetadata(metadata *dto.ThreatMetadataDTO) *iocpb.ThreatMetadata {
	if metadata == nil {
		return nil
	}

	pbMetadata := &iocpb.ThreatMetadata{
		Ttps:       metadata.TTPs,
		References: metadata.References,
	}

	if metadata.CustomFields != nil {
		customFieldsStructs, err := structpb.NewStruct(metadata.CustomFields)
		if err == nil {
			pbMetadata.CustomFields = customFieldsStructs
		}
	}

	return pbMetadata
}

func (c *Converter) ToPbThreatFilter(filter *dto.ThreatFilter) *iocpb.ThreatFilter {
	if filter == nil {
		return nil
	}

	pbFilter := &iocpb.ThreatFilter{
		SearchQuery: filter.SearchQuery,
		Category:    c.ToPbThreatCategory(filter.Category),
		Severity:    c.ToPbSeverity(filter.Severity),
		Campaign:    filter.Campaign,
		ThreatActor: filter.ThreatActor,
	}

	if filter.IsActive != nil {
		pbFilter.IsActive = *filter.IsActive
	}

	if filter.StartDate != nil {
		pbFilter.StartDate = timestamppb.New(*filter.StartDate)
	}

	if filter.EndDate != nil {
		pbFilter.EndDate = timestamppb.New(*filter.EndDate)
	}

	return pbFilter
}
