package handler

import (
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Converter struct{}

func NewConverter() *Converter {
	return &Converter{}
}

/* PB TO DOMAIN */
func (c *Converter) ToDomainBatchIoC(pbIoCs []*iocpb.IoC) []*domain.IoC {
	if pbIoCs == nil {
		return nil
	}

	domainIoCs := make([]*domain.IoC, 0, len(pbIoCs))
	for _, pbIoC := range pbIoCs {
		domainIoCs = append(domainIoCs, c.ToDomainIoC(pbIoC))
	}
	return domainIoCs
}

func (c *Converter) ToDomainIoC(pbIoC *iocpb.IoC) *domain.IoC {
	if pbIoC == nil {
		return nil
	}
	var createdAt, updatedAt time.Time
	var expiresAt *time.Time

	if pbIoC.CreatedAt != nil {
		createdAt = pbIoC.CreatedAt.AsTime()
	}
	if pbIoC.UpdatedAt != nil {
		updatedAt = pbIoC.UpdatedAt.AsTime()
	}
	if pbIoC.ExpiresAt != nil {
		t := pbIoC.ExpiresAt.AsTime()
		expiresAt = &t
	}

	return &domain.IoC{
		ID:                pbIoC.GetId(),
		Type:              c.ToDomainIoCType(pbIoC.GetType()),
		Value:             pbIoC.GetValue(),
		Verdict:           c.ToDomainVerdict(pbIoC.GetVerdict()),
		Severity:          c.ToDomainSeverity(pbIoC.GetSeverity()),
		Source:            pbIoC.GetSource(),
		Description:       pbIoC.GetDescription(),
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
		ExpiresAt:         expiresAt,
		Tags:              pbIoC.GetTags(),
		ThreatContext:     c.ToDomainThreatContext(pbIoC.GetThreatContext()),
		EnrichmentSummary: c.ToDomainEnrichmentSummary(pbIoC.GetEnrichmentSummary()),
		Metadata:          c.ToDomainIoCMetadata(pbIoC.GetMetadata()),
		IsActive:          pbIoC.GetIsActive(),
		DetectionCount:    pbIoC.GetDetectionCount(),
	}
}

func (c *Converter) ToDomainIoCType(pbIoCType iocpb.IoCType) domain.IoCType {
	switch pbIoCType {
	case iocpb.IoCType_IOC_TYPE_IP:
		return domain.IoCTypeIP
	case iocpb.IoCType_IOC_TYPE_DOMAIN:
		return domain.IoCTypeDomain
	case iocpb.IoCType_IOC_TYPE_URL:
		return domain.IoCTypeURL
	case iocpb.IoCType_IOC_TYPE_HASH_MD5:
		return domain.IoCTypeHashMD5
	case iocpb.IoCType_IOC_TYPE_HASH_SHA1:
		return domain.IoCTypeHashSHA1
	case iocpb.IoCType_IOC_TYPE_HASH_SHA256:
		return domain.IoCTypeHashSHA256
	case iocpb.IoCType_IOC_TYPE_FILE_PATH:
		return domain.IoCTypeFilePath
	default:
		return domain.IoCTypeUnspecified
	}
}

func (c *Converter) ToDomainVerdict(pbVerdict iocpb.Verdict) domain.Verdict {
	switch pbVerdict {
	case iocpb.Verdict_VERDICT_MALICIOUS:
		return domain.VerdictMalicious
	case iocpb.Verdict_VERDICT_SUSPICIOUS:
		return domain.VerdictSuspicious
	case iocpb.Verdict_VERDICT_BENIGN:
		return domain.VerdictBenign
	case iocpb.Verdict_VERDICT_FALSE_POSITIVE:
		return domain.VerdictFalsePositive
	default:
		return domain.VerdictUnknown
	}
}

func (c *Converter) ToDomainSeverity(pbSeverity iocpb.Severity) domain.Severity {
	switch pbSeverity {
	case iocpb.Severity_SEVERITY_INFO:
		return domain.SeverityInfo
	case iocpb.Severity_SEVERITY_LOW:
		return domain.SeverityLow
	case iocpb.Severity_SEVERITY_MEDIUM:
		return domain.SeverityMedium
	case iocpb.Severity_SEVERITY_HIGH:
		return domain.SeverityHigh
	case iocpb.Severity_SEVERITY_CRITICAL:
		return domain.SeverityCritical
	default:
		return domain.SeverityUnspecified
	}
}

func (c *Converter) ToDomainThreatContext(pbThreatContext *iocpb.ThreatContext) *domain.ThreatContext {
	if pbThreatContext == nil {
		return nil
	}

	domainCategories := make([]domain.ThreatCategory, 0, len(pbThreatContext.GetCategories()))
	for _, pbCategory := range pbThreatContext.GetCategories() {
		domainCategories = append(domainCategories, c.ToDomainThreatCategory(pbCategory))
	}

	return &domain.ThreatContext{
		ConfidenceScore: pbThreatContext.GetConfidenceScore(),
		Categories:      domainCategories,
		KillChainPhase:  c.ToDomainKillChainPhase(pbThreatContext.GetKillChainPhase()),
		ThreatActors:    pbThreatContext.GetThreatActors(),
		Campaigns:       pbThreatContext.GetCampaigns(),
	}
}

func (c *Converter) ToDomainEnrichmentSummary(pbEnrichmentSummary *iocpb.EnrichmentSummary) *domain.EnrichmentSummary {
	if pbEnrichmentSummary == nil {
		return nil
	}

	var lastEnriched time.Time
	if pbEnrichmentSummary.LastEnriched != nil {
		lastEnriched = pbEnrichmentSummary.LastEnriched.AsTime()
	}

	sourceDetails := make(map[string]*domain.SourceResult)
	for key, pbSourceResult := range pbEnrichmentSummary.GetSourceDetails() {
		sourceDetails[key] = c.ToDomainSourceResult(pbSourceResult)
	}

	return &domain.EnrichmentSummary{
		TotalSources:    pbEnrichmentSummary.GetTotalSources(),
		MaliciousCount:  pbEnrichmentSummary.GetMaliciousCount(),
		SuspiciousCount: pbEnrichmentSummary.GetSuspiciousCount(),
		BenignCount:     pbEnrichmentSummary.GetBenignCount(),
		LastEnriched:    lastEnriched,
		SourceDetails:   sourceDetails,
	}
}

func (c *Converter) ToDomainIoCMetadata(pbMetadata *iocpb.IoCMetadata) *domain.IoCMetadata {
	if pbMetadata == nil {
		return nil
	}

	domainMd := &domain.IoCMetadata{
		CreatedBy: pbMetadata.GetCreatedBy(),
		UpdatedBy: pbMetadata.GetUpdatedBy(),
	}

	if pbMetadata.CustomFields != nil {
		domainMd.CustomFields = pbMetadata.GetCustomFields().AsMap()
	}

	return domainMd
}

func (c *Converter) ToDomainThreatCategory(pbCategory iocpb.ThreatCategory) domain.ThreatCategory {
	switch pbCategory {
	case iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE:
		return domain.ThreatCategoryMalware
	case iocpb.ThreatCategory_THREAT_CATEGORY_EXPLOIT:
		return domain.ThreatCategoryExploit
	case iocpb.ThreatCategory_THREAT_CATEGORY_BOTNET:
		return domain.ThreatCategoryBotnet
	case iocpb.ThreatCategory_THREAT_CATEGORY_C2:
		return domain.ThreatCategoryC2
	case iocpb.ThreatCategory_THREAT_CATEGORY_PHISHING:
		return domain.ThreatCategoryPhishing
	case iocpb.ThreatCategory_THREAT_CATEGORY_SPAM:
		return domain.ThreatCategorySpam
	default:
		return domain.ThreatCategoryUnspecified
	}
}

func (c *Converter) ToDomainKillChainPhase(pbKillChainPhase iocpb.KillChainPhase) domain.KillChainPhase {
	switch pbKillChainPhase {
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_RECONNAISSANCE:
		return domain.PhaseReconnaissance
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_WEAPONIZATION:
		return domain.PhaseWeaponization
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY:
		return domain.PhaseDelivery
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_EXPLOITATION:
		return domain.PhaseExploitation
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_INSTALLATION:
		return domain.PhaseInstallation
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_COMMAND_AND_CONTROL:
		return domain.PhaseC2
	case iocpb.KillChainPhase_KILL_CHAIN_PHASE_ACTIONS_ON_OBJECTIVES:
		return domain.PhaseActions
	default:
		return domain.PhaseUnspecified
	}
}

func (c *Converter) ToDomainSourceResult(pbSourceResult *iocpb.SourceResult) *domain.SourceResult {
	if pbSourceResult == nil {
		return nil
	}

	var checkedAt time.Time
	var rawData map[string]interface{}
	if pbSourceResult.GetCheckedAt() != nil {
		checkedAt = pbSourceResult.GetCheckedAt().AsTime()
	}

	if pbSourceResult.GetRawData() != nil {
		rawData = pbSourceResult.GetRawData().AsMap()
	}

	return &domain.SourceResult{
		SourceName:  pbSourceResult.GetSourceName(),
		IsMalicious: pbSourceResult.GetIsMalicious(),
		Score:       pbSourceResult.GetScore(),
		Verdict:     pbSourceResult.GetVerdict(),
		CheckedAt:   checkedAt,
		RawData:     rawData,
	}
}

func (c *Converter) ToDomainRelatedIoC(pbRelated *iocpb.RelatedIoC) *domain.RelatedIoC {
	if pbRelated == nil {
		return nil
	}

	return &domain.RelatedIoC{
		IoCID:           pbRelated.GetIocId(),
		Value:           pbRelated.GetValue(),
		Type:            c.ToDomainIoCType(pbRelated.GetType()),
		RelationType:    c.ToDomainRelationType(pbRelated.GetRelationType()),
		SimilarityScore: pbRelated.GetSimilarityScore(),
	}
}

func (c *Converter) ToDomainRelationType(pbRelationType iocpb.RelationType) domain.RelationType {
	switch pbRelationType {
	case iocpb.RelationType_RELATION_TYPE_COMMUNICATES_WITH:
		return domain.RelationTypeCommunicatesWith
	case iocpb.RelationType_RELATION_TYPE_DOWNLOADED_FROM:
		return domain.RelationTypeDownloadedFrom
	case iocpb.RelationType_RELATION_TYPE_DROPS:
		return domain.RelationTypeDrops
	case iocpb.RelationType_RELATION_TYPE_SAME_CAMPAIGN:
		return domain.RelationTypeSameCampaign
	case iocpb.RelationType_RELATION_TYPE_SAME_THREAT_ACTOR:
		return domain.RelationTypeSameThreatActor
	case iocpb.RelationType_RELATION_TYPE_SAME_FAMILY:
		return domain.RelationTypeSameFamily
	default:
		return domain.RelationTypeUnspecified
	}
}

func (c *Converter) ToDomainPagination(pbPagination *iocpb.Pagination) *domain.Pagination {
	if pbPagination == nil {
		return nil
	}
	return &domain.Pagination{
		Page:       pbPagination.GetPage(),
		PageSize:   pbPagination.GetPageSize(),
		TotalCount: pbPagination.GetTotalCount(),
		TotalPages: pbPagination.GetTotalPages(),
	}
}

func (c *Converter) ToDomainIoCFilter(pbFilter *iocpb.IoCFilter) *domain.IoCFilter {
	if pbFilter == nil {
		return nil
	}

	var startDate, endDate *time.Time
	var isActive *bool
	if pbFilter.GetStartDate() != nil {
		t := pbFilter.GetStartDate().AsTime()
		startDate = &t
	}
	if pbFilter.GetEndDate() != nil {
		t := pbFilter.GetEndDate().AsTime()
		endDate = &t
	}
	boolean := pbFilter.GetIsActive()
	isActive = &boolean

	return &domain.IoCFilter{
		SearchQuery:    pbFilter.GetSearchQuery(),
		Type:           c.ToDomainIoCType(pbFilter.GetType()),
		Severity:       c.ToDomainSeverity(pbFilter.GetSeverity()),
		Verdict:        c.ToDomainVerdict(pbFilter.GetVerdict()),
		Source:         pbFilter.GetSource(),
		Tags:           pbFilter.GetTags(),
		KillChainPhase: c.ToDomainKillChainPhase(pbFilter.GetKillChainPhase()),
		IsActive:       isActive,
		StartDate:      startDate,
		EndDate:        endDate,
	}
}

func (c *Converter) ToDomainBatchThreats(pbThreats []*iocpb.Threat) []*domain.Threat {
	if pbThreats == nil {
		return nil
	}
	domainThreats := make([]*domain.Threat, 0, len(pbThreats))
	for _, pbThreat := range pbThreats {
		domainThreats = append(domainThreats, c.ToDomainThreat(pbThreat))
	}
	return domainThreats
}

func (c *Converter) ToDomainThreat(pbThreat *iocpb.Threat) *domain.Threat {
	if pbThreat == nil {
		return nil
	}

	var createdAt, updatedAt time.Time
	if pbThreat.CreatedAt != nil {
		createdAt = pbThreat.CreatedAt.AsTime()
	}
	if pbThreat.UpdatedAt != nil {
		updatedAt = pbThreat.UpdatedAt.AsTime()
	}

	return &domain.Threat{
		ID:           pbThreat.GetId(),
		Name:         pbThreat.GetName(),
		Description:  pbThreat.GetDescription(),
		Category:     c.ToDomainThreatCategory(pbThreat.GetCategory()),
		Severity:     c.ToDomainSeverity(pbThreat.GetSeverity()),
		Indicators:   nil,
		ThreatActors: pbThreat.GetThreatActors(),
		Campaigns:    pbThreat.GetCampaigns(),
		Confidence:   pbThreat.GetConfidence(),
		Metadata:     c.ToDomainThreatMetadata(pbThreat.GetMetadata()),
		Tags:         pbThreat.GetTags(),
		IsActive:     pbThreat.GetIsActive(),
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}
}

func (c *Converter) ToDomainThreatFilter(pbFilter *iocpb.ThreatFilter) *domain.ThreatFilter {
	if pbFilter == nil {
		return nil
	}

	var startDate, endDate *time.Time
	if pbFilter.GetStartDate() != nil {
		t := pbFilter.GetStartDate().AsTime()
		startDate = &t
	}
	if pbFilter.GetEndDate() != nil {
		t := pbFilter.GetEndDate().AsTime()
		endDate = &t
	}
	boolean := pbFilter.GetIsActive()
	isActive := &boolean

	return &domain.ThreatFilter{
		SearchQuery: pbFilter.GetSearchQuery(),
		Category:    c.ToDomainThreatCategory(pbFilter.GetCategory()),
		Severity:    c.ToDomainSeverity(pbFilter.GetSeverity()),
		Campaign:    pbFilter.GetCampaign(),
		ThreatActor: pbFilter.GetThreatActor(),
		IsActive:    isActive,
		StartDate:   startDate,
		EndDate:     endDate,
	}
}

func (c *Converter) ToDomainThreatMetadata(pbMetadata *iocpb.ThreatMetadata) *domain.ThreatMetadata {
	if pbMetadata == nil {
		return nil
	}
	domainMd := &domain.ThreatMetadata{
		CreatedBy: pbMetadata.GetCreatedBy(),
		UpdatedBy: pbMetadata.GetUpdatedBy(),
	}
	if pbMetadata.CustomFields != nil {
		domainMd.CustomFields = pbMetadata.GetCustomFields().AsMap()
	}
	return domainMd
}

/* DOMAIN TO PB */
func (c *Converter) ToPbBatchIoCs(domainIoCs []*domain.IoC) []*iocpb.IoC {
	if domainIoCs == nil {
		return nil
	}
	pbIoCs := make([]*iocpb.IoC, 0, len(domainIoCs))
	for _, domainIoC := range domainIoCs {
		pbIoCs = append(pbIoCs, c.ToPbIoC(domainIoC))
	}
	return pbIoCs
}

func (c *Converter) ToPbIoC(domainIoC *domain.IoC) *iocpb.IoC {
	if domainIoC == nil {
		return nil
	}

	pbIoC := &iocpb.IoC{
		Id:                domainIoC.ID,
		Type:              c.ToPbIoCType(domainIoC.Type),
		Value:             domainIoC.Value,
		Verdict:           c.ToPbVerdict(domainIoC.Verdict),
		Severity:          c.ToPbSeverity(domainIoC.Severity),
		Source:            domainIoC.Source,
		Description:       domainIoC.Description,
		Tags:              domainIoC.Tags,
		ThreatContext:     c.ToPbThreatContext(domainIoC.ThreatContext),
		EnrichmentSummary: c.ToPbEnrichmentSummary(domainIoC.EnrichmentSummary),
		Metadata:          c.ToPbIoCMetadata(domainIoC.Metadata),
		IsActive:          domainIoC.IsActive,
		DetectionCount:    domainIoC.DetectionCount,
	}

	if !domainIoC.CreatedAt.IsZero() {
		pbIoC.CreatedAt = timestamppb.New(domainIoC.CreatedAt)
	}
	if !domainIoC.UpdatedAt.IsZero() {
		pbIoC.UpdatedAt = timestamppb.New(domainIoC.UpdatedAt)
	}
	if domainIoC.ExpiresAt != nil && !domainIoC.ExpiresAt.IsZero() {
		pbIoC.ExpiresAt = timestamppb.New(*domainIoC.ExpiresAt)
	}

	return pbIoC
}

func (c *Converter) ToPbIoCType(domainIoCType domain.IoCType) iocpb.IoCType {
	switch domainIoCType {
	case domain.IoCTypeIP:
		return iocpb.IoCType_IOC_TYPE_IP
	case domain.IoCTypeDomain:
		return iocpb.IoCType_IOC_TYPE_DOMAIN
	case domain.IoCTypeURL:
		return iocpb.IoCType_IOC_TYPE_URL
	case domain.IoCTypeHashMD5:
		return iocpb.IoCType_IOC_TYPE_HASH_MD5
	case domain.IoCTypeHashSHA1:
		return iocpb.IoCType_IOC_TYPE_HASH_SHA1
	case domain.IoCTypeHashSHA256:
		return iocpb.IoCType_IOC_TYPE_HASH_SHA256
	case domain.IoCTypeFilePath:
		return iocpb.IoCType_IOC_TYPE_FILE_PATH
	default:
		return iocpb.IoCType_IOC_TYPE_UNSPECIFIED
	}
}

func (c *Converter) ToPbVerdict(domainVerdict domain.Verdict) iocpb.Verdict {
	switch domainVerdict {
	case domain.VerdictMalicious:
		return iocpb.Verdict_VERDICT_MALICIOUS
	case domain.VerdictSuspicious:
		return iocpb.Verdict_VERDICT_SUSPICIOUS
	case domain.VerdictBenign:
		return iocpb.Verdict_VERDICT_BENIGN
	case domain.VerdictFalsePositive:
		return iocpb.Verdict_VERDICT_FALSE_POSITIVE
	default:
		return iocpb.Verdict_VERDICT_UNKNOWN
	}
}

func (c *Converter) ToPbSeverity(domainSeverity domain.Severity) iocpb.Severity {
	switch domainSeverity {
	case domain.SeverityInfo:
		return iocpb.Severity_SEVERITY_INFO
	case domain.SeverityLow:
		return iocpb.Severity_SEVERITY_LOW
	case domain.SeverityMedium:
		return iocpb.Severity_SEVERITY_MEDIUM
	case domain.SeverityHigh:
		return iocpb.Severity_SEVERITY_HIGH
	case domain.SeverityCritical:
		return iocpb.Severity_SEVERITY_CRITICAL
	default:
		return iocpb.Severity_SEVERITY_UNSPECIFIED
	}
}

func (c *Converter) ToPbThreatContext(domainThreatContext *domain.ThreatContext) *iocpb.ThreatContext {
	if domainThreatContext == nil {
		return nil
	}

	pbCategories := make([]iocpb.ThreatCategory, 0, len(domainThreatContext.Categories))
	for _, domainCategory := range domainThreatContext.Categories {
		pbCategories = append(pbCategories, c.ToPbThreatCategory(domainCategory))
	}
	return &iocpb.ThreatContext{
		Categories:      pbCategories,
		ConfidenceScore: domainThreatContext.ConfidenceScore,
		KillChainPhase:  c.ToPbKillChainPhase(domainThreatContext.KillChainPhase),
		ThreatActors:    domainThreatContext.ThreatActors,
		Campaigns:       domainThreatContext.Campaigns,
	}
}

func (c *Converter) ToPbEnrichmentSummary(domainEnrichmentSummary *domain.EnrichmentSummary) *iocpb.EnrichmentSummary {
	if domainEnrichmentSummary == nil {
		return nil
	}

	sourceDetails := make(map[string]*iocpb.SourceResult)
	for key, domainSourceResult := range domainEnrichmentSummary.SourceDetails {
		sourceDetails[key] = c.ToPbSourceResult(domainSourceResult)
	}

	return &iocpb.EnrichmentSummary{
		TotalSources:    domainEnrichmentSummary.TotalSources,
		MaliciousCount:  domainEnrichmentSummary.MaliciousCount,
		SuspiciousCount: domainEnrichmentSummary.SuspiciousCount,
		BenignCount:     domainEnrichmentSummary.BenignCount,
		LastEnriched:    timestamppb.New(domainEnrichmentSummary.LastEnriched),
		SourceDetails:   sourceDetails,
	}
}

func (c *Converter) ToPbIoCMetadata(domainMetadata *domain.IoCMetadata) *iocpb.IoCMetadata {
	if domainMetadata == nil {
		return nil
	}
	pbMetadata := &iocpb.IoCMetadata{
		CreatedBy: domainMetadata.CreatedBy,
		UpdatedBy: domainMetadata.UpdatedBy,
	}
	if domainMetadata.CustomFields != nil {
		pbStruct, err := structpb.NewStruct(domainMetadata.CustomFields)
		if err == nil {
			pbMetadata.CustomFields = pbStruct
		} else {
			pbMetadata.CustomFields = &structpb.Struct{}
		}
	}
	return pbMetadata
}

func (c *Converter) ToPbThreatCategory(domainCategory domain.ThreatCategory) iocpb.ThreatCategory {
	switch domainCategory {
	case domain.ThreatCategoryMalware:
		return iocpb.ThreatCategory_THREAT_CATEGORY_MALWARE
	case domain.ThreatCategoryExploit:
		return iocpb.ThreatCategory_THREAT_CATEGORY_EXPLOIT
	case domain.ThreatCategoryBotnet:
		return iocpb.ThreatCategory_THREAT_CATEGORY_BOTNET
	case domain.ThreatCategoryC2:
		return iocpb.ThreatCategory_THREAT_CATEGORY_C2
	case domain.ThreatCategoryPhishing:
		return iocpb.ThreatCategory_THREAT_CATEGORY_PHISHING
	case domain.ThreatCategorySpam:
		return iocpb.ThreatCategory_THREAT_CATEGORY_SPAM
	default:
		return iocpb.ThreatCategory_THREAT_CATEGORY_UNSPECIFIED
	}
}

func (c *Converter) ToPbKillChainPhase(domainKillChainPhase domain.KillChainPhase) iocpb.KillChainPhase {
	switch domainKillChainPhase {
	case domain.PhaseReconnaissance:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_RECONNAISSANCE
	case domain.PhaseWeaponization:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_WEAPONIZATION
	case domain.PhaseDelivery:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY
	case domain.PhaseExploitation:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_EXPLOITATION
	case domain.PhaseInstallation:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_INSTALLATION
	case domain.PhaseC2:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_COMMAND_AND_CONTROL
	case domain.PhaseActions:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_ACTIONS_ON_OBJECTIVES
	default:
		return iocpb.KillChainPhase_KILL_CHAIN_PHASE_UNSPECIFIED
	}
}

func (c *Converter) ToPbSourceResult(domainSourceResult *domain.SourceResult) *iocpb.SourceResult {
	if domainSourceResult == nil {
		return nil
	}

	pbSourceResult := &iocpb.SourceResult{
		SourceName:  domainSourceResult.SourceName,
		IsMalicious: domainSourceResult.IsMalicious,
		Score:       domainSourceResult.Score,
		Verdict:     domainSourceResult.Verdict,
	}

	if !domainSourceResult.CheckedAt.IsZero() {
		pbSourceResult.CheckedAt = timestamppb.New(domainSourceResult.CheckedAt)
	}

	if domainSourceResult.RawData != nil {
		pbStruct, err := structpb.NewStruct(domainSourceResult.RawData)
		if err == nil {
			pbSourceResult.RawData = pbStruct
		} else {
			pbSourceResult.RawData = &structpb.Struct{}
		}
	}

	return pbSourceResult
}

func (c *Converter) ToPbRelatedIoCs(domainRelatedIoCs []*domain.RelatedIoC) []*iocpb.RelatedIoC {
	if domainRelatedIoCs == nil {
		return nil
	}
	pbRelatedIoCs := make([]*iocpb.RelatedIoC, 0, len(domainRelatedIoCs))
	for _, domainRelated := range domainRelatedIoCs {
		pbRelatedIoCs = append(pbRelatedIoCs, &iocpb.RelatedIoC{
			IocId:           domainRelated.IoCID,
			Value:           domainRelated.Value,
			Type:            c.ToPbIoCType(domainRelated.Type),
			RelationType:    c.ToPbRelationType(domainRelated.RelationType),
			SimilarityScore: domainRelated.SimilarityScore,
		})
	}
	return pbRelatedIoCs
}

func (c *Converter) ToPbRelationType(domainRelationType domain.RelationType) iocpb.RelationType {
	switch domainRelationType {
	case domain.RelationTypeCommunicatesWith:
		return iocpb.RelationType_RELATION_TYPE_COMMUNICATES_WITH
	case domain.RelationTypeDownloadedFrom:
		return iocpb.RelationType_RELATION_TYPE_DOWNLOADED_FROM
	case domain.RelationTypeDrops:
		return iocpb.RelationType_RELATION_TYPE_DROPS
	case domain.RelationTypeSameCampaign:
		return iocpb.RelationType_RELATION_TYPE_SAME_CAMPAIGN
	case domain.RelationTypeSameThreatActor:
		return iocpb.RelationType_RELATION_TYPE_SAME_THREAT_ACTOR
	case domain.RelationTypeSameFamily:
		return iocpb.RelationType_RELATION_TYPE_SAME_FAMILY
	default:
		return iocpb.RelationType_RELATION_TYPE_UNSPECIFIED
	}
}

func (c *Converter) ToPbPagination(domainPagination *domain.Pagination) *iocpb.Pagination {
	if domainPagination == nil {
		return nil
	}
	return &iocpb.Pagination{
		Page:       domainPagination.Page,
		PageSize:   domainPagination.PageSize,
		TotalCount: domainPagination.TotalCount,
		TotalPages: domainPagination.TotalPages,
	}
}

func (c *Converter) ToPbIoCFilter(domainFilter *domain.IoCFilter) *iocpb.IoCFilter {
	if domainFilter == nil {
		return nil
	}

	var startDate, endDate *timestamppb.Timestamp
	if domainFilter.StartDate != nil && !domainFilter.StartDate.IsZero() {
		startDate = timestamppb.New(*domainFilter.StartDate)
	}

	if domainFilter.EndDate != nil && !domainFilter.EndDate.IsZero() {
		endDate = timestamppb.New(*domainFilter.EndDate)
	}

	return &iocpb.IoCFilter{
		SearchQuery:    domainFilter.SearchQuery,
		Type:           c.ToPbIoCType(domainFilter.Type),
		Severity:       c.ToPbSeverity(domainFilter.Severity),
		Verdict:        c.ToPbVerdict(domainFilter.Verdict),
		Source:         domainFilter.Source,
		Tags:           domainFilter.Tags,
		KillChainPhase: c.ToPbKillChainPhase(domainFilter.KillChainPhase),
		IsActive:       domainFilter.IsActive != nil && *domainFilter.IsActive,
		StartDate:      startDate,
		EndDate:        endDate,
	}
}

func (c *Converter) ToPbIoCStatistics(domainStats *domain.IoCStatistics) *iocpb.IoCStatistics {
	if domainStats == nil {
		return nil
	}

	var generatedAt *timestamppb.Timestamp
	if !domainStats.GeneratedAt.IsZero() {
		generatedAt = timestamppb.New(domainStats.GeneratedAt)
	}

	return &iocpb.IoCStatistics{
		TotalIocs:   domainStats.TotalIoCs,
		ActiveIocs:  domainStats.ActiveIoCs,
		ByType:      domainStats.ByType,
		BySeverity:  domainStats.BySeverity,
		ByVerdict:   domainStats.ByVerdict,
		GeneratedAt: generatedAt,
	}
}

func (c *Converter) ToPbBatchThreats(domainThreats []*domain.Threat) []*iocpb.Threat {
	if domainThreats == nil {
		return nil
	}
	pbThreats := make([]*iocpb.Threat, 0, len(domainThreats))
	for _, domainThreat := range domainThreats {
		pbThreats = append(pbThreats, c.ToPbThreat(domainThreat))
	}
	return pbThreats
}

func (c *Converter) ToPbThreat(domainThreat *domain.Threat) *iocpb.Threat {
	if domainThreat == nil {
		return nil
	}
	pbThreat := &iocpb.Threat{
		Id:           domainThreat.ID,
		Name:         domainThreat.Name,
		Description:  domainThreat.Description,
		Indicators:   nil,
		Category:     c.ToPbThreatCategory(domainThreat.Category),
		Severity:     c.ToPbSeverity(domainThreat.Severity),
		ThreatActors: domainThreat.ThreatActors,
		Campaigns:    domainThreat.Campaigns,
		Confidence:   domainThreat.Confidence,
		Metadata:     c.ToPbThreatMetadata(domainThreat.Metadata),
		Tags:         domainThreat.Tags,
		IsActive:     domainThreat.IsActive,
	}

	if !domainThreat.CreatedAt.IsZero() {
		pbThreat.CreatedAt = timestamppb.New(domainThreat.CreatedAt)
	}
	if !domainThreat.UpdatedAt.IsZero() {
		pbThreat.UpdatedAt = timestamppb.New(domainThreat.UpdatedAt)
	}

	return pbThreat
}

func (c *Converter) ToPbThreatMetadata(domainMetadata *domain.ThreatMetadata) *iocpb.ThreatMetadata {
	if domainMetadata == nil {
		return nil
	}
	pbMetadata := &iocpb.ThreatMetadata{
		CreatedBy: domainMetadata.CreatedBy,
		UpdatedBy: domainMetadata.UpdatedBy,
	}
	if domainMetadata.CustomFields != nil {
		pbStruct, err := structpb.NewStruct(domainMetadata.CustomFields)
		if err == nil {
			pbMetadata.CustomFields = pbStruct
		} else {
			pbMetadata.CustomFields = &structpb.Struct{}
		}
	}
	return pbMetadata
}

func (c *Converter) ToPbThreatStatistics(domainStatistics *domain.ThreatStatistics) *iocpb.ThreatStatistics {
	if domainStatistics == nil {
		return nil
	}

	var generatedAt *timestamppb.Timestamp
	if !domainStatistics.GeneratedAt.IsZero() {
		generatedAt = timestamppb.New(domainStatistics.GeneratedAt)
	}

	return &iocpb.ThreatStatistics{
		TotalThreats:    domainStatistics.TotalThreats,
		ActiveThreats:   domainStatistics.ActiveThreats,
		ByCategory:      domainStatistics.ByCategory,
		BySeverity:      domainStatistics.BySeverity,
		TopCampaigns:    domainStatistics.TopCampaigns,
		TopThreatActors: domainStatistics.TopThreatActors,
		GeneratedAt:     generatedAt,
	}
}

func (c *Converter) ToPbBatchThreatCorrelations(domainCorrelations []*domain.ThreatCorrelation) []*iocpb.ThreatCorrelation {
	if domainCorrelations == nil {
		return nil
	}

	pbCorrelations := make([]*iocpb.ThreatCorrelation, 0, len(domainCorrelations))
	for _, domainCorrelation := range domainCorrelations {
		pbCorrelations = append(pbCorrelations, c.ToPbThreatCorrelation(domainCorrelation))
	}
	return pbCorrelations
}

func (c *Converter) ToPbThreatCorrelation(domainCorrelation *domain.ThreatCorrelation) *iocpb.ThreatCorrelation {
	if domainCorrelation == nil {
		return nil
	}

	var createdAt *timestamppb.Timestamp
	if !domainCorrelation.CreatedAt.IsZero() {
		createdAt = timestamppb.New(domainCorrelation.CreatedAt)
	}

	return &iocpb.ThreatCorrelation{
		ThreatId:  domainCorrelation.ThreatID,
		IocId:     domainCorrelation.IoCID,
		Source:    domainCorrelation.Source,
		CreatedAt: createdAt,
	}
}
