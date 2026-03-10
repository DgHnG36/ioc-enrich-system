package application

import (
	"context"
	"fmt"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/client"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	enrichmentpb "github.com/DgHnG36/ioc-enrich-system/shared/go/enrichment/v1"
)

type EnrichAdapter struct {
	grpcClient client.EnrichClient
	logger     *logger.Logger
}

func NewEnrichAdapter(grpcClient client.EnrichClient, log *logger.Logger) *EnrichAdapter {
	return &EnrichAdapter{
		grpcClient: grpcClient,
		logger:     log,
	}
}

func (a *EnrichAdapter) defaultSources() []string {
	return []string{"virustotal", "abuseipdb", "otx", "hybrid_analysis"}
}

/* ENRICH IOC */
func (a *EnrichAdapter) EnrichIoC(ctx context.Context, ioc *domain.IoC) (*domain.IoC, error) {
	return a.EnrichIoCWithSources(ctx, ioc, a.defaultSources())
}

func (a *EnrichAdapter) EnrichIoCWithSources(ctx context.Context, ioc *domain.IoC, sources []string) (*domain.IoC, error) {
	if ioc == nil {
		return nil, errors.ErrInternal.Clone().WithMessage("IoC cannot be nil")
	}

	var enrichResp interface{}
	var err error
	switch ioc.Type {
	case domain.IoCTypeIP:
		enrichResp, err = a.grpcClient.EnrichIP(ctx, ioc.Value, sources)
	case domain.IoCTypeDomain:
		enrichResp, err = a.grpcClient.EnrichDomain(ctx, ioc.Value, sources)
	case domain.IoCTypeURL:
		enrichResp, err = a.grpcClient.EnrichURL(ctx, ioc.Value, sources)
	case domain.IoCTypeHashMD5, domain.IoCTypeHashSHA1, domain.IoCTypeHashSHA256:
		enrichResp, err = a.grpcClient.EnrichHash(ctx, ioc.Value, ioc.Type.String(), sources)
	case domain.IoCTypeFilePath:
		enrichResp, err = a.grpcClient.EnrichFilePath(ctx, ioc.Value, sources)
	default:
		return nil, errors.ErrInvalidInput.Clone().WithMessage(fmt.Sprintf("unsupported IoC type: %s", ioc.Type))
	}

	if err != nil {
		a.logger.Error("Failed to enrich IoC via gRPC", err, logger.Fields{
			"ioc_type":  ioc.Type,
			"ioc_value": ioc.Value,
		})
		return nil, err
	}

	enriched, err := a.convertEnrichResponse(ioc, enrichResp)
	if err != nil {
		return nil, err
	}

	a.logger.Info("IoC enriched successfully", logger.Fields{
		"ioc_id":   ioc.ID,
		"ioc_type": ioc.Type,
		"sources":  sources,
	})

	return enriched, nil
}

/* CONVERT ENRICH RESPONSE */
func (a *EnrichAdapter) convertEnrichResponse(ioc *domain.IoC, resp interface{}) (*domain.IoC, error) {
	switch r := resp.(type) {
	case *enrichmentpb.EnrichIPResponse:
		return a.convertIPResponse(ioc, r)
	case *enrichmentpb.EnrichDomainResponse:
		return a.convertDomainResponse(ioc, r)
	case *enrichmentpb.EnrichURLResponse:
		return a.convertURLResponse(ioc, r)
	case *enrichmentpb.EnrichHashResponse:
		return a.convertHashResponse(ioc, r)
	case *enrichmentpb.EnrichFilePathResponse:
		return a.convertFilePathResponse(ioc, r)
	default:
		return nil, errors.ErrInternal.Clone().WithMessage("unknown enrichment response type")
	}
}

func (a *EnrichAdapter) convertIPResponse(ioc *domain.IoC, resp *enrichmentpb.EnrichIPResponse) (*domain.IoC, error) {
	if resp == nil {
		return nil, fmt.Errorf("IP response is nil")
	}

	var enrichedAt time.Time
	if resp.GetEnrichedAt() != nil {
		enrichedAt = resp.GetEnrichedAt().AsTime()
	}

	a.processCommonEnrichData(ioc, resp.GetResults(), resp.GetAggregated(), enrichedAt)

	if ipData := resp.GetIpData(); ipData != nil {
		a.ensureMetadataExists(ioc)
		ioc.Metadata.CustomFields["ip_data"] = map[string]any{
			"country":  ipData.GetCountry(),
			"asn":      ipData.GetAsn(),
			"is_proxy": ipData.GetIsProxy(),
			"is_tor":   ipData.GetIsTor(),
			"is_vpn":   ipData.GetIsVpn(),
		}
	}

	return ioc, nil
}

func (a *EnrichAdapter) convertDomainResponse(ioc *domain.IoC, resp *enrichmentpb.EnrichDomainResponse) (*domain.IoC, error) {
	if resp == nil {
		return nil, fmt.Errorf("domain enrichment response is nil")
	}

	var enrichedTime time.Time
	if resp.GetEnrichedAt() != nil {
		enrichedTime = resp.GetEnrichedAt().AsTime()
	}

	a.processCommonEnrichData(ioc, resp.GetResults(), resp.GetAggregated(), enrichedTime)

	if ddata := resp.GetDomainData(); ddata != nil {
		a.ensureMetadataExists(ioc)

		creationDate := ""
		if ddata.GetCreationDate() != nil {
			creationDate = ddata.GetCreationDate().AsTime().Format(time.RFC3339)
		}

		ioc.Metadata.CustomFields["domain_enrichment"] = map[string]any{
			"creation_date": creationDate,
			"registrar":     ddata.GetRegistrar(),
			"resolved_ips":  ddata.GetResolvedIps(),
			"has_ssl":       ddata.GetHasSsl(),
		}
	}
	return ioc, nil
}

func (a *EnrichAdapter) convertURLResponse(ioc *domain.IoC, resp *enrichmentpb.EnrichURLResponse) (*domain.IoC, error) {
	if resp == nil {
		return nil, fmt.Errorf("URL enrichment response is nil")
	}

	var enrichedTime time.Time
	if resp.GetEnrichedAt() != nil {
		enrichedTime = resp.GetEnrichedAt().AsTime()
	}

	a.processCommonEnrichData(ioc, resp.GetResults(), resp.GetAggregated(), enrichedTime)

	if udata := resp.GetUrlData(); udata != nil {
		a.ensureMetadataExists(ioc)
		ioc.Metadata.CustomFields["url_enrichment"] = map[string]any{
			"final_url":               udata.GetFinalUrl(),
			"redirect_count":          udata.GetRedirectCount(),
			"has_phishing_indicators": udata.GetHasPhishingIndicators(),
		}
	}
	return ioc, nil
}

func (a *EnrichAdapter) convertHashResponse(ioc *domain.IoC, resp *enrichmentpb.EnrichHashResponse) (*domain.IoC, error) {
	if resp == nil {
		return nil, fmt.Errorf("hash enrichment response is nil")
	}

	var enrichedTime time.Time
	if resp.GetEnrichedAt() != nil {
		enrichedTime = resp.GetEnrichedAt().AsTime()
	}

	a.processCommonEnrichData(ioc, resp.GetResults(), resp.GetAggregated(), enrichedTime)

	if hdata := resp.GetHashData(); hdata != nil {
		a.ensureMetadataExists(ioc)
		ioc.Metadata.CustomFields["hash_enrichment"] = map[string]any{
			"hash_type": hdata.GetHashType(),
			"file_size": hdata.GetFileSize(),
			"file_type": hdata.GetFileType(),
			"is_packed": hdata.GetIsPacked(),
		}
	}
	return ioc, nil
}

func (a *EnrichAdapter) convertFilePathResponse(ioc *domain.IoC, resp *enrichmentpb.EnrichFilePathResponse) (*domain.IoC, error) {
	if resp == nil {
		return nil, fmt.Errorf("filepath enrichment response is nil")
	}

	var enrichedTime time.Time
	if resp.GetEnrichedAt() != nil {
		enrichedTime = resp.GetEnrichedAt().AsTime()
	}

	a.processCommonEnrichData(ioc, resp.GetResults(), resp.GetAggregated(), enrichedTime)

	if fdata := resp.GetFilePathData(); fdata != nil {
		a.ensureMetadataExists(ioc)
		ioc.Metadata.CustomFields["filepath_enrichment"] = map[string]any{
			"path":                     fdata.GetPath(),
			"extension":                fdata.GetExtension(),
			"is_system_path":           fdata.GetIsSystemPath(),
			"is_temp_path":             fdata.GetIsTempPath(),
			"known_associated_malware": fdata.GetKnownAssociatedMalware(),
		}
	}
	return ioc, nil
}

/* HELPER METHODS */
func (a *EnrichAdapter) ensureMetadataExists(ioc *domain.IoC) {
	if ioc.Metadata == nil {
		ioc.Metadata = &domain.IoCMetadata{
			CustomFields: make(map[string]any),
			UpdatedBy:    "ioc-core service",
			CreatedBy:    "ioc-core service",
		}
	}

	if ioc.Metadata.CustomFields == nil {
		ioc.Metadata.CustomFields = make(map[string]any)
	}
}

func (a *EnrichAdapter) processCommonEnrichData(ioc *domain.IoC, results map[string]*enrichmentpb.ThreatIntelData, aggregated *enrichmentpb.AggregatedScore, enrichedAt time.Time) {
	if ioc.ThreatContext == nil {
		ioc.ThreatContext = &domain.ThreatContext{}
	}

	var totalSources, maliciousCount, benignCount int32
	if aggregated != nil {
		ioc.Verdict = a.toDomainVerdict(aggregated.Verdict)
		ioc.Severity = a.calcSeverity(aggregated)
		ioc.ThreatContext.ConfidenceScore = aggregated.GetOverallScore()

		totalSources = aggregated.GetTotalSources()
		maliciousCount = aggregated.GetMaliciousCount()
		benignCount = totalSources - maliciousCount
	}

	if ioc.EnrichmentSummary == nil {
		ioc.EnrichmentSummary = &domain.EnrichmentSummary{
			SourceDetails: make(map[string]*domain.SourceResult),
		}
	}

	ioc.EnrichmentSummary.TotalSources = totalSources
	ioc.EnrichmentSummary.MaliciousCount = maliciousCount
	ioc.EnrichmentSummary.BenignCount = benignCount

	if !enrichedAt.IsZero() {
		ioc.EnrichmentSummary.LastEnriched = enrichedAt
	}

	for sourceName, intelData := range results {
		isMalicious := intelData.GetConfidence() >= 50
		sourceResult := &domain.SourceResult{
			SourceName:  sourceName,
			IsMalicious: isMalicious,
			Score:       intelData.GetConfidence(),
			Verdict:     string(a.calcVerdictSourceResult(isMalicious, intelData.GetConfidence())),
		}

		if intelData.GetReportedAt() != nil {
			sourceResult.CheckedAt = intelData.GetReportedAt().AsTime()
		}

		if intelData.GetRawData() != nil {
			sourceResult.RawData = intelData.GetRawData().AsMap()
		}

		ioc.EnrichmentSummary.SourceDetails[sourceName] = sourceResult
	}

	ioc.ThreatContext.KillChainPhase = a.determineKCP(ioc.ThreatContext)
	ioc.UpdatedAt = time.Now()
}

func (a *EnrichAdapter) toDomainVerdict(v enrichmentpb.Verdict) domain.Verdict {
	switch v {
	case enrichmentpb.Verdict_VERDICT_MALICIOUS:
		return domain.VerdictMalicious
	case enrichmentpb.Verdict_VERDICT_SUSPICIOUS:
		return domain.VerdictSuspicious
	case enrichmentpb.Verdict_VERDICT_BENIGN:
		return domain.VerdictBenign
	case enrichmentpb.Verdict_VERDICT_FALSE_POSITIVE:
		return domain.VerdictFalsePositive
	default:
		return domain.VerdictUnknown
	}
}

func (a *EnrichAdapter) calcSeverity(aggregated *enrichmentpb.AggregatedScore) domain.Severity {
	if aggregated == nil {
		return domain.SeverityUnspecified
	}
	score := aggregated.GetOverallScore()
	switch {
	case score >= 90:
		return domain.SeverityCritical
	case score >= 70:
		return domain.SeverityHigh
	case score >= 40:
		return domain.SeverityMedium
	case score >= 10:
		return domain.SeverityLow
	case score >= 0:
		return domain.SeverityInfo
	default:
		return domain.SeverityUnspecified
	}
}

func (a *EnrichAdapter) calcVerdictSourceResult(isMalicious bool, confidence float32) domain.Verdict {
	if isMalicious {
		if confidence >= 80 {
			return domain.VerdictMalicious
		} else if confidence >= 50 {
			return domain.VerdictSuspicious
		} else {
			return domain.VerdictUnknown
		}
	} else {
		if confidence >= 80 {
			return domain.VerdictBenign
		} else if confidence >= 50 {
			return domain.VerdictSuspicious
		}
		return domain.VerdictUnknown
	}
}

func (a *EnrichAdapter) determineKCP(ctx *domain.ThreatContext) domain.KillChainPhase {
	if ctx == nil {
		return domain.PhaseUnspecified
	}

	for _, c := range ctx.Categories {
		switch c {
		case domain.ThreatCategoryExploit:
			return domain.PhaseExploitation
		case domain.ThreatCategoryPhishing, domain.ThreatCategorySpam:
			return domain.PhaseDelivery
		case domain.ThreatCategoryBotnet, domain.ThreatCategoryC2:
			return domain.PhaseC2
		case domain.ThreatCategoryMalware:
			return domain.PhaseActions
		}
	}
	return domain.PhaseUnspecified
}
