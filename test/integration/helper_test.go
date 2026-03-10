package integration

import (
	"fmt"
	"time"

	iocv1 "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type IoCTestOption func(*iocv1.IoC)
type ThreatTestOption func(*iocv1.Threat)

func uniqueSuffix() int64 {
	return time.Now().UnixNano()
}

func mustStruct(fields map[string]interface{}) *structpb.Struct {
	s, err := structpb.NewStruct(fields)
	if err != nil {
		return &structpb.Struct{}
	}
	return s
}

// createTestIoC populates all fields defined in proto/domain with sensible test defaults.
func createTestIoC(
	iocType iocv1.IoCType,
	value, source string,
	severity iocv1.Severity,
	verdict iocv1.Verdict,
	opts ...IoCTestOption,
) *iocv1.IoC {
	now := timestamppb.Now()
	expires := timestamppb.New(time.Now().Add(24 * time.Hour))
	ioc := &iocv1.IoC{
		Id:          fmt.Sprintf("test-ioc-%d", uniqueSuffix()),
		Type:        iocType,
		Value:       value,
		Verdict:     verdict,
		Severity:    severity,
		Source:      source,
		Description: "integration test ioc",
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   expires,
		Tags:        []string{"integration", "test"},
		ThreatContext: &iocv1.ThreatContext{
			ConfidenceScore: 0.8,
			Categories:      []iocv1.ThreatCategory{iocv1.ThreatCategory_THREAT_CATEGORY_MALWARE},
			KillChainPhase:  iocv1.KillChainPhase_KILL_CHAIN_PHASE_DELIVERY,
			ThreatActors:    []string{"test-actor"},
			Campaigns:       []string{"test-campaign"},
		},
		EnrichmentSummary: &iocv1.EnrichmentSummary{
			TotalSources:    1,
			MaliciousCount:  1,
			SuspiciousCount: 0,
			BenignCount:     0,
			LastEnriched:    now,
			SourceDetails: map[string]*iocv1.SourceResult{
				"test-source": {
					SourceName:  "test-source",
					IsMalicious: verdict == iocv1.Verdict_VERDICT_MALICIOUS,
					Score:       0.8,
					Verdict:     verdict.String(),
					CheckedAt:   now,
					RawData:     mustStruct(map[string]interface{}{"sample": true}),
				},
			},
		},
		Metadata: &iocv1.IoCMetadata{
			CustomFields: mustStruct(map[string]interface{}{"env": "integration"}),
			CreatedBy:    "integration-test",
			UpdatedBy:    "integration-test",
		},
		IsActive:       true,
		DetectionCount: 0,
	}
	for _, opt := range opts {
		opt(ioc)
	}
	return ioc
}

// createTestThreat populates all fields defined in proto/domain with sensible test defaults.
func createTestThreat(
	name, description string,
	category iocv1.ThreatCategory,
	severity iocv1.Severity,
	confidence float32,
	ttps []string,
	opts ...ThreatTestOption,
) *iocv1.Threat {
	now := timestamppb.Now()
	threat := &iocv1.Threat{
		Id:           fmt.Sprintf("test-threat-%d", uniqueSuffix()),
		Name:         name,
		Category:     category,
		Severity:     severity,
		Description:  description,
		Indicators:   []*iocv1.IoC{},
		Campaigns:    []string{"test-campaign"},
		ThreatActors: []string{"test-actor"},
		Confidence:   confidence,
		Metadata: &iocv1.ThreatMetadata{
			Ttps:         ttps,
			References:   []string{"https://example.com/report"},
			CustomFields: mustStruct(map[string]interface{}{"env": "integration"}),
			CreatedBy:    "integration-test",
			UpdatedBy:    "integration-test",
		},
		Tags:      []string{"integration", "test"},
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	for _, opt := range opts {
		opt(threat)
	}
	return threat
}

func withIoCDescription(desc string) IoCTestOption {
	return func(i *iocv1.IoC) { i.Description = desc }
}

func withThreatDescription(desc string) ThreatTestOption {
	return func(t *iocv1.Threat) { t.Description = desc }
}
