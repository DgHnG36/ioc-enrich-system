package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
)

/* IOC MODELS */
type IoC struct {
	ID                string             `json:"id"`
	Type              IoCType            `json:"type"`
	Value             string             `json:"value"`
	Verdict           Verdict            `json:"verdict"`
	Severity          Severity           `json:"severity"`
	Source            string             `json:"source"`
	Description       string             `json:"description"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	ExpiresAt         *time.Time         `json:"expires_at,omitempty"`
	Tags              []string           `json:"tags"`
	ThreatContext     *ThreatContext     `json:"threat_context,omitempty"`
	EnrichmentSummary *EnrichmentSummary `json:"enrichment_summary,omitempty"`
	Metadata          *IoCMetadata       `json:"metadata,omitempty"`
	IsActive          bool               `json:"is_active"`
	DetectionCount    int32              `json:"detection_count"`
}

type ThreatContext struct {
	ConfidenceScore float32          `json:"confidence_score"` // 0.0 - 1.0
	Categories      []ThreatCategory `json:"categories"`
	KillChainPhase  KillChainPhase   `json:"kill_chain_phase"`
	ThreatActors    []string         `json:"threat_actors"`
	Campaigns       []string         `json:"campaigns"`
}

/* HELPER VALUE FOR DATABASE */
func (t *ThreatContext) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	return json.Marshal(t)
}

func (t *ThreatContext) Scanner(value interface{}) error {
	if value == nil {
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, t)
}

type EnrichmentSummary struct {
	TotalSources    int32                    `json:"total_sources"`
	MaliciousCount  int32                    `json:"malicious_count"`
	SuspiciousCount int32                    `json:"suspicious_count"`
	BenignCount     int32                    `json:"benign_count"`
	LastEnriched    time.Time                `json:"last_enriched"`
	SourceDetails   map[string]*SourceResult `json:"source_details"`
}

type SourceResult struct {
	SourceName  string         `json:"source_name"`
	IsMalicious bool           `json:"is_malicious"`
	Score       float32        `json:"score"`
	Verdict     string         `json:"verdict"`
	CheckedAt   time.Time      `json:"checked_at"`
	RawData     map[string]any `json:"raw_data"`
}

type IoCMetadata struct {
	CustomFields map[string]any `json:"custom_fields"`
	CreatedBy    string         `json:"created_by"`
	UpdatedBy    string         `json:"updated_by"`
}

/* HELPER VALUE FOR DATABASE */
func (m *IoCMetadata) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func (m *IoCMetadata) Scanner(value interface{}) error {
	if value == nil {
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, m)
}

type RelatedIoC struct {
	IoCID           string       `json:"ioc_id"`
	Value           string       `json:"value"`
	Type            IoCType      `json:"type"`
	RelationType    RelationType `json:"relation_type"`
	SimilarityScore float32      `json:"similarity_score"` // 0.0 - 1.0
	Source          string       `json:"source"`
	FirstSeen       time.Time    `json:"first_seen"`
	LastSeen        time.Time    `json:"last_seen"`
	Description     string       `json:"description"`
}

func NewIoC(ioc_type IoCType, value string, severity Severity, source string) *IoC {
	now := time.Now()
	return &IoC{
		Type:           ioc_type,
		Value:          value,
		Severity:       severity,
		Source:         source,
		Verdict:        VerdictUnknown,
		CreatedAt:      now,
		UpdatedAt:      now,
		Tags:           make([]string, 0),
		IsActive:       true,
		DetectionCount: 0,
	}
}

func (ioc *IoC) IsExpired() bool {
	if ioc.ExpiresAt == nil {
		return true
	}
	return ioc.ExpiresAt.Before(time.Now())
}

func (ioc *IoC) IsMalicious() bool {
	if ioc.ThreatContext == nil {
		return false
	}
	if ioc.Verdict == VerdictMalicious || ioc.Verdict == VerdictSuspicious {
		return true
	}
	return false
}

func (ioc *IoC) MatchReason() string {
	if ioc.IsMalicious() {
		return "verdict malicious or verdict suspicious"
	}
	return "verdict clean or verdict false positive"
}

func (ioc *IoC) GetConfidenceScore() float32 {
	if ioc.ThreatContext == nil {
		return 0.0
	}
	return ioc.ThreatContext.ConfidenceScore
}

func (ioc *IoC) UpdatedThreatContext(ctx *ThreatContext) {
	ioc.ThreatContext = ctx
	ioc.UpdatedAt = time.Now()
}

func (ioc *IoC) AddTag(tag string) {
	if tag == "" {
		return
	}

	if ioc.Tags == nil {
		ioc.Tags = make([]string, 0)
	}

	for _, t := range ioc.Tags {
		if t == tag {
			return
		}
	}

	ioc.Tags = append(ioc.Tags, tag)
	ioc.UpdatedAt = time.Now()
}

func (ioc *IoC) RemoveTag(tag string) {
	if ioc.Tags == nil {
		return
	}
	for i, t := range ioc.Tags {
		if t == tag {
			ioc.Tags = append(ioc.Tags[:i], ioc.Tags[i+1:]...)
			ioc.UpdatedAt = time.Now()
			break
		}
	}
}

func (ioc *IoC) IncrementDetectionCount() {
	ioc.DetectionCount++
	ioc.UpdatedAt = time.Now()
}

func (ioc *IoC) Deactivate() {
	ioc.IsActive = false
	ioc.UpdatedAt = time.Now()
}

func (ioc *IoC) Activate() {
	ioc.IsActive = true
	ioc.UpdatedAt = time.Now()
}

func (ioc *IoC) Validate() error {
	if ioc.Value == "" {
		return errors.ErrInvalidInput.Clone().WithMessage("IoC value cannot be empty")
	}

	if !ioc.Type.IsValid() {
		return errors.ErrInvalidInput.Clone().WithMessage("invalid IoC type")
	}

	if !ioc.Severity.IsValid() {
		return errors.ErrInvalidInput.Clone().WithMessage("invalid severity")
	}

	if ioc.Source == "" {
		return errors.ErrNotFound.Clone().WithMessage("resource cannot be empty")
	}

	return nil
}

/* COMMAND */
type IoCBatch struct {
	IoCs         []*IoC  `json:"iocs"`
	TotalCount   int32   `json:"total_count"`
	SuccessCount int32   `json:"success_count"`
	FailedCount  int32   `json:"failed_count"`
	Errors       []error `json:"errors,omitempty"`
}
