package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/google/uuid"
)

type Threat struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Category     ThreatCategory  `json:"category"`
	Severity     Severity        `json:"severity"`
	Description  string          `json:"description"`
	Indicators   []*IoC          `json:"indicators,omitempty"`
	ThreatActors []string        `json:"threat_actors"`
	Campaigns    []string        `json:"campaigns"`
	Confidence   float32         `json:"confidence"`
	Metadata     *ThreatMetadata `json:"metadata,omitempty"`
	Tags         []string        `json:"tags"`
	IsActive     bool            `json:"is_active"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type ThreatMetadata struct {
	TTPs         []string       `json:"ttps"`       // MITRE ATT&CK TTPs
	References   []string       `json:"references"` // External references
	CustomFields map[string]any `json:"custom_fields"`
	CreatedBy    string         `json:"created_by"`
	UpdatedBy    string         `json:"updated_by"`
}

/* HELPER VALUE FOR DATABASE */
func (t *ThreatMetadata) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	return json.Marshal(t)
}

func (t *ThreatMetadata) Scanner(value interface{}) error {
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

type ThreatCorrelation struct {
	ThreatID  string    `json:"threat_id"`
	IoCID     string    `json:"ioc_id"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

type ThreatIntelligence struct {
	Source     EnrichmentSource `json:"source"`
	ThreatID   string           `json:"threat_id"`
	Confidence float32          `json:"confidence"`
	ReportedAt time.Time        `json:"reported_at"`
	RawData    map[string]any   `json:"raw_data"`
}

func NewThreat(name string, category ThreatCategory, severity Severity) *Threat {
	now := time.Now()
	return &Threat{
		ID:           uuid.NewString(),
		Name:         name,
		Category:     category,
		Severity:     severity,
		Description:  "",
		Indicators:   make([]*IoC, 0),
		ThreatActors: make([]string, 0),
		Confidence:   0.0,
		Metadata:     &ThreatMetadata{},
		Campaigns:    make([]string, 0),
		Tags:         make([]string, 0),
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func (threat *Threat) AddIndicators(ioc *IoC) {
	if threat.Indicators == nil {
		threat.Indicators = make([]*IoC, 0)
	}
	for _, existingIoC := range threat.Indicators {
		if existingIoC.ID == ioc.ID {
			return
		}
	}

	if threat.Indicators == nil {
		threat.Indicators = make([]*IoC, 0)
	}
	threat.Indicators = append(threat.Indicators, ioc)
	threat.UpdatedAt = time.Now()

	ioc.UpdatedAt = time.Now()
}

func (threat *Threat) RemoveIndicators(ioCID string) {
	if threat.Indicators == nil {
		return
	}

	for i, ioc := range threat.Indicators {
		if ioc.ID == ioCID {
			threat.Indicators = append(threat.Indicators[:i], threat.Indicators[i+1:]...)
			break
		}
	}
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) GetIndicatorCount() int {
	return len(threat.Indicators)
}

func (threat *Threat) AddCampaign(campaign string) {
	if threat.Campaigns == nil {
		threat.Campaigns = make([]string, 0)
	}

	for _, c := range threat.Campaigns {
		if c == campaign {
			return
		}
	}

	threat.Campaigns = append(threat.Campaigns, campaign)
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) AddThreatActors(actor string) {
	if threat.ThreatActors == nil {
		threat.ThreatActors = make([]string, 0)
	}

	for _, a := range threat.ThreatActors {
		if a == actor {
			return
		}
	}

	threat.ThreatActors = append(threat.ThreatActors, actor)
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) AddTag(tag string) {
	if tag == "" {
		return
	}

	if threat.Tags == nil {
		threat.Tags = make([]string, 0)
	}

	for _, t := range threat.Tags {
		if t == tag {
			return
		}
	}

	threat.Tags = append(threat.Tags, tag)
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) RemoveTag(tag string) {
	if threat.Tags == nil {
		return
	}
	for i, t := range threat.Tags {
		if t == tag {
			threat.Tags = append(threat.Tags[:i], threat.Tags[i+1:]...)
			threat.UpdatedAt = time.Now()
			break
		}
	}
}

func (threat *Threat) Deactivate() {
	threat.IsActive = false
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) Activate() {
	threat.IsActive = true
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) UpdateConfidence(confidence float32) {
	if confidence < 0.0 {
		threat.Confidence = 0.0
	} else if confidence > 1.0 {
		threat.Confidence = 1.0
	} else {
		threat.Confidence = confidence
	}
	threat.UpdatedAt = time.Now()
}

func (threat *Threat) Validate() error {
	if threat.Name == "" {
		return errors.ErrInvalidInput.Clone().WithMessage("threat name cannot be empty")
	}

	if !threat.Category.IsValid() {
		return errors.ErrInvalidInput.Clone().WithMessage("invalid category")
	}

	if !threat.Severity.IsValid() {
		return errors.ErrInvalidInput.Clone().WithMessage("invalid severity")
	}

	if threat.Confidence < 0.0 || threat.Confidence > 1.0 {
		return errors.ErrInvalidInput.Clone().WithMessage("confidence must be between 0.0 and 1.0")
	}
	return nil
}
