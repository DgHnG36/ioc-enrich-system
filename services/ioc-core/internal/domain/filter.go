package domain

import "time"

/* IOC FILTER AND STATISTICS */
type IoCFilter struct {
	SearchQuery    string         `json:"search_query,omitempty"`
	Type           IoCType        `json:"type,omitempty"`
	Severity       Severity       `json:"severity,omitempty"`
	Verdict        Verdict        `json:"verdict,omitempty"`
	Source         string         `json:"source,omitempty"`
	Tags           []string       `json:"tags,omitempty"`
	KillChainPhase KillChainPhase `json:"kill_chain_phase,omitempty"`
	IsActive       *bool          `json:"is_active,omitempty"`
	StartDate      *time.Time     `json:"start_date,omitempty"`
	EndDate        *time.Time     `json:"end_date,omitempty"`
}

type IoCStatistics struct {
	TotalIoCs   int32            `json:"total_iocs" db:"total_iocs"`
	ActiveIoCs  int32            `json:"active_iocs" db:"active_iocs"`
	ByType      map[string]int32 `json:"by_type"`
	BySeverity  map[string]int32 `json:"by_severity"`
	ByVerdict   map[string]int32 `json:"by_verdict"`
	GeneratedAt time.Time        `json:"generated_at"`
}

/* THREAT FILTER AND STATISTICS */
type ThreatFilter struct {
	SearchQuery string         `json:"search_query,omitempty"`
	Category    ThreatCategory `json:"category,omitempty"`
	Severity    Severity       `json:"severity,omitempty"`
	Campaign    string         `json:"campaign,omitempty"`
	ThreatActor string         `json:"threat_actor,omitempty"`
	IsActive    *bool          `json:"is_active,omitempty"`
	StartDate   *time.Time     `json:"start_date,omitempty"`
	EndDate     *time.Time     `json:"end_date,omitempty"`
}

type ThreatStatistics struct {
	TotalThreats    int32            `json:"total_threats"`
	ActiveThreats   int32            `json:"active_threats"`
	ByCategory      map[string]int32 `json:"by_category"`
	BySeverity      map[string]int32 `json:"by_severity"`
	TopCampaigns    []string         `json:"top_campaigns"`
	TopThreatActors []string         `json:"top_threat_actors"`
	GeneratedAt     time.Time        `json:"generated_at"`
}

/* COMMON PAGINATION */
type Pagination struct {
	Page       int32 `json:"page"`
	PageSize   int32 `json:"page_size"`
	TotalCount int32 `json:"total_count"`
	TotalPages int32 `json:"total_pages"`
}

func (p *Pagination) CalculateTotalPages() {
	if p.PageSize > 0 {
		p.TotalPages = (p.TotalCount + p.PageSize - 1) / p.PageSize
	}
}
