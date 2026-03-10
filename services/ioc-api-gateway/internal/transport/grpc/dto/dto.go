package http

import "time"

/* COMMON DTO */
type Pagination struct {
	Page     int32 `json:"page" binding:"omitempty,min=1"`
	PageSize int32 `json:"page_size" binding:"omitempty,min=1,max=100"`
}

type SortOptions struct {
	SortBy []string `json:"sort_by"`
	Desc   bool     `json:"desc"`
}

type CheckSourceHealthDTO struct {
	Sources []string `json:"sources"`
}

type EnrichOptionsDTO struct {
	HashType            string `json:"hash_type"`
	IncludeFileMetadata bool   `json:"include_file_metadata"`
	ForceRefresh        bool   `json:"force_refresh"`
}

/* IOC DTO */
type IoCIDUriRequest struct {
	ID string `uri:"id" binding:"required"`
}

type IoCValueUriRequest struct {
	Value string `uri:"value" binding:"required"`
}

type GetIoCQuery struct {
	Type           string   `form:"type"`
	Value          string   `form:"value"`
	IncludeRelated bool     `form:"include_related"`
	RelationTypes  []string `form:"relation_types"`
}

type GetRelatedIoCsDTO struct {
	RelationType string `form:"relation_type"`
}

type GetExpiredQuery struct {
	Limit int32 `form:"limit" binding:"omitempty,min=1,max=100"`
}

type IoCStatsQuery struct {
	SearchQuery    string     `form:"search_query"`
	Type           string     `form:"type"`
	Severity       string     `form:"severity"`
	Verdict        string     `form:"verdict"`
	Source         string     `form:"source"`
	KillChainPhase string     `form:"kill_chain_phase"`
	Tags           []string   `form:"tags"`
	IsActive       *bool      `form:"is_active"`
	StartDate      *time.Time `form:"start_date" time_format:"2006-01-02T15:04:05Z07:00"`
	EndDate        *time.Time `form:"end_date" time_format:"2006-01-02T15:04:05Z07:00"`
}

type CreateIoCRequest struct {
	Type        string         `json:"type" binding:"required"`
	Value       string         `json:"value" binding:"required"`
	Severity    string         `json:"severity"`
	Source      string         `json:"source" binding:"required"`
	Description string         `json:"description"`
	Tags        []string       `json:"tags"`
	Metadata    map[string]any `json:"metadata"`
}

func (r *CreateIoCRequest) Validate() error {
	/* CHECK IOC VALIDATION */
	return nil
}

type BatchUpsertDTO struct {
	IoCs       []CreateIoCRequest `json:"iocs" binding:"required,gt=0"`
	AutoEnrich bool               `json:"auto_enrich"`
}

type EnrichIoCDTO struct {
	TargetSources []string `json:"target_sources"`
	ForceRefresh  bool     `json:"force_refresh"`
}

type DeleteIoCsDTO struct {
	IDs    []string `json:"ids" binding:"required,gt=0"`
	Reason string   `json:"reason" binding:"required"`
}

type IoCFilter struct {
	SearchQuery    string     `json:"search_query"`
	Type           string     `json:"type"`
	Severity       string     `json:"severity"`
	Verdict        string     `json:"verdict"`
	Source         string     `json:"source"`
	KillChainPhase string     `json:"kill_chain_phase"`
	Tags           []string   `json:"tags"`
	IsActive       *bool      `json:"is_active"`
	StartDate      *time.Time `json:"start_date"`
	EndDate        *time.Time `json:"end_date"`
}

type FindIoCsDTO struct {
	Pagination  Pagination  `json:"pagination"`
	Filter      IoCFilter   `json:"filter"`
	SortOptions SortOptions `json:"sort_options"`
}

/* THREAT DTO */

type ThreatUriRequest struct {
	ID string `uri:"id" binding:"required,uuid"`
}

type ThreatIoCUriRequest struct {
	IoCID string `uri:"ioc_id" binding:"required,uuid"`
}

type GetThreatQuery struct {
	Name              string `form:"name"`
	IncludeIndicators bool   `form:"include_indicators"`
}

type ThreatTTPQuery struct {
	TTPs []string `form:"ttp" binding:"required,gt=0"`
}

type ThreatStatsQuery struct {
	SearchQuery string     `form:"search_query"`
	Category    string     `form:"category"`
	Severity    string     `form:"severity"`
	Campaign    string     `form:"campaign"`
	ThreatActor string     `form:"threat_actor"`
	IsActive    *bool      `form:"is_active"`
	Tags        []string   `form:"tags"`
	StartDate   *time.Time `form:"start_date" time_format:"2006-01-02T15:04:05Z07:00"`
	EndDate     *time.Time `form:"end_date" time_format:"2006-01-02T15:04:05Z07:00"`
}

type ThreatMetadataDTO struct {
	TTPs         []string       `json:"ttps"`
	References   []string       `json:"references"`
	CustomFields map[string]any `json:"custom_fields"`
}

type CreateThreatRequest struct {
	Name         string            `json:"name" binding:"required"`
	Severity     string            `json:"severity" binding:"required"`
	Description  string            `json:"description"`
	Category     string            `json:"category"`
	Campaigns    []string          `json:"campaigns"`
	ThreatActors []string          `json:"threat_actors"`
	Confidence   float32           `json:"confidence"`
	Tags         []string          `json:"tags"`
	Metadata     ThreatMetadataDTO `json:"metadata"`
}

func (r *CreateThreatRequest) Validate() error {
	/* CHECK THREAT VALIDATION */
	return nil
}

type BatchUpsertThreatsDTO struct {
	Threats []CreateThreatRequest `json:"threats" binding:"required,gt=0"`
}

type DeleteThreatsDTO struct {
	IDs    []string `json:"ids" binding:"required,gt=0"`
	Reason string   `json:"reason" binding:"required"`
}

type ThreatFilter struct {
	SearchQuery string     `json:"search_query"`
	Category    string     `json:"category"`
	Severity    string     `json:"severity"`
	Campaign    string     `json:"campaign"`
	ThreatActor string     `json:"threat_actor"`
	IsActive    *bool      `json:"is_active"`
	StartDate   *time.Time `json:"start_date"`
	EndDate     *time.Time `json:"end_date"`
	Tags        []string   `json:"tags"`
}

type FindThreatsDTO struct {
	Pagination  Pagination   `json:"pagination"`
	Filter      ThreatFilter `json:"filter"`
	SortOptions SortOptions  `json:"sort_options"`
}

type CorrelateThreatDTO struct {
	IoCID         string  `json:"ioc_id" binding:"required,uuid"`
	MinConfidence float32 `json:"min_confidence"`
}

type LinkIoCsDTO struct {
	IoCIDs []string `json:"ioc_ids" binding:"required,gt=0"`
}
