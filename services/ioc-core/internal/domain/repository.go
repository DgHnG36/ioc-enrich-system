package domain

import "context"

type IoCRepository interface {
	Create(ctx context.Context, iocs ...*IoC) error
	Update(ctx context.Context, iocs ...*IoC) error
	Upsert(ctx context.Context, iocs ...*IoC) error
	Delete(ctx context.Context, ids ...string) error
	Get(ctx context.Context, id string) (*IoC, error)
	GetByValue(ctx context.Context, iocType IoCType, value string) (*IoC, error)
	Find(ctx context.Context, filter *IoCFilter, page *Pagination) ([]*IoC, int64, error)
	GetStatistics(ctx context.Context, filter *IoCFilter) (*IoCStatistics, error)
	GetExpired(ctx context.Context, limit int) ([]*IoC, error)
	IncrementDetectionCount(ctx context.Context, id string) error
}

type ThreatRepository interface {
	Upsert(ctx context.Context, threats ...*Threat) error
	Delete(ctx context.Context, ids ...string) error
	Get(ctx context.Context, id string) (*Threat, error)
	GetByName(ctx context.Context, name string) (*Threat, error)
	Find(ctx context.Context, filter *ThreatFilter, page *Pagination) ([]*Threat, int64, error)
	GetStatistics(ctx context.Context, filter *ThreatFilter) (*ThreatStatistics, error)
	LinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error
	UnlinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error
	// Correlate and relationship queries
	GetByIoC(ctx context.Context, iocID string) ([]*Threat, error)
	GetByTTP(ctx context.Context, ttps []string) ([]*Threat, error)
	CorrelateThreat(ctx context.Context, iocID string, minConfidence float32) ([]*ThreatCorrelation, error) // Can add for service
}

type RelatedIoCRepository interface {
	UpsertRelation(ctx context.Context, sourceID, targetID string, relationType RelationType, score float32) error
	DeleteRelation(ctx context.Context, sourceID string, targetIDs ...string) error
	GetRelations(ctx context.Context, sourceID string, relationType RelationType) ([]*RelatedIoC, error)
}
