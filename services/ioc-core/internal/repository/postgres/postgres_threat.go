package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type ThreatRepo struct {
	db     *sqlx.DB
	logger *logger.Logger
}

func NewThreatRepository(db *sqlx.DB, logger *logger.Logger) domain.ThreatRepository {
	return &ThreatRepo{
		db:     db,
		logger: logger,
	}
}

type threatRow struct {
	ID           string         `db:"id"`
	Name         string         `db:"name"`
	Category     string         `db:"category"`
	Severity     string         `db:"severity"`
	Description  string         `db:"description"`
	ThreatActors pq.StringArray `db:"threat_actors"`
	Campaigns    pq.StringArray `db:"campaigns"`
	Confidence   float32        `db:"confidence"`
	Metadata     sql.NullString `db:"metadata"` // JSONB
	Tags         pq.StringArray `db:"tags"`
	IsActive     bool           `db:"is_active"`
	CreatedAt    time.Time      `db:"created_at"`
	UpdatedAt    time.Time      `db:"updated_at"`
}

func (r *ThreatRepo) Upsert(ctx context.Context, threats ...*domain.Threat) error {
	if len(threats) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to begin transaction")
	}
	defer tx.Rollback()

	query := `
	INSERT INTO threats (
		id, name, category, severity, description, threat_actors, campaigns,
		confidence, metadata, tags, is_active, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13
	)
	ON CONFLICT (id) DO UPDATE SET
		name = EXCLUDED.name, category = EXCLUDED.category, severity = EXCLUDED.severity,
		description = EXCLUDED.description, threat_actors = EXCLUDED.threat_actors,
		campaigns = EXCLUDED.campaigns, confidence = EXCLUDED.confidence,
		metadata = EXCLUDED.metadata, tags = EXCLUDED.tags,
		is_active = EXCLUDED.is_active, updated_at = EXCLUDED.updated_at
	`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to prepare statement")
	}
	defer stmt.Close()

	for _, t := range threats {
		_, err := stmt.ExecContext(ctx,
			t.ID, t.Name, t.Category, t.Severity, t.Description, pq.Array(t.ThreatActors),
			pq.Array(t.Campaigns), t.Confidence, r.toJSONB(t.Metadata), pq.Array(t.Tags),
			t.IsActive, t.CreatedAt, t.UpdatedAt,
		)
		if err != nil {
			r.logger.Error("Failed to upsert threat", err, logger.Fields{"threat_id": t.ID})
			return errors.ErrInternal.Clone().WithMessage(fmt.Sprintf("failed to upsert threat: %s", t.ID))
		}
	}
	return tx.Commit()
}

func (r *ThreatRepo) Delete(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, _ = tx.ExecContext(ctx, `DELETE FROM threat_ioc_relations WHERE threat_id = ANY($1)`, pq.Array(ids))

	result, err := tx.ExecContext(ctx, `DELETE FROM threats WHERE id = ANY($1)`, pq.Array(ids))
	if err != nil {
		r.logger.Error("Failed to delete threats", err)
		return errors.ErrInternal.Clone().WithMessage("failed to delete threats")
	}

	if affected, _ := result.RowsAffected(); affected == 0 {
		return errors.ErrNotFound.Clone().WithMessage("threat(s) not found")
	}

	return tx.Commit()
}

func (r *ThreatRepo) Get(ctx context.Context, id string) (*domain.Threat, error) {
	query := `
		SELECT id, name, category, severity, description, threat_actors, campaigns, 
		       confidence, metadata, tags, is_active, created_at, updated_at 
		FROM threats WHERE id = $1`
	var row threatRow
	if err := r.db.GetContext(ctx, &row, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound.Clone().WithMessage("threat not found")
		}
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get threat")
	}
	return r.rowToThreat(&row)
}

func (r *ThreatRepo) GetByName(ctx context.Context, name string) (*domain.Threat, error) {
	query := `
		SELECT id, name, category, severity, description, threat_actors, campaigns, 
		       confidence, metadata, tags, is_active, created_at, updated_at 
		FROM threats WHERE name = $1 LIMIT 1`
	var row threatRow
	if err := r.db.GetContext(ctx, &row, query, name); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound.Clone().WithMessage("threat not found")
		}
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get threat by name")
	}
	return r.rowToThreat(&row)
}

func (r *ThreatRepo) Find(ctx context.Context, filter *domain.ThreatFilter, page *domain.Pagination) ([]*domain.Threat, int64, error) {
	whereClause, args := r.buildWhereClause(filter)

	// Đếm tổng số lượng
	var total int64
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM threats %s`, whereClause)
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	if total == 0 {
		return []*domain.Threat{}, 0, nil
	}

	offset := (page.Page - 1) * page.PageSize
	query := fmt.Sprintf(`
		SELECT id, name, category, severity, description, threat_actors, campaigns, 
		       confidence, metadata, tags, is_active, created_at, updated_at
		FROM threats %s 
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		whereClause, len(args)+1, len(args)+2,
	)
	args = append(args, page.PageSize, offset)

	var rows []threatRow
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, 0, err
	}

	threats := make([]*domain.Threat, 0, len(rows))
	for _, row := range rows {
		if t, err := r.rowToThreat(&row); err == nil {
			threats = append(threats, t)
		}
	}
	return threats, total, nil
}

func (r *ThreatRepo) GetStatistics(ctx context.Context, filter *domain.ThreatFilter) (*domain.ThreatStatistics, error) {
	whereClause, args := r.buildWhereClause(filter)
	query := fmt.Sprintf(`
		SELECT COUNT(*) as total_threats, 
		       COUNT(CASE WHEN is_active = true THEN 1 END) as active_threats, 
		       AVG(confidence) as avg_confidence_score
		FROM threats %s`, whereClause)

	var stats domain.ThreatStatistics
	if err := r.db.GetContext(ctx, &stats, query, args...); err != nil {
		return nil, err
	}

	// Run count-by-field queries in parallel to reduce total latency
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		stats.ByCategory = r.getCountByField(ctx, "category", whereClause, args)
	}()
	go func() {
		defer wg.Done()
		stats.BySeverity = r.getCountByField(ctx, "severity", whereClause, args)
	}()
	go func() {
		defer wg.Done()
		stats.TopCampaigns = r.getTopArrayValues(ctx, "campaigns", whereClause, args, 10)
	}()
	go func() {
		defer wg.Done()
		stats.TopThreatActors = r.getTopArrayValues(ctx, "threat_actors", whereClause, args, 10)
	}()
	wg.Wait()
	stats.GeneratedAt = time.Now()

	return &stats, nil
}

func (r *ThreatRepo) LinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error {
	query := `INSERT INTO threat_ioc_relations (threat_id, ioc_id, created_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`
	for _, iocID := range iocIDs {
		if _, err := r.db.ExecContext(ctx, query, threatID, iocID); err != nil {
			r.logger.Error("Failed to link IoC", err)
			return errors.ErrInternal.Clone().WithMessage("failed to link IoC")
		}
	}
	return nil
}

func (r *ThreatRepo) UnlinkIoCs(ctx context.Context, threatID string, iocIDs ...string) error {
	query := `DELETE FROM threat_ioc_relations WHERE threat_id = $1 AND ioc_id = $2`
	for _, iocID := range iocIDs {
		result, err := r.db.ExecContext(ctx, query, threatID, iocID)
		if err != nil {
			return errors.ErrInternal.Clone().WithMessage("failed to unlink IoC")
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return errors.ErrNotFound.Clone().WithMessage("relationship not found")
		}
	}
	return nil
}

func (r *ThreatRepo) GetByIoC(ctx context.Context, iocID string) ([]*domain.Threat, error) {
	query := `
		SELECT t.id, t.name, t.category, t.severity, t.description, t.threat_actors, t.campaigns, 
		       t.confidence, t.metadata, t.tags, t.is_active, t.created_at, t.updated_at
		FROM threats t
		INNER JOIN threat_ioc_relations tir ON t.id = tir.threat_id
		WHERE tir.ioc_id = $1
		ORDER BY t.created_at DESC`

	var rows []threatRow
	if err := r.db.SelectContext(ctx, &rows, query, iocID); err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get threats by IoC")
	}

	threats := make([]*domain.Threat, 0, len(rows))
	for _, row := range rows {
		if t, err := r.rowToThreat(&row); err == nil {
			threats = append(threats, t)
		}
	}
	return threats, nil
}

func (r *ThreatRepo) GetByTTP(ctx context.Context, ttps []string) ([]*domain.Threat, error) {
	query := `
		SELECT id, name, category, severity, description, threat_actors, campaigns, 
		       confidence, metadata, tags, is_active, created_at, updated_at
		FROM threats
		WHERE metadata->'ttps' ?| $1
		ORDER BY created_at DESC`

	var rows []threatRow
	if err := r.db.SelectContext(ctx, &rows, query, pq.Array(ttps)); err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get threats by TTP")
	}

	threats := make([]*domain.Threat, 0, len(rows))
	for _, row := range rows {
		if t, err := r.rowToThreat(&row); err == nil {
			threats = append(threats, t)
		}
	}
	return threats, nil
}

func (r *ThreatRepo) CorrelateThreat(ctx context.Context, iocID string, minConfidence float32) ([]*domain.ThreatCorrelation, error) {
	query := `
		SELECT
			t.id as threat_id,
			$1 as ioc_id,
			'database_link' as source,
			tir.created_at
		FROM threat_ioc_relations tir
		INNER JOIN threats t ON tir.threat_id = t.id
		WHERE tir.ioc_id = $1 AND t.confidence >= $2
		ORDER BY tir.created_at DESC
	`

	// Lưu ý: Có thể bạn cần tạo struct ThreatCorrelationRow riêng, ở đây ánh xạ thẳng nếu struct json db match.
	var correlations []*domain.ThreatCorrelation
	if err := r.db.SelectContext(ctx, &correlations, query, iocID, minConfidence); err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage("failed to correlate threat")
	}
	return correlations, nil
}

/* HELPER METHODS */

func (r *ThreatRepo) buildWhereClause(filter *domain.ThreatFilter) (string, []interface{}) {
	if filter == nil {
		return "", []interface{}{}
	}

	var conditions []string
	var args []interface{}
	argCount := 1

	if filter.Category != "" && filter.Category != domain.ThreatCategoryUnspecified {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argCount))
		args = append(args, filter.Category)
		argCount++
	}
	if filter.Severity != "" && filter.Severity != domain.SeverityUnspecified {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argCount))
		args = append(args, filter.Severity)
		argCount++
	}
	if filter.SearchQuery != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argCount, argCount))
		args = append(args, "%"+filter.SearchQuery+"%")
		argCount++
	}
	if filter.Campaign != "" {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(campaigns)", argCount))
		args = append(args, filter.Campaign)
		argCount++
	}
	if filter.ThreatActor != "" {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(threat_actors)", argCount))
		args = append(args, filter.ThreatActor)
		argCount++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argCount))
		args = append(args, *filter.IsActive)
		argCount++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *ThreatRepo) getCountByField(ctx context.Context, field, whereClause string, args []interface{}) map[string]int32 {
	query := fmt.Sprintf(`SELECT %s, COUNT(*) as count FROM threats %s GROUP BY %s`, field, whereClause, field)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return make(map[string]int32)
	}
	defer rows.Close()

	result := make(map[string]int32)
	for rows.Next() {
		var key string
		var count int32
		if err := rows.Scan(&key, &count); err == nil {
			result[key] = count
		}
	}
	return result
}

func (r *ThreatRepo) getTopArrayValues(ctx context.Context, field, whereClause string, args []interface{}, limit int) []string {
	query := fmt.Sprintf(`
		SELECT DISTINCT unnest(%s) as item, COUNT(*) as count 
		FROM threats %s GROUP BY item ORDER BY count DESC LIMIT %d`,
		field, whereClause, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var item string
		var count int
		if err := rows.Scan(&item, &count); err == nil && item != "" {
			result = append(result, item)
		}
	}
	return result
}

func (r *ThreatRepo) rowToThreat(row *threatRow) (*domain.Threat, error) {
	threat := &domain.Threat{
		ID:           row.ID,
		Name:         row.Name,
		Category:     domain.ThreatCategory(row.Category),
		Severity:     domain.Severity(row.Severity),
		Description:  row.Description,
		ThreatActors: row.ThreatActors,
		Campaigns:    row.Campaigns,
		Confidence:   row.Confidence,
		Tags:         row.Tags,
		IsActive:     row.IsActive,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
		// Indicators: []*domain.IoC{} -> Không mapping ở đây để tránh N+1 Queries.
		// (Nếu muốn lấy danh sách IoC, Service sẽ tự gọi IoCRepo.GetRelated)
	}

	if row.Metadata.Valid && row.Metadata.String != "" {
		var m domain.ThreatMetadata
		if err := json.Unmarshal([]byte(row.Metadata.String), &m); err == nil {
			threat.Metadata = &m
		}
	}
	return threat, nil
}

func (r *ThreatRepo) toJSONB(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	data, _ := json.Marshal(v)
	return data
}
