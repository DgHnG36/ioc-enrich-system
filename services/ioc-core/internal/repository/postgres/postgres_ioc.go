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

type IoCRepo struct {
	db     *sqlx.DB
	logger *logger.Logger
}

func NewIoCRepository(db *sqlx.DB, log *logger.Logger) domain.IoCRepository {
	return &IoCRepo{
		db:     db,
		logger: log,
	}
}

type iocRow struct {
	ID             string         `db:"id"`
	Type           string         `db:"type"`
	Value          string         `db:"value"`
	Verdict        string         `db:"verdict"`
	Severity       string         `db:"severity"`
	Source         string         `db:"source"`
	Description    string         `db:"description"`
	CreatedAt      time.Time      `db:"created_at"`
	UpdatedAt      time.Time      `db:"updated_at"`
	ExpiresAt      sql.NullTime   `db:"expires_at"`
	Tags           pq.StringArray `db:"tags"`
	ThreatContext  sql.NullString `db:"threat_context"` // JSONB - contains kill_chain_phase
	Metadata       sql.NullString `db:"metadata"`       // JSONB
	IsActive       bool           `db:"is_active"`
	DetectionCount int32          `db:"detection_count"`
}

func (r *IoCRepo) Create(ctx context.Context, iocs ...*domain.IoC) error {
	if len(iocs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to begin transaction")
	}
	defer tx.Rollback()

	// Build multi-value INSERT to reduce DB roundtrips
	const colCount = 15
	valueStrings := make([]string, 0, len(iocs))
	args := make([]interface{}, 0, len(iocs)*colCount)

	for i, ioc := range iocs {
		base := i * colCount
		valueStrings = append(valueStrings,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d::jsonb, $%d::jsonb, $%d, $%d)",
				base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
				base+9, base+10, base+11, base+12, base+13, base+14, base+15))
		args = append(args,
			ioc.ID, ioc.Type, ioc.Value, ioc.Verdict, ioc.Severity,
			ioc.Source, ioc.Description, ioc.CreatedAt, ioc.UpdatedAt,
			r.toNullTime(ioc.ExpiresAt), pq.Array(ioc.Tags),
			r.toJSONB(ioc.ThreatContext), r.toJSONB(ioc.Metadata),
			ioc.IsActive, ioc.DetectionCount,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO iocs(
			id, type, value, verdict, severity, source, description, created_at, updated_at,
			expires_at, tags, threat_context, metadata, is_active, detection_count
		) VALUES %s`, strings.Join(valueStrings, ", "))

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return errors.ErrAlreadyExists.Clone().WithMessage("IoC already exists (duplicate key)")
		}
		return errors.ErrInternal.Clone().WithMessage("failed to batch insert IoCs")
	}

	return tx.Commit()
}

func (r *IoCRepo) Update(ctx context.Context, iocs ...*domain.IoC) error {
	if len(iocs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to begin transaction")
	}
	defer tx.Rollback()

	query := `
		UPDATE iocs SET
			type = $2,
			value = $3,
			verdict = $4,
			severity = $5,
			source = $6,
			description = $7,
			updated_at = $8,
			expires_at = $9,
			tags = $10,
			threat_context = $11::jsonb,
			metadata = $12::jsonb,
			is_active = $13,
			detection_count = $14
		WHERE id = $1
	`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to prepare statement")
	}
	defer stmt.Close()

	for _, ioc := range iocs {
		_, err := stmt.ExecContext(
			ctx,
			ioc.ID,
			ioc.Type,
			ioc.Value,
			ioc.Verdict,
			ioc.Severity,
			ioc.Source,
			ioc.Description,
			ioc.UpdatedAt,
			r.toNullTime(ioc.ExpiresAt),
			pq.Array(ioc.Tags),
			r.toJSONB(ioc.ThreatContext),
			r.toJSONB(ioc.Metadata),
			ioc.IsActive,
			ioc.DetectionCount,
		)
		if err != nil {
			return errors.ErrInternal.Clone().WithMessage(fmt.Sprintf("failed to update IoC: %s", ioc.ID))
		}
	}

	return tx.Commit()
}

func (r *IoCRepo) Upsert(ctx context.Context, iocs ...*domain.IoC) error {
	if len(iocs) == 0 {
		return nil
	}

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to begin transaction")
	}
	defer tx.Rollback()

	// Build multi-value UPSERT to reduce DB roundtrips
	const colCount = 15
	valueStrings := make([]string, 0, len(iocs))
	args := make([]interface{}, 0, len(iocs)*colCount)

	for i, ioc := range iocs {
		base := i * colCount
		valueStrings = append(valueStrings,
			fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d::jsonb, $%d::jsonb, $%d, $%d)",
				base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
				base+9, base+10, base+11, base+12, base+13, base+14, base+15))
		args = append(args,
			ioc.ID, ioc.Type, ioc.Value, ioc.Verdict, ioc.Severity,
			ioc.Source, ioc.Description, ioc.CreatedAt, ioc.UpdatedAt,
			r.toNullTime(ioc.ExpiresAt), pq.Array(ioc.Tags),
			r.toJSONB(ioc.ThreatContext), r.toJSONB(ioc.Metadata),
			ioc.IsActive, ioc.DetectionCount,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO iocs (
			id, type, value, verdict, severity, source, description, created_at, updated_at,
			expires_at, tags, threat_context, metadata, is_active, detection_count
		) VALUES %s
		ON CONFLICT (id) DO UPDATE SET
			type = EXCLUDED.type,
			value = EXCLUDED.value,
			verdict = EXCLUDED.verdict,
			severity = EXCLUDED.severity,
			source = EXCLUDED.source,
			description = EXCLUDED.description,
			updated_at = EXCLUDED.updated_at,
			expires_at = EXCLUDED.expires_at,
			tags = EXCLUDED.tags,
			threat_context = EXCLUDED.threat_context,
			metadata = EXCLUDED.metadata,
			is_active = EXCLUDED.is_active,
			detection_count = EXCLUDED.detection_count
	`, strings.Join(valueStrings, ", "))

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage("failed to batch upsert IoCs")
	}

	return tx.Commit()
}

func (r *IoCRepo) Delete(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}

	query := `DELETE FROM iocs WHERE id = ANY($1)`

	result, err := r.db.ExecContext(ctx, query, pq.Array(ids))
	if err != nil {
		r.logger.Errorf("failed to delete IoCs: %v", err)
		return errors.ErrInternal.Clone().WithMessage("failed to delete IoCs")
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return errors.ErrNotFound.Clone().WithMessage("no IoCs found to delete")
	}

	return nil
}

func (r *IoCRepo) Get(ctx context.Context, id string) (*domain.IoC, error) {
	if id == "" {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("id cannot be empty")
	}

	query := `
		SELECT id, type, value, verdict, severity, source, description, created_at, updated_at,
			expires_at, tags, threat_context, metadata, is_active, detection_count
		FROM iocs
		WHERE id = $1
	`
	var row iocRow
	err := r.db.GetContext(ctx, &row, query, id)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound.Clone().WithMessage(fmt.Sprintf("IoC not found: %s", id))
	}
	if err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage(fmt.Sprintf("failed to get IoC: %s", id))
	}

	return r.rowToIoC(&row)
}

func (r *IoCRepo) GetByValue(ctx context.Context, iocType domain.IoCType, value string) (*domain.IoC, error) {
	if iocType == domain.IoCTypeUnspecified || value == "" {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("ioc type or value cannot be empty")
	}

	query := `
		SELECT id, type, value, verdict, severity, source, description, created_at, updated_at,
			expires_at, tags, threat_context, metadata, is_active, detection_count
		FROM iocs
		WHERE type = $1 AND value = $2
		LIMIT 1
	`
	var row iocRow
	err := r.db.GetContext(ctx, &row, query, iocType.String(), value)
	if err == sql.ErrNoRows {
		return nil, errors.ErrNotFound.Clone().WithMessage(fmt.Sprintf("IoC not found: %s", value))
	}
	if err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage(fmt.Sprintf("failed to get IoC: %s", value))
	}

	return r.rowToIoC(&row)
}

func (r *IoCRepo) Find(ctx context.Context, filter *domain.IoCFilter, page *domain.Pagination) ([]*domain.IoC, int64, error) {
	whereClause, args := r.buildWhereClause(filter)

	var total int64
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM iocs %s`, whereClause)
	if err := r.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, errors.ErrInternal.Clone().WithMessage("failed to query IoCs")
	}

	if total == 0 {
		return []*domain.IoC{}, 0, nil
	}

	offset := (page.Page - 1) * page.PageSize
	query := fmt.Sprintf(`
		SELECT id, type, value, verdict, severity, source, description, created_at, updated_at,
			expires_at, tags, threat_context, metadata, is_active, detection_count
		FROM iocs
		%s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d
	`, whereClause, len(args)+1, len(args)+2)
	args = append(args, page.PageSize, offset)

	var rows []iocRow
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, 0, errors.ErrInternal.Clone().WithMessage("failed to query IoCs")
	}

	iocs := make([]*domain.IoC, 0, len(rows))
	for _, row := range rows {
		if ioc, err := r.rowToIoC(&row); err == nil {
			iocs = append(iocs, ioc)
		}
	}

	return iocs, total, nil
}

func (r *IoCRepo) GetStatistics(ctx context.Context, filter *domain.IoCFilter) (*domain.IoCStatistics, error) {
	whereClause, args := r.buildWhereClause(filter)

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) as total_iocs,
			COUNT(CASE WHEN is_active THEN 1 END) as active_iocs
		FROM iocs
		%s
	`, whereClause)

	var stats domain.IoCStatistics
	if err := r.db.GetContext(ctx, &stats, query, args...); err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get IoC statistics")
	}

	// Run count-by-field queries in parallel to reduce total latency
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		stats.ByType = r.getCountByField(ctx, "type", whereClause, args)
	}()
	go func() {
		defer wg.Done()
		stats.BySeverity = r.getCountByField(ctx, "severity", whereClause, args)
	}()
	go func() {
		defer wg.Done()
		stats.ByVerdict = r.getCountByField(ctx, "verdict", whereClause, args)
	}()
	wg.Wait()
	stats.GeneratedAt = time.Now()

	return &stats, nil
}

func (r *IoCRepo) GetExpired(ctx context.Context, limit int) ([]*domain.IoC, error) {
	query := `
		SELECT id, type, value, verdict, severity, source, description, created_at, updated_at,
			expires_at, tags, threat_context, metadata, is_active, detection_count
		FROM iocs
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
		LIMIT $1
	`
	var rows []iocRow
	if err := r.db.SelectContext(ctx, &rows, query, limit); err != nil {
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get expired IoCs")
	}

	iocs := make([]*domain.IoC, 0, len(rows))
	for _, row := range rows {
		if ioc, err := r.rowToIoC(&row); err == nil {
			iocs = append(iocs, ioc)
		}
	}

	return iocs, nil
}

func (r *IoCRepo) IncrementDetectionCount(ctx context.Context, id string) error {
	if id == "" {
		return errors.ErrInvalidInput.Clone().WithMessage("id cannot be empty")
	}
	query := `
		UPDATE iocs SET 
			detection_count = detection_count + 1,
			updated_at = NOW()
		WHERE id = $1
	`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.ErrInternal.Clone().WithMessage(fmt.Sprintf("failed to increment detection count: %s", id))
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return errors.ErrNotFound.Clone().WithMessage(fmt.Sprintf("IoC not found: %s", id))
	}

	return nil
}

/* HELPER METHODS */
func (r *IoCRepo) buildWhereClause(filter *domain.IoCFilter) (string, []interface{}) {
	if filter == nil {
		return "", nil
	}
	conditions := []string{}
	args := []interface{}{}
	argCount := 1
	if filter.Type != domain.IoCTypeUnspecified {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argCount))
		args = append(args, filter.Type.String())
		argCount++
	}
	if filter.Verdict != domain.VerdictUnspecified {
		conditions = append(conditions, fmt.Sprintf("verdict = $%d", argCount))
		args = append(args, filter.Verdict.String())
		argCount++
	}
	if filter.Severity != domain.SeverityUnspecified {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argCount))
		args = append(args, filter.Severity)
		argCount++
	}
	if filter.Source != "" {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argCount))
		args = append(args, filter.Source)
		argCount++
	}
	if filter.SearchQuery != "" {
		conditions = append(conditions, fmt.Sprintf("(value ILIKE $%d OR description ILIKE $%d)", argCount, argCount))
		args = append(args, "%"+filter.SearchQuery+"%")
		argCount++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argCount))
		args = append(args, *filter.IsActive)
		argCount++
	}
	// Tags, KillChainPhase update later
	if len(conditions) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *IoCRepo) getCountByField(ctx context.Context, field string, whereClause string, args []interface{}) map[string]int32 {
	query := fmt.Sprintf(`SELECT %s, COUNT(*) as count FROM iocs %s GROUP BY %s`, field, whereClause, field)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Errorf("failed to get count by %s: %v", field, err)
		return nil
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

func (r *IoCRepo) rowToIoC(row *iocRow) (*domain.IoC, error) {
	ioc := &domain.IoC{
		ID:             row.ID,
		Type:           domain.IoCType(row.Type),
		Value:          row.Value,
		Verdict:        domain.Verdict(row.Verdict),
		Severity:       domain.Severity(row.Severity),
		Source:         row.Source,
		Description:    row.Description,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
		Tags:           row.Tags,
		IsActive:       row.IsActive,
		DetectionCount: row.DetectionCount,
	}

	if row.ExpiresAt.Valid {
		ioc.ExpiresAt = &row.ExpiresAt.Time
	}

	if row.ThreatContext.Valid && row.ThreatContext.String != "" {
		var tc domain.ThreatContext
		if err := json.Unmarshal([]byte(row.ThreatContext.String), &tc); err == nil {
			ioc.ThreatContext = &tc
		}
	}

	if row.Metadata.Valid && row.Metadata.String != "" {
		var md domain.IoCMetadata
		if err := json.Unmarshal([]byte(row.Metadata.String), &md); err == nil {
			ioc.Metadata = &md
		}
	}

	return ioc, nil
}

func (r *IoCRepo) toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}

	return sql.NullTime{
		Time:  *t,
		Valid: true,
	}
}

func (r *IoCRepo) toJSONB(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	data, _ := json.Marshal(v)
	return data
}
