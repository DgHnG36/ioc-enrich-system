package postgres

import (
	"context"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type RelatedIoCRepo struct {
	db     *sqlx.DB
	logger *logger.Logger
}

func NewRelatedIoCRepository(db *sqlx.DB, log *logger.Logger) domain.RelatedIoCRepository {
	return &RelatedIoCRepo{
		db:     db,
		logger: log,
	}
}

// relatedIoCRow ánh xạ với bảng ioc_relations và lấy thêm data từ bảng iocs
type relatedIoCRow struct {
	SourceID        string    `db:"source_id"`
	TargetID        string    `db:"target_id"`
	RelationType    string    `db:"relation_type"`
	SimilarityScore float32   `db:"similarity_score"`
	Source          string    `db:"source"`
	FirstSeen       time.Time `db:"first_seen"`
	LastSeen        time.Time `db:"last_seen"`
	Description     string    `db:"description"`

	// Các trường được JOIN từ bảng iocs
	TargetValue string `db:"target_value"`
	TargetType  string `db:"target_type"`
}

func (r *RelatedIoCRepo) UpsertRelation(ctx context.Context, sourceID, targetID string, relationType domain.RelationType, score float32) error {
	if score < 0.0 || score > 1.0 {
		return errors.ErrInvalidInput.Clone().WithMessage("similarity score must be between 0.0 and 1.0")
	}

	// Chú ý: Vì hàm Interface hiện tại không truyền vào source/description
	// Nên mình gán tạm chuỗi rỗng ("system"). FirstSeen/LastSeen dùng time.Now()
	now := time.Now()
	defaultSource := "system_correlation"
	defaultDesc := ""

	query := `
	INSERT INTO ioc_relations (
		source_id, target_id, relation_type, similarity_score,
		source, first_seen, last_seen, description
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8
	)
	ON CONFLICT (source_id, target_id) 
	DO UPDATE SET
		relation_type = EXCLUDED.relation_type,
		similarity_score = EXCLUDED.similarity_score,
		last_seen = EXCLUDED.last_seen
	`
	// (Ghi chú: Nếu DB của bạn unique theo cả 3 trường (source, target, type) thì sửa ON CONFLICT thành (source_id, target_id, relation_type))

	_, err := r.db.ExecContext(ctx, query,
		sourceID, targetID, relationType, score,
		defaultSource, now, now, defaultDesc,
	)

	if err != nil {
		r.logger.Error("Failed to upsert relation", err, logger.Fields{
			"source_id": sourceID,
			"target_id": targetID,
		})
		return errors.ErrInternal.Clone().WithMessage("failed to upsert relation")
	}

	return nil
}

func (r *RelatedIoCRepo) DeleteRelation(ctx context.Context, sourceID string, targetIDs ...string) error {
	// 1. Nếu không truyền targetIDs -> Xóa sạch mọi liên kết của sourceID (Thay thế DeleteAllRelations)
	if len(targetIDs) == 0 {
		query := `DELETE FROM ioc_relations WHERE source_id = $1 OR target_id = $1`
		_, err := r.db.ExecContext(ctx, query, sourceID)
		if err != nil {
			r.logger.Error("Failed to delete all relations", err, logger.Fields{"ioc_id": sourceID})
			return errors.ErrInternal.Clone().WithMessage("failed to delete all relations")
		}
		return nil
	}

	// 2. Nếu có truyền targetIDs -> Xóa đích danh các liên kết đó bằng toán tử ANY
	query := `DELETE FROM ioc_relations WHERE source_id = $1 AND target_id = ANY($2)`
	_, err := r.db.ExecContext(ctx, query, sourceID, pq.Array(targetIDs))
	if err != nil {
		r.logger.Error("Failed to delete specific relations", err, logger.Fields{
			"source_id": sourceID,
			"targets":   targetIDs,
		})
		return errors.ErrInternal.Clone().WithMessage("failed to delete relations")
	}

	return nil
}

func (r *RelatedIoCRepo) GetRelations(ctx context.Context, sourceID string, relationType domain.RelationType) ([]*domain.RelatedIoC, error) {
	query := `
	SELECT 
		r.source_id, r.target_id, r.relation_type, r.similarity_score,
		r.source, r.first_seen, r.last_seen, r.description,
		i.value as target_value, i.type as target_type
	FROM ioc_relations r
	INNER JOIN iocs i ON r.target_id = i.id
	WHERE r.source_id = $1
	`
	args := []interface{}{sourceID}

	// Nếu tầng Service truyền vào RelationType hợp lệ thì lọc thêm, nếu không thì lấy hết
	if relationType != "" {
		query += ` AND r.relation_type = $2`
		args = append(args, relationType)
	}

	query += ` ORDER BY r.similarity_score DESC, r.last_seen DESC`

	var rows []relatedIoCRow
	err := r.db.SelectContext(ctx, &rows, query, args...)
	if err != nil {
		r.logger.Error("Failed to get IoC relations", err, logger.Fields{"ioc_id": sourceID})
		return nil, errors.ErrInternal.Clone().WithMessage("failed to get relations")
	}

	return r.rowsToRelatedIoCs(rows), nil
}

/* HELPER METHODS */

func (r *RelatedIoCRepo) rowsToRelatedIoCs(rows []relatedIoCRow) []*domain.RelatedIoC {
	relatedIoCs := make([]*domain.RelatedIoC, 0, len(rows))

	for _, row := range rows {
		relatedIoCs = append(relatedIoCs, &domain.RelatedIoC{
			IoCID:           row.TargetID,
			Value:           row.TargetValue,
			Type:            domain.IoCType(row.TargetType),
			RelationType:    domain.RelationType(row.RelationType),
			SimilarityScore: row.SimilarityScore,
			Source:          row.Source,
			FirstSeen:       row.FirstSeen,
			LastSeen:        row.LastSeen,
			Description:     row.Description,
		})
	}

	return relatedIoCs
}
