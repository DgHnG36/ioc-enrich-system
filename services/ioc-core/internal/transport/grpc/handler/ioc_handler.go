package handler

import (
	"context"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/application"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type IoCHandler struct {
	iocpb.UnimplementedIoCServiceServer
	service   *application.IoCService
	logger    *logger.Logger
	converter *Converter
}

func NewIoCHandler(service *application.IoCService, logger *logger.Logger, converter *Converter) *IoCHandler {
	return &IoCHandler{
		service:   service,
		logger:    logger,
		converter: converter,
	}
}

func (h *IoCHandler) BatchUpsertIoCs(ctx context.Context, req *iocpb.BatchUpsertIoCsRequest) (*iocpb.BatchUpsertIoCsResponse, error) {
	if req.GetIocs() == nil || len(req.GetIocs()) == 0 {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("empty IoCs list")
	}

	h.logger.Info("Batch upserting IoCs request", logger.Fields{
		"count":       len(req.GetIocs()),
		"auto_enrich": req.GetAutoEnrich(),
	})

	domainIoCs := h.converter.ToDomainBatchIoC(req.GetIocs())
	upsertedIDs, err := h.service.BatchUpsertIoCs(ctx, domainIoCs, req.GetAutoEnrich())
	if err != nil {
		h.logger.Error("Failed to batch upsert IoCs", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.BatchUpsertIoCsResponse{
		UpsertedIds:  upsertedIDs,
		Message:      "IoCs upserted successfully",
		TotalSuccess: int32(len(upsertedIDs)),
		TotalFailed:  int32(len(req.GetIocs()) - len(upsertedIDs)),
	}, nil
}

func (h *IoCHandler) GetIoC(ctx context.Context, req *iocpb.GetIoCRequest) (*iocpb.GetIoCResponse, error) {
	var ioc *domain.IoC
	var related []*domain.RelatedIoC
	var err error
	h.logger.Debug("Getting IoC request", logger.Fields{
		"include_related": req.GetIncludeRelated(),
	})

	relationTypes := make([]domain.RelationType, 0, len(req.GetRelationTypes()))
	for _, rt := range req.GetRelationTypes() {
		relationTypes = append(relationTypes, h.converter.ToDomainRelationType(rt))
	}

	switch id := req.Identifier.(type) {
	case *iocpb.GetIoCRequest_Id:
		ioc, related, err = h.service.GetIoC(ctx, id.Id, req.GetIncludeRelated(), relationTypes...)
	case *iocpb.GetIoCRequest_ValueIdentifier:
		iocType := h.converter.ToDomainIoCType(id.ValueIdentifier.IocType)
		ioc, related, err = h.service.GetByValue(ctx, iocType, id.ValueIdentifier.Value, req.GetIncludeRelated(), relationTypes...)
	case nil:
		return nil, errors.ErrInvalidInput.Clone().WithMessage("missing identifier")
	default:
		return nil, errors.ErrInvalidInput.Clone().WithMessage("invalid identifier type")
	}

	if err != nil {
		h.logger.Error("Failed to get IoC", err)
		return nil, h.handleServiceError(err)
	}

	pbIoC := h.converter.ToPbIoC(ioc)
	pbRelated := h.converter.ToPbRelatedIoCs(related)

	return &iocpb.GetIoCResponse{
		Ioc:         pbIoC,
		RelatedIocs: pbRelated,
	}, nil
}

func (h *IoCHandler) GetByValue(ctx context.Context, req *iocpb.GetByValueRequest) (*iocpb.GetByValueResponse, error) {
	h.logger.Debug("Getting IoC by value request", logger.Fields{
		"type":            req.GetType(),
		"value":           req.GetValue(),
		"include_related": req.GetIncludeRelated(),
	})

	iocType := h.converter.ToDomainIoCType(req.GetType())
	relationTypes := make([]domain.RelationType, 0, len(req.GetRelationTypes()))
	for _, rt := range req.GetRelationTypes() {
		relationTypes = append(relationTypes, h.converter.ToDomainRelationType(rt))
	}

	ioc, related, err := h.service.GetByValue(ctx, iocType, req.GetValue(), req.GetIncludeRelated(), relationTypes...)
	if err != nil {
		h.logger.Error("Failed to get IoC by value", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.GetByValueResponse{
		Ioc:         h.converter.ToPbIoC(ioc),
		RelatedIocs: h.converter.ToPbRelatedIoCs(related),
	}, nil
}

func (h *IoCHandler) DeleteIoCs(ctx context.Context, req *iocpb.DeleteIoCsRequest) (*iocpb.DeleteIoCsResponse, error) {
	if len(req.GetIds()) == 0 {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("no IoC IDs provided for deletion")
	}

	h.logger.Info("Deleting IoCs request", logger.Fields{
		"count":  len(req.GetIds()),
		"reason": req.GetReason(),
	})

	if err := h.service.DeleteIoCs(ctx, req.GetIds()); err != nil {
		h.logger.Error("Failed to delete IoCs", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.DeleteIoCsResponse{
		DeletedCount: int32(len(req.GetIds())),
		Message:      "Deleted successfully",
	}, nil
}

func (h *IoCHandler) FindIoCs(ctx context.Context, req *iocpb.FindIoCsRequest) (*iocpb.FindIoCsResponse, error) {
	h.logger.Debug("Finding IoCs request")

	domainPagination := h.converter.ToDomainPagination(req.GetPagination())
	if domainPagination == nil {
		domainPagination = &domain.Pagination{
			Page:     1,
			PageSize: 20,
		}
	}
	domainFilter := h.converter.ToDomainIoCFilter(req.GetFilter())
	if domainFilter == nil {
		domainFilter = &domain.IoCFilter{}
	}

	iocs, totalCount, err := h.service.FindIoCs(ctx, domainFilter, domainPagination)
	if err != nil {
		h.logger.Error("Failed to find IoCs", err)
		return nil, h.handleServiceError(err)
	}

	domainPagination.TotalCount = int32(totalCount)
	return &iocpb.FindIoCsResponse{
		Iocs:       h.converter.ToPbBatchIoCs(iocs),
		Pagination: h.converter.ToPbPagination(domainPagination),
	}, nil
}

func (h *IoCHandler) GetIoCStatistics(ctx context.Context, req *iocpb.GetIoCStatisticsRequest) (*iocpb.GetIoCStatisticsResponse, error) {
	h.logger.Debug("Getting IoC statistics request")

	domainFilter := h.converter.ToDomainIoCFilter(req.GetFilter())
	if domainFilter == nil {
		domainFilter = &domain.IoCFilter{}
	}

	stats, err := h.service.GetStatistics(ctx, domainFilter)
	if err != nil {
		h.logger.Error("Failed to get IoC statistics", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.GetIoCStatisticsResponse{
		Statistics: h.converter.ToPbIoCStatistics(stats),
	}, nil
}

func (h *IoCHandler) GetExpired(ctx context.Context, req *iocpb.GetExpiredRequest) (*iocpb.GetExpiredResponse, error) {
	h.logger.Debug("Getting expired IoCs request", logger.Fields{
		"limit": req.GetLimit(),
	})
	expiredIoCs, err := h.service.GetExpiredIoCs(ctx, int(req.GetLimit()))
	if err != nil {
		h.logger.Error("Failed to get expired IoCs", err)
		return nil, h.handleServiceError(err)
	}
	return &iocpb.GetExpiredResponse{
		ExpiredIocs: h.converter.ToPbBatchIoCs(expiredIoCs),
		Total:       int32(len(expiredIoCs)),
	}, nil
}

func (h *IoCHandler) IncrementDetectionCount(ctx context.Context, req *iocpb.IncrementDetectionCountRequest) (*emptypb.Empty, error) {
	h.logger.Debug("Incrementing detection count request", logger.Fields{
		"ioc_ids": req.GetIocIds(),
	})

	for _, id := range req.GetIocIds() {
		if err := h.service.IncrementDetectionCount(ctx, id); err != nil {
			h.logger.Error("Failed to increment detection count for IoC ID: "+id, err)
			return nil, h.handleServiceError(err)
		}
	}
	return &emptypb.Empty{}, nil
}

func (h *IoCHandler) EnrichIoC(ctx context.Context, req *iocpb.EnrichIoCRequest) (*iocpb.EnrichIoCResponse, error) {
	h.logger.Debug("Enriching IoC request", logger.Fields{
		"sources":       req.GetTargetSources(),
		"force_refresh": req.GetForceRefresh(),
	})

	iocType := h.converter.ToDomainIoCType(req.GetValueIdentifier().GetIocType())
	enrichedIoC, err := h.service.EnrichIoC(ctx, req.GetIocId(), iocType, req.GetValueIdentifier().GetValue(), req.GetTargetSources(), req.GetForceRefresh())
	if err != nil {
		h.logger.Error("Failed to enrich IoC", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.EnrichIoCResponse{
		IocId:   enrichedIoC.ID,
		Message: "Enrichment completed",
	}, nil
}

// GetEnrichmentStatus

func (h *IoCHandler) GetRelatedIoCs(ctx context.Context, req *iocpb.GetRelatedIoCsRequest) (*iocpb.GetRelatedIoCsResponse, error) {
	h.logger.Debug("Getting related IoCs request", logger.Fields{
		"ioc_id":        req.GetIocId(),
		"relation_type": req.GetRelationType(),
	})

	relationType := h.converter.ToDomainRelationType(req.GetRelationType())

	relatedIoCs, err := h.service.GetRelatedIoCs(ctx, relationType)
	if err != nil {
		h.logger.Error("Failed to get related IoCs", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.GetRelatedIoCsResponse{
		RelatedIocs: h.converter.ToPbRelatedIoCs(relatedIoCs),
	}, nil
}

/* HELPER METHODS */
func (h *IoCHandler) handleServiceError(err error) error {
	if err == nil {
		return nil
	}

	if appErr, ok := err.(*errors.AppError); ok {
		return appErr.ToGRPCError()
	}

	return status.Error(errors.GetGRPCStatus(err), err.Error())
}
