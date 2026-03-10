package handler

import (
	"context"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/application"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/domain"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
)

type ThreatHandler struct {
	iocpb.UnimplementedThreatServiceServer
	service   *application.ThreatService
	converter *Converter
	logger    *logger.Logger
}

func NewThreatHandler(service *application.ThreatService, logger *logger.Logger, converter *Converter) *ThreatHandler {
	return &ThreatHandler{
		service:   service,
		converter: converter,
		logger:    logger,
	}
}

func (h *ThreatHandler) BatchUpsertThreats(ctx context.Context, req *iocpb.BatchUpsertThreatsRequest) (*iocpb.BatchUpsertThreatsResponse, error) {
	if req.GetThreats() == nil || len(req.GetThreats()) == 0 {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("empty threats list")
	}

	h.logger.Info("Batch upserting threats request", logger.Fields{
		"count": len(req.GetThreats()),
	})

	domainThreats := h.converter.ToDomainBatchThreats(req.GetThreats())
	upsertedIDs, err := h.service.BatchUpsertThreats(ctx, domainThreats)
	if err != nil {
		h.logger.Error("Failed to batch upsert threats", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.BatchUpsertThreatsResponse{
		UpsertedIds: upsertedIDs,
		Message:     "Threats upserted successfully",
	}, nil
}

func (h *ThreatHandler) GetThreat(ctx context.Context, req *iocpb.GetThreatRequest) (*iocpb.GetThreatResponse, error) {
	h.logger.Debug("Getting threat request")

	threat, err := h.service.GetThreat(ctx, req.GetId(), req.GetName(), req.GetIncludeIndicators())
	if err != nil {
		h.logger.Error("Failed to get threat", err)
		return nil, h.handleServiceError(err)
	}

	pbThreat := h.converter.ToPbThreat(threat)
	var pbIoCs []*iocpb.IoC
	if req.GetIncludeIndicators() {
		pbIoCs = h.converter.ToPbBatchIoCs(threat.Indicators)
	}

	pbThreat.Indicators = pbIoCs

	return &iocpb.GetThreatResponse{
		Threat: pbThreat,
	}, nil
}

func (h *ThreatHandler) DeleteThreats(ctx context.Context, req *iocpb.DeleteThreatsRequest) (*iocpb.DeleteThreatsResponse, error) {
	if len(req.GetIds()) == 0 {
		return nil, errors.ErrInvalidInput.Clone().WithMessage("empty threat IDs list")
	}

	h.logger.Debug("Deleting threats request", logger.Fields{
		"ids":    req.GetIds(),
		"reason": req.GetReason(),
	})

	if err := h.service.DeleteThreats(ctx, req.GetIds()); err != nil {
		return nil, h.handleServiceError(err)
	}

	return &iocpb.DeleteThreatsResponse{
		DeletedCount: int32(len(req.GetIds())),
		Message:      "Threats deleted successfully",
	}, nil
}

func (h *ThreatHandler) FindThreats(ctx context.Context, req *iocpb.FindThreatsRequest) (*iocpb.FindThreatsResponse, error) {
	h.logger.Info("Finding threats")
	domainPagination := h.converter.ToDomainPagination(req.GetPagination())
	if domainPagination == nil {
		domainPagination = &domain.Pagination{
			Page:     1,
			PageSize: 20,
		}
	}

	domainFilter := h.converter.ToDomainThreatFilter(req.GetFilter())
	if domainFilter == nil {
		domainFilter = &domain.ThreatFilter{}
	}

	threats, totalCount, err := h.service.FindThreats(ctx, domainFilter, domainPagination)
	if err != nil {
		h.logger.Error("Failed to find threats", err)
		return nil, h.handleServiceError(err)
	}

	domainPagination.TotalCount = int32(totalCount)
	pbThreats := h.converter.ToPbBatchThreats(threats)

	return &iocpb.FindThreatsResponse{
		Threats:    pbThreats,
		Pagination: h.converter.ToPbPagination(domainPagination),
	}, nil
}

func (h *ThreatHandler) GetThreatStatistics(ctx context.Context, req *iocpb.GetThreatStatisticsRequest) (*iocpb.GetThreatStatisticsResponse, error) {
	h.logger.Info("Getting threat statistics")
	domainFilter := h.converter.ToDomainThreatFilter(req.GetFilter())
	if domainFilter == nil {
		domainFilter = &domain.ThreatFilter{}
	}

	stats, err := h.service.GetThreatStatistics(ctx, domainFilter)
	if err != nil {
		h.logger.Error("Failed to get threat statistics", err)
		return nil, h.handleServiceError(err)
	}
	return &iocpb.GetThreatStatisticsResponse{
		Statistics: h.converter.ToPbThreatStatistics(stats),
	}, nil
}

func (h *ThreatHandler) GetThreatsByIoC(ctx context.Context, req *iocpb.GetThreatsByIoCRequest) (*iocpb.GetThreatsByIoCResponse, error) {
	h.logger.Info("Getting threats by IoC request", logger.Fields{
		"ioc_id": req.GetIocId(),
	})

	threats, err := h.service.GetThreatsByIoC(ctx, req.GetIocId())
	if err != nil {
		h.logger.Error("Failed to get threats by IoC", err)
		return nil, h.handleServiceError(err)
	}

	pbThreats := h.converter.ToPbBatchThreats(threats)
	return &iocpb.GetThreatsByIoCResponse{
		Threats: pbThreats,
	}, nil
}

func (h *ThreatHandler) GetThreatsByTTP(ctx context.Context, req *iocpb.GetThreatsByTTPRequest) (*iocpb.GetThreatsByTTPResponse, error) {
	h.logger.Info("Getting threats by TTP request")

	threats, err := h.service.GetThreatsByTTP(ctx, req.Ttps)
	if err != nil {
		h.logger.Error("Failed to get threats by TTP", err)
		return nil, h.handleServiceError(err)
	}

	pbThreats := h.converter.ToPbBatchThreats(threats)
	return &iocpb.GetThreatsByTTPResponse{
		Threats: pbThreats,
	}, nil
}

func (h *ThreatHandler) CorrelateThreat(ctx context.Context, req *iocpb.CorrelateThreatRequest) (*iocpb.CorrelateThreatResponse, error) {
	h.logger.Info("Correlating threat request", logger.Fields{
		"ioc_id":         req.GetIocId(),
		"min_confidence": req.GetMinConfidence(),
	})

	correlatedThreats, totalFound, err := h.service.CorrelateThreat(ctx, req.GetIocId(), req.GetMinConfidence())
	if err != nil {
		h.logger.Error("Failed to correlate threat", err)
		return nil, h.handleServiceError(err)
	}

	pbCorrelatedThreats := h.converter.ToPbBatchThreatCorrelations(correlatedThreats)
	return &iocpb.CorrelateThreatResponse{
		Correlations: pbCorrelatedThreats,
		TotalFound:   int32(totalFound),
	}, nil
}

func (h *ThreatHandler) LinkIoCs(ctx context.Context, req *iocpb.LinkIoCsRequest) (*iocpb.LinkIoCsResponse, error) {
	h.logger.Info("Linking IoCs to threat request", logger.Fields{
		"threat_id": req.GetThreatId(),
		"ioc_ids":   req.GetIocIds(),
	})

	if err := h.service.LinkIoCs(ctx, req.GetThreatId(), req.GetIocIds()); err != nil {
		h.logger.Error("Failed to link IoCs to threat", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.LinkIoCsResponse{
		Message: "IoCs linked to threat successfully",
	}, nil
}

func (h *ThreatHandler) UnlinkIoCs(ctx context.Context, req *iocpb.UnlinkIoCsRequest) (*iocpb.UnlinkIoCsResponse, error) {
	h.logger.Info("Unlinking IoCs from threat request", logger.Fields{
		"threat_id": req.GetThreatId(),
		"ioc_ids":   req.GetIocIds(),
	})

	if err := h.service.UnlinkIoCs(ctx, req.GetThreatId(), req.GetIocIds()); err != nil {
		h.logger.Error("Failed to unlink IoCs from threat", err)
		return nil, h.handleServiceError(err)
	}

	return &iocpb.UnlinkIoCsResponse{
		Message: "IoCs unlinked from threat successfully",
	}, nil
}

/* HELPER METHODS */
func (h *ThreatHandler) handleServiceError(err error) error {
	return nil
}
