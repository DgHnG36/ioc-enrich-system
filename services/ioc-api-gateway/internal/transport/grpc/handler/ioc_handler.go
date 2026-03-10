package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/client"
	dto "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/dto"

	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
)

type IoCHandler struct {
	grpcClient *client.GatewayClient
	converter  *Converter
	logger     *zap.Logger
}

func NewIoCHandler(grpcClient *client.GatewayClient, converter *Converter, logger *zap.Logger) *IoCHandler {
	return &IoCHandler{
		grpcClient: grpcClient,
		converter:  converter,
		logger:     logger,
	}
}

func (h *IoCHandler) BatchUpsertIoCs(c *gin.Context) {
	var reqUpsert dto.BatchUpsertDTO

	if err := c.ShouldBindJSON(&reqUpsert); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	var protoIoCs []*iocpb.IoC
	for _, ioc := range reqUpsert.IoCs {
		if err := ioc.Validate(); err != nil {
			h.respondError(c, http.StatusBadRequest, "Invalid IoC data", err)
			return
		}
		protoIoCs = append(protoIoCs, h.converter.ToPbIoC(ioc))
	}

	resp, err := h.grpcClient.BatchUpsertIoCs(c, &iocpb.BatchUpsertIoCsRequest{
		Iocs:       protoIoCs,
		AutoEnrich: reqUpsert.AutoEnrich,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}

	h.respondSuccess(c, http.StatusOK, "IoCs upserted successfully", resp)
}

func (h *IoCHandler) GetIoC(c *gin.Context) {
	var uriReq dto.IoCIDUriRequest
	var queryReq dto.GetIoCQuery

	_ = c.ShouldBindUri(&uriReq)
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	grpcReq := &iocpb.GetIoCRequest{
		IncludeRelated: queryReq.IncludeRelated,
		RelationTypes:  h.converter.ToPbRelationTypes(queryReq.RelationTypes),
	}

	if uriReq.ID != "" {
		grpcReq.Identifier = &iocpb.GetIoCRequest_Id{
			Id: uriReq.ID,
		}
	} else if queryReq.Type != "" && queryReq.Value != "" {
		grpcReq.Identifier = &iocpb.GetIoCRequest_ValueIdentifier{
			ValueIdentifier: &iocpb.IoCIdentifier{
				IocType: h.converter.ToPbIoCType(queryReq.Type),
				Value:   queryReq.Value,
			},
		}
	} else {
		h.respondError(c, http.StatusBadRequest, "Either ID or Type/Value must be provided", nil)
		return
	}

	resp, err := h.grpcClient.GetIoC(c, grpcReq)
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}

	h.respondSuccess(c, http.StatusOK, "Get IoC successfully", resp)
}

func (h *IoCHandler) GetByValue(c *gin.Context) {
	var uriReq dto.IoCValueUriRequest
	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid URI parameters", err)
		return
	}

	var queryReq dto.GetIoCQuery
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	if queryReq.Type == "" {
		h.respondError(c, http.StatusBadRequest, "Type query parameter is required", nil)
		return
	}

	resp, err := h.grpcClient.GetIoC(c, &iocpb.GetIoCRequest{
		Identifier: &iocpb.GetIoCRequest_ValueIdentifier{
			ValueIdentifier: &iocpb.IoCIdentifier{
				IocType: h.converter.ToPbIoCType(queryReq.Type),
				Value:   uriReq.Value,
			},
		},
		IncludeRelated: false,
		RelationTypes:  h.converter.ToPbRelationTypes(queryReq.RelationTypes),
	})

	if err != nil {
		h.handleGRPCError(c, err)
		return
	}

	h.respondSuccess(c, http.StatusOK, "Get IoC by value successfully", resp)
}

func (h *IoCHandler) DeleteIoCs(c *gin.Context) {
	var req dto.DeleteIoCsDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.DeleteIoCs(c, &iocpb.DeleteIoCsRequest{
		Ids:    req.IDs,
		Reason: req.Reason,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}

	h.respondSuccess(c, http.StatusOK, "IoCs deleted successfully", resp)
}

func (h *IoCHandler) FindIoCs(c *gin.Context) {
	var req dto.FindIoCsDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.FindIoCs(c, &iocpb.FindIoCsRequest{
		Pagination: h.converter.ToPbPagination(&req.Pagination),
		Filter:     h.converter.ToPbIoCFilter(&req.Filter),
		SortOptions: &iocpb.SortOptions{
			SortBy:   req.SortOptions.SortBy,
			SortDesc: req.SortOptions.Desc,
		},
	})

	if err != nil {
		h.handleGRPCError(c, err)
		return
	}

	h.respondSuccess(c, http.StatusOK, "Find IoCs successfully", resp)
}

func (h *IoCHandler) GetIoCStatistics(c *gin.Context) {
	var queryReq dto.IoCStatsQuery
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	filterDto := &dto.IoCFilter{
		SearchQuery:    queryReq.SearchQuery,
		Type:           queryReq.Type,
		Severity:       queryReq.Severity,
		Verdict:        queryReq.Verdict,
		Source:         queryReq.Source,
		KillChainPhase: queryReq.KillChainPhase,
		Tags:           queryReq.Tags,
		IsActive:       queryReq.IsActive,
		StartDate:      queryReq.StartDate,
		EndDate:        queryReq.EndDate,
	}
	resp, err := h.grpcClient.GetIoCStatistics(c, &iocpb.GetIoCStatisticsRequest{
		Filter: h.converter.ToPbIoCFilter(filterDto),
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get IoC Statistics successfully", resp)
}

func (h *IoCHandler) GetExpired(c *gin.Context) {
	var queryReq dto.GetExpiredQuery
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	limit := queryReq.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	resp, err := h.grpcClient.GetExpired(c, &iocpb.GetExpiredRequest{
		Limit: int32(limit),
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get expired IoCs successfully", resp)
}

func (h *IoCHandler) IncrementDetectionCount(c *gin.Context) {
	var uriReq dto.IoCIDUriRequest
	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid URI parameters", err)
		return
	}
	grpcReq := &iocpb.IncrementDetectionCountRequest{
		IocIds: []string{uriReq.ID},
	}
	resp, err := h.grpcClient.IncrementDetectionCount(c, grpcReq)
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Increment detection count successfully", resp)
}

func (h *IoCHandler) EnrichIoC(c *gin.Context) {
	var uriReq dto.IoCIDUriRequest
	var bodyReq dto.EnrichIoCDTO
	var queryReq dto.GetIoCQuery

	_ = c.ShouldBindUri(&uriReq)
	_ = c.ShouldBindQuery(&queryReq)

	if err := c.ShouldBindJSON(&bodyReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	grpcReq := &iocpb.EnrichIoCRequest{
		TargetSources: bodyReq.TargetSources,
		ForceRefresh:  bodyReq.ForceRefresh,
	}
	if uriReq.ID != "" {
		grpcReq.Identifier = &iocpb.EnrichIoCRequest_IocId{
			IocId: uriReq.ID,
		}
	} else if queryReq.Type != "" && queryReq.Value != "" {
		grpcReq.Identifier = &iocpb.EnrichIoCRequest_ValueIdentifier{
			ValueIdentifier: &iocpb.IoCIdentifier{
				IocType: h.converter.ToPbIoCType(queryReq.Type),
				Value:   queryReq.Value,
			},
		}
	} else {
		h.respondError(c, http.StatusBadRequest, "Either ID or Type/Value must be provided", nil)
		return
	}

	resp, err := h.grpcClient.EnrichIoC(c, grpcReq)
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Enrichment triggered", resp)
}

func (h *IoCHandler) GetEnrichmentStatus(c *gin.Context) {
	var uriReq dto.IoCIDUriRequest
	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid URI parameters", err)
		return
	}

	grpcReq := &iocpb.GetEnrichmentStatusRequest{
		IocId: uriReq.ID,
	}
	resp, err := h.grpcClient.GetEnrichmentStatus(c, grpcReq)
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get enrichment status successfully", resp)
}

func (h *IoCHandler) GetRelatedIoCs(c *gin.Context) {
	var uriReq dto.IoCIDUriRequest
	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid URI parameters", err)
		return
	}

	var queryReq dto.GetRelatedIoCsDTO
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	grpcReq := &iocpb.GetRelatedIoCsRequest{
		IocId:        uriReq.ID,
		RelationType: h.converter.ToPbRelationType(queryReq.RelationType),
	}
	resp, err := h.grpcClient.GetRelatedIoCs(c, grpcReq)
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get related IoCs successfully", resp)
}

/* HELPER METHOD */
func (h *IoCHandler) Ping() error {
	/* CHECK CONNECTION TO GRPC SERVER */
	return nil
}

func (h *IoCHandler) respondError(c *gin.Context, code int, message string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	c.JSON(code, gin.H{
		"success": false,
		"message": message,
		"error":   errMsg,
	})
}

func (h *IoCHandler) respondSuccess(c *gin.Context, code int, message string, data interface{}) {
	c.JSON(code, gin.H{
		"success": true,
		"message": message,
		"data":    data,
	})
}

func (h *IoCHandler) handleGRPCError(c *gin.Context, err error) {
	h.logger.Error("gRPC Error", zap.Error(err))
	st, ok := status.FromError(err)
	if !ok {
		h.respondError(c, http.StatusInternalServerError, "Internal server error", err)
		return
	}

	switch st.Code() {
	case codes.NotFound:
		h.respondError(c, http.StatusNotFound, st.Message(), nil)
	case codes.InvalidArgument:
		h.respondError(c, http.StatusBadRequest, st.Message(), nil)
	case codes.Unauthenticated:
		h.respondError(c, http.StatusUnauthorized, st.Message(), nil)
	default:
		h.respondError(c, http.StatusInternalServerError, "Microservice Error", err)
	}
}
