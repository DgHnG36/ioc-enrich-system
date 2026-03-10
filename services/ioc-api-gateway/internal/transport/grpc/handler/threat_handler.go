package handler

import (
	"net/http"

	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/client"
	dto "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/dto"
	threatpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ThreatHandler struct {
	grpcClient *client.GatewayClient
	converter  *Converter
	logger     *zap.Logger
}

func NewThreatHandler(grpcClient *client.GatewayClient, converter *Converter, logger *zap.Logger) *ThreatHandler {
	return &ThreatHandler{
		grpcClient: grpcClient,
		converter:  converter,
		logger:     logger,
	}
}

func (h *ThreatHandler) GetThreat(c *gin.Context) {
	var uriReq dto.ThreatUriRequest
	var bodyReq dto.GetThreatQuery
	_ = c.ShouldBindUri(&uriReq)
	if err := c.ShouldBindQuery(&bodyReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid body parameter", err)
		return
	}

	grpcReq := &threatpb.GetThreatRequest{
		IncludeIndicators: bodyReq.IncludeIndicators,
	}

	if uriReq.ID != "" {
		grpcReq.Identifier = &threatpb.GetThreatRequest_Id{Id: uriReq.ID}
	} else if bodyReq.Name != "" {
		grpcReq.Identifier = &threatpb.GetThreatRequest_Name{Name: bodyReq.Name}
	} else {
		h.respondError(c, http.StatusBadRequest, "Either ID or Name must be provided", nil)
		return
	}

	resp, err := h.grpcClient.GetThreat(c, grpcReq)
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get Threat successfully", resp)
}

func (h *ThreatHandler) FindThreats(c *gin.Context) {
	var req dto.FindThreatsDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.FindThreats(c, &threatpb.FindThreatsRequest{
		Pagination: h.converter.ToPbPagination(&req.Pagination),
		Filter:     h.converter.ToPbThreatFilter(&req.Filter),
		SortOptions: &threatpb.SortOptions{
			SortBy:   req.SortOptions.SortBy,
			SortDesc: req.SortOptions.Desc,
		},
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Find Threats successfully", resp)
}

func (h *ThreatHandler) BatchUpsertThreats(c *gin.Context) {
	var req dto.BatchUpsertThreatsDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	var pbThreats []*threatpb.Threat
	for _, t := range req.Threats {
		pbThreats = append(pbThreats, h.converter.ToPbCreateThreat(t))
	}

	resp, err := h.grpcClient.BatchUpsertThreats(c, &threatpb.BatchUpsertThreatsRequest{
		Threats: pbThreats,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Threats upserted successfully", resp)
}

func (h *ThreatHandler) DeleteThreats(c *gin.Context) {
	var req dto.DeleteThreatsDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.DeleteThreats(c, &threatpb.DeleteThreatsRequest{
		Ids:    req.IDs,
		Reason: req.Reason,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Threats deleted successfully", resp)
}

func (h *ThreatHandler) GetThreatStatistics(c *gin.Context) {
	var queryReq dto.ThreatStatsQuery
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid query parameters", err)
		return
	}

	filterDto := &dto.ThreatFilter{
		SearchQuery: queryReq.SearchQuery,
		Category:    queryReq.Category,
		Severity:    queryReq.Severity,
		Campaign:    queryReq.Campaign,
		ThreatActor: queryReq.ThreatActor,
		IsActive:    queryReq.IsActive,
		StartDate:   queryReq.StartDate,
		EndDate:     queryReq.EndDate,
		Tags:        queryReq.Tags,
	}

	resp, err := h.grpcClient.GetThreatStatistics(c, &threatpb.GetThreatStatisticsRequest{
		Filter: h.converter.ToPbThreatFilter(filterDto),
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get Threat Statistics successfully", resp)
}

func (h *ThreatHandler) GetThreatsByIoC(c *gin.Context) {
	var uriReq dto.ThreatIoCUriRequest
	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid IoC ID", err)
		return
	}

	resp, err := h.grpcClient.GetThreatsByIoC(c, &threatpb.GetThreatsByIoCRequest{
		IocId: uriReq.IoCID,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get Threats by IoC successfully", resp)
}

func (h *ThreatHandler) GetThreatsByTTP(c *gin.Context) {
	var queryReq dto.ThreatTTPQuery
	if err := c.ShouldBindQuery(&queryReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Missing TTP query parameter", err)
		return
	}

	resp, err := h.grpcClient.GetThreatsByTTP(c, &threatpb.GetThreatsByTTPRequest{
		Ttps: queryReq.TTPs,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Get Threats by TTP successfully", resp)
}

func (h *ThreatHandler) CorrelateThreat(c *gin.Context) {
	var req dto.CorrelateThreatDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.CorrelateThreat(c, &threatpb.CorrelateThreatRequest{
		IocId:         req.IoCID,
		MinConfidence: req.MinConfidence,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "Correlate Threat successfully", resp)
}

func (h *ThreatHandler) LinkIoCs(c *gin.Context) {
	var uriReq dto.ThreatUriRequest
	var bodyReq dto.LinkIoCsDTO

	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid Threat ID", err)
		return
	}
	if err := c.ShouldBindJSON(&bodyReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.LinkIoCs(c, &threatpb.LinkIoCsRequest{
		ThreatId: uriReq.ID,
		IocIds:   bodyReq.IoCIDs,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "IoCs linked successfully", resp)
}

func (h *ThreatHandler) UnlinkIoCs(c *gin.Context) {
	var uriReq dto.ThreatUriRequest
	var bodyReq dto.LinkIoCsDTO

	if err := c.ShouldBindUri(&uriReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid Threat ID", err)
		return
	}
	if err := c.ShouldBindJSON(&bodyReq); err != nil {
		h.respondError(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	resp, err := h.grpcClient.UnlinkIoCs(c, &threatpb.UnlinkIoCsRequest{
		ThreatId: uriReq.ID,
		IocIds:   bodyReq.IoCIDs,
	})
	if err != nil {
		h.handleGRPCError(c, err)
		return
	}
	h.respondSuccess(c, http.StatusOK, "IoCs unlinked successfully", resp)
}

/* HELPER METHODS */
func (h *ThreatHandler) Ping() error {
	// Thực hiện một lệnh gọi nhẹ hoặc check connection state
	// Trong thực tế, bạn có thể gọi một rpc HealthCheck rỗng
	return nil
}

func (h *ThreatHandler) respondError(c *gin.Context, code int, message string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	c.JSON(code, gin.H{"success": false, "message": message, "error": errMsg})
}

func (h *ThreatHandler) respondSuccess(c *gin.Context, code int, message string, data interface{}) {
	c.JSON(code, gin.H{"success": true, "message": message, "data": data})
}

func (h *ThreatHandler) handleGRPCError(c *gin.Context, err error) {
	h.logger.Error("gRPC Error in ThreatHandler", zap.Error(err))
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
