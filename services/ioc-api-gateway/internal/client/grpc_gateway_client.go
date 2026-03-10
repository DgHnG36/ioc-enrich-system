package client

import (
	"context"
	"fmt"
	"time"

	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type GatewayClient struct {
	iocCoreConn *grpc.ClientConn

	iocServiceClient    iocpb.IoCServiceClient
	threatServiceClient iocpb.ThreatServiceClient

	logger *zap.Logger
}

type Config struct {
	IoCCoreAddr    string
	ConnectTimeout time.Duration
}

func NewGatewayClient(config Config, logger *zap.Logger) (*GatewayClient, error) {
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}

	client := &GatewayClient{
		logger: logger,
	}

	conn, err := client.connectIoCCore(config.IoCCoreAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ioc-core: %w", err)
	}

	client.iocCoreConn = conn
	client.iocServiceClient = iocpb.NewIoCServiceClient(conn)
	client.threatServiceClient = iocpb.NewThreatServiceClient(conn)

	logger.Info(
		"IoC API Gateway client initialized",
		zap.String("ioc-core", config.IoCCoreAddr),
	)

	return client, nil
}

func (c *GatewayClient) connectIoCCore(addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	if err != nil {
		c.logger.Error("Failed to connect to ioc-core service", zap.Error(err))
		return nil, err
	}

	c.logger.Info("Connected to ioc-core service", zap.String("addr", addr))
	return conn, nil
}

// createRequestContext get user_id and request_id from incoming context (if available) and create a new context with gRPC metadata for outgoing calls
func (c *GatewayClient) createRequestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return c.createRequestContextWithTimeout(ctx, 30*time.Second)
}

// createRequestContextWithTimeout same as createRequestContext but with a custom timeout
func (c *GatewayClient) createRequestContextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	var userID, reqID string

	if ginCtx, ok := ctx.(*gin.Context); ok {
		userID = ginCtx.GetString("user_id")
		reqID = ginCtx.GetString("request_id")
	}

	if reqID == "" {
		reqID = uuid.New().String()
	}

	// Create gRPC metadata
	md := metadata.New(map[string]string{
		"x-request-id":   reqID,
		"x-user-id":      userID,
		"x-service-name": "api-gateway",
		"client-service": "ioc-api-gateway",
	})

	mdCtx := metadata.NewOutgoingContext(ctx, md)

	return context.WithTimeout(mdCtx, timeout)
}

/* IOC CORE SERVICE CALLS */

func (c *GatewayClient) BatchUpsertIoCs(ctx context.Context, req *iocpb.BatchUpsertIoCsRequest) (*iocpb.BatchUpsertIoCsResponse, error) {
	reqCtx, cancel := c.createRequestContextWithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.iocServiceClient.BatchUpsertIoCs(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetIoC(ctx context.Context, req *iocpb.GetIoCRequest) (*iocpb.GetIoCResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.GetIoC(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetByValue(ctx context.Context, req *iocpb.GetByValueRequest) (*iocpb.GetByValueResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.GetByValue(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) DeleteIoCs(ctx context.Context, req *iocpb.DeleteIoCsRequest) (*iocpb.DeleteIoCsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.DeleteIoCs(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) FindIoCs(ctx context.Context, req *iocpb.FindIoCsRequest) (*iocpb.FindIoCsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.FindIoCs(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetIoCStatistics(ctx context.Context, req *iocpb.GetIoCStatisticsRequest) (*iocpb.GetIoCStatisticsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.GetIoCStatistics(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) IncrementDetectionCount(ctx context.Context, req *iocpb.IncrementDetectionCountRequest) (*emptypb.Empty, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.IncrementDetectionCount(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetExpired(ctx context.Context, req *iocpb.GetExpiredRequest) (*iocpb.GetExpiredResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.GetExpired(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) EnrichIoC(ctx context.Context, req *iocpb.EnrichIoCRequest) (*iocpb.EnrichIoCResponse, error) {
	reqCtx, cancel := c.createRequestContextWithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.iocServiceClient.EnrichIoC(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetEnrichmentStatus(ctx context.Context, req *iocpb.GetEnrichmentStatusRequest) (*iocpb.GetEnrichmentStatusResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.GetEnrichmentStatus(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetRelatedIoCs(ctx context.Context, req *iocpb.GetRelatedIoCsRequest) (*iocpb.GetRelatedIoCsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.iocServiceClient.GetRelatedIoCs(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

/* THREAT SERVICE CALLS */

func (c *GatewayClient) BatchUpsertThreats(ctx context.Context, req *iocpb.BatchUpsertThreatsRequest) (*iocpb.BatchUpsertThreatsResponse, error) {
	reqCtx, cancel := c.createRequestContextWithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.threatServiceClient.BatchUpsertThreats(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetThreat(ctx context.Context, req *iocpb.GetThreatRequest) (*iocpb.GetThreatResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.GetThreat(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) DeleteThreats(ctx context.Context, req *iocpb.DeleteThreatsRequest) (*iocpb.DeleteThreatsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.DeleteThreats(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) FindThreats(ctx context.Context, req *iocpb.FindThreatsRequest) (*iocpb.FindThreatsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.FindThreats(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetThreatStatistics(ctx context.Context, req *iocpb.GetThreatStatisticsRequest) (*iocpb.GetThreatStatisticsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.GetThreatStatistics(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetThreatsByIoC(ctx context.Context, req *iocpb.GetThreatsByIoCRequest) (*iocpb.GetThreatsByIoCResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.GetThreatsByIoC(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) GetThreatsByTTP(ctx context.Context, req *iocpb.GetThreatsByTTPRequest) (*iocpb.GetThreatsByTTPResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.GetThreatsByTTP(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) CorrelateThreat(ctx context.Context, req *iocpb.CorrelateThreatRequest) (*iocpb.CorrelateThreatResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.CorrelateThreat(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) LinkIoCs(ctx context.Context, req *iocpb.LinkIoCsRequest) (*iocpb.LinkIoCsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.LinkIoCs(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

func (c *GatewayClient) UnlinkIoCs(ctx context.Context, req *iocpb.UnlinkIoCsRequest) (*iocpb.UnlinkIoCsResponse, error) {
	reqCtx, cancel := c.createRequestContext(ctx)
	defer cancel()

	resp, err := c.threatServiceClient.UnlinkIoCs(reqCtx, req)
	if err != nil {
		return nil, c.handleGRPCError(err)
	}
	return resp, nil
}

/* ERROR HANDLING */

type HTTPError struct {
	Code    int
	Message string
}

func (e *HTTPError) Error() string {
	return e.Message
}

func (c *GatewayClient) handleGRPCError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		c.logger.Error("Non-gRPC error", zap.Error(err))
		return &HTTPError{Code: 500, Message: "Internal server error"}
	}

	switch st.Code() {
	case codes.OK:
		return nil
	case codes.Canceled:
		return &HTTPError{Code: 499, Message: "Request canceled"}
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		return &HTTPError{Code: 400, Message: st.Message()}
	case codes.DeadlineExceeded:
		return &HTTPError{Code: 504, Message: "Gateway timeout"}
	case codes.NotFound:
		return &HTTPError{Code: 404, Message: st.Message()}
	case codes.AlreadyExists, codes.Aborted:
		return &HTTPError{Code: 409, Message: st.Message()}
	case codes.PermissionDenied:
		return &HTTPError{Code: 403, Message: st.Message()}
	case codes.ResourceExhausted:
		return &HTTPError{Code: 429, Message: "Rate limit exceeded"}
	case codes.Unimplemented:
		return &HTTPError{Code: 501, Message: "Not implemented"}
	case codes.Unauthenticated:
		return &HTTPError{Code: 401, Message: st.Message()}
	case codes.Unavailable:
		return &HTTPError{Code: 503, Message: "Service unavailable"}
	default:
		c.logger.Error("Internal gRPC error", zap.String("code", st.Code().String()), zap.String("message", st.Message()))
		return &HTTPError{Code: 500, Message: "Internal server error"}
	}
}
