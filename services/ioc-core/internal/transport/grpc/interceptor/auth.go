package interceptor

import (
	"context"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/errors"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

/* CONFIG AND STRUCTS */

type ContextInterceptorConfig struct {
	TrustedServices map[string]bool
	AllowedMethods  []string
}

type RequestContext struct {
	UserID      string
	Username    string
	RequestID   string
	ServiceName string
	ClientIP    string
	UserAgent   string
}

type ContextInterceptor struct {
	config *ContextInterceptorConfig
	logger *logger.Logger
}

func NewContextInterceptorConfig(cfg *ContextInterceptorConfig, log *logger.Logger) *ContextInterceptor {
	if cfg == nil {
		cfg = DefaultContextInterceptorConfig()
	}

	return &ContextInterceptor{
		config: cfg,
		logger: log,
	}
}

/* INTERCEPTOR LOGIC */

func (c *ContextInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Allow whitelisting methods
		if c.isAllowedMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		// Extract Context
		reqCtx := c.extractRequestContext(ctx)

		// Check Trusted Service (if configured)
		if len(c.config.TrustedServices) > 0 && !c.config.TrustedServices[reqCtx.ServiceName] {
			c.logger.Error("Untrusted service blocked", nil, logger.Fields{
				"service": reqCtx.ServiceName,
				"method":  info.FullMethod,
			})
			return nil, status.Error(codes.PermissionDenied, "untrusted service")
		}

		// Inject in Go Context
		ctx = c.addRequestContextToContext(ctx, reqCtx)
		return handler(ctx, req)
	}
}

func (c *ContextInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if c.isAllowedMethod(info.FullMethod) {
			return handler(srv, ss)
		}

		ctx := ss.Context()
		reqCtx := c.extractRequestContext(ctx)

		if len(c.config.TrustedServices) > 0 && !c.config.TrustedServices[reqCtx.ServiceName] {
			c.logger.Error("Untrusted service blocked in stream interceptor", nil, logger.Fields{
				"service": reqCtx.ServiceName,
				"method":  info.FullMethod,
			})
			return status.Error(codes.PermissionDenied, "untrusted service")
		}

		// Wrapper stream to inject new context into
		wrappedStream := &contextStream{
			ServerStream: ss,
			ctx:          c.addRequestContextToContext(ctx, reqCtx),
		}

		return handler(srv, wrappedStream)
	}
}

/* HELPER METHODS */

func (c *ContextInterceptor) extractRequestContext(ctx context.Context) *RequestContext {
	reqCtx := &RequestContext{
		ServiceName: "unknown-service",
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return reqCtx
	}

	// Gateway Inject Headers
	if values := md.Get("x-user-id"); len(values) > 0 {
		reqCtx.UserID = values[0]
	}

	if values := md.Get("x-username"); len(values) > 0 {
		reqCtx.Username = values[0]
	}

	if values := md.Get("x-request-id"); len(values) > 0 {
		reqCtx.RequestID = values[0]
	}

	if values := md.Get("x-service-name"); len(values) > 0 {
		reqCtx.ServiceName = values[0]
	}

	// Network Headers
	if values := md.Get("x-forwarded-for"); len(values) > 0 {
		reqCtx.ClientIP = values[0]
	} else if values := md.Get("x-real-ip"); len(values) > 0 {
		reqCtx.ClientIP = values[0]
	}

	if values := md.Get("user-agent"); len(values) > 0 {
		reqCtx.UserAgent = values[0]
	}

	return reqCtx
}

func (c *ContextInterceptor) isAllowedMethod(method string) bool {
	for _, allowedMethod := range c.config.AllowedMethods {
		if method == allowedMethod {
			return true
		}
	}
	return false
}

/* CONTEXT MANIPULATION */

type requestContextKey struct{}

func (c *ContextInterceptor) addRequestContextToContext(ctx context.Context, reqCtx *RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey{}, reqCtx)
}

// GetRequestContext retrieves the RequestContext from the context. Returns false if not found.
func GetRequestContext(ctx context.Context) (*RequestContext, bool) {
	reqCtx, ok := ctx.Value(requestContextKey{}).(*RequestContext)
	return reqCtx, ok
}

type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextStream) Context() context.Context {
	return s.ctx
}

/* UTILITY FUNCTIONS */

func GetUserID(ctx context.Context) (string, error) {
	reqCtx, ok := GetRequestContext(ctx)
	if !ok || reqCtx.UserID == "" {
		return "", errors.ErrUnauthorized.Clone().WithMessage("request context not found or user ID is empty")
	}
	return reqCtx.UserID, nil
}

func GetRequestID(ctx context.Context) string {
	reqCtx, ok := GetRequestContext(ctx)
	if !ok {
		return ""
	}
	return reqCtx.RequestID
}

func DefaultContextInterceptorConfig() *ContextInterceptorConfig {
	return &ContextInterceptorConfig{
		TrustedServices: map[string]bool{
			"api-gateway":        true,
			"ioc-service":        true,
			"threat-service":     true,
			"enrichment-service": true,
		},
		AllowedMethods: []string{
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		},
	}
}
