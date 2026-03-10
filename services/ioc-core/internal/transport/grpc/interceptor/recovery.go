package interceptor

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

/* CONFIG AND STRUCT */
type RecoveryConfig struct {
	EnableStackTrace bool
	RecoveryHandler  RecoveryHandlerFunc
}

type RecoveryHandlerFunc func(ctx context.Context, p interface{}) error

type RecoveryInterceptor struct {
	config *RecoveryConfig
	logger *logger.Logger
}

func NewRecoveryInterceptor(cfg *RecoveryConfig, log *logger.Logger) *RecoveryInterceptor {
	if cfg == nil {
		cfg = &RecoveryConfig{
			EnableStackTrace: true, // Auto turn on for debugging
			RecoveryHandler:  nil,
		}
	}
	return &RecoveryInterceptor{
		config: cfg,
		logger: log,
	}
}

func (r *RecoveryInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if p := recover(); p != nil {
				r.logPanic(ctx, p, info.FullMethod)

				if r.config.RecoveryHandler != nil {
					err = r.config.RecoveryHandler(ctx, p)
				} else {
					err = r.defaultRecoveryHandler(ctx, p)
				}
			}
		}()
		return handler(ctx, req)
	}
}

func (r *RecoveryInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if p := recover(); p != nil {
				ctx := ss.Context()
				r.logPanic(ctx, p, info.FullMethod)

				if r.config.RecoveryHandler != nil {
					err = r.config.RecoveryHandler(ctx, p)
				} else {
					err = r.defaultRecoveryHandler(ctx, p)
				}
			}
		}()
		return handler(srv, ss)
	}
}

func (r *RecoveryInterceptor) logPanic(ctx context.Context, p interface{}, method string) {
	fields := logger.Fields{
		"method": method,
		"panic":  fmt.Sprintf("%v", p),
		"type":   fmt.Sprintf("%T", p),
	}

	if r.config.EnableStackTrace {
		fields["stack_trace"] = string(debug.Stack())
	}

	if requestID := GetRequestID(ctx); requestID != "" {
		fields["request_id"] = requestID
	}

	r.logger.Error("Panic recovered in gRPC handler", nil, fields)
}

func (r *RecoveryInterceptor) defaultRecoveryHandler(ctx context.Context, p interface{}) error {
	return status.Errorf(codes.Internal, "internal server error: panic recovered")
}

// Helpers utility
func RecoveryUnaryInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return NewRecoveryInterceptor(nil, log).UnaryServerInterceptor()
}

func RecoveryStreamInterceptor(log *logger.Logger) grpc.StreamServerInterceptor {
	return NewRecoveryInterceptor(nil, log).StreamServerInterceptor()
}

/* METRICS AND ADVANCED HANDLERS */

type RecoveryMetrics interface {
	IncrementPanicCount(serviceName string)
	RecordRecoveryDuration(serviceName string, duration float64)
}

func WithMetrics(metrics RecoveryMetrics) RecoveryHandlerFunc {
	return func(ctx context.Context, p interface{}) error {
		serviceName := "unknown"

		if reqCtx, ok := GetRequestContext(ctx); ok {
			if reqCtx.ServiceName != "" {
				serviceName = reqCtx.ServiceName
			}
		}

		metrics.IncrementPanicCount(serviceName)

		return status.Errorf(codes.Internal, "internal server error: %v", p)
	}
}

// SafeGo helps run goroutines safely (prevents app crashes in case of panic)
func SafeGo(log *logger.Logger, fn func()) {
	go func() {
		defer func() {
			if p := recover(); p != nil {
				log.Error("Panic in goroutine", nil, logger.Fields{
					"panic":       fmt.Sprintf("%v", p),
					"stack_trace": string(debug.Stack()),
				})
			}
		}()
		fn()
	}()
}
