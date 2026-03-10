package interceptor

import (
	"context"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

/* CONFIG AND STRUCT */
type LoggingConfig struct {
	LogRequests          bool
	LogResponses         bool
	LogPayloads          bool // Default false for performance
	LogMetadata          bool
	SlowRequestThreshold int64 // ms
	ExcludedMethods      []string
}

type LoggingInterceptor struct {
	config *LoggingConfig
	logger *logger.Logger
}

func NewLoggingInterceptor(config *LoggingConfig, log *logger.Logger) *LoggingInterceptor {
	if config == nil {
		config = DefaultLoggingConfig()
	}
	return &LoggingInterceptor{
		config: config,
		logger: log,
	}
}

func (l *LoggingInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if l.isExcluded(info.FullMethod) {
			return handler(ctx, req)
		}

		startTime := time.Now()

		if l.config.LogRequests {
			l.logRequest(ctx, info.FullMethod, req)
		}

		resp, err := handler(ctx, req)

		duration := time.Since(startTime)
		if l.config.LogResponses {
			l.logResponse(ctx, info.FullMethod, resp, err, duration)
		}

		if l.config.SlowRequestThreshold > 0 && duration.Milliseconds() > l.config.SlowRequestThreshold {
			l.logSlowRequest(ctx, info.FullMethod, duration)
		}

		return resp, err
	}
}

func (l *LoggingInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if l.isExcluded(info.FullMethod) {
			return handler(srv, ss)
		}

		startTime := time.Now()
		ctx := ss.Context()

		if l.config.LogRequests {
			l.logStreamStart(ctx, info.FullMethod)
		}

		wrappedStream := &loggingStream{
			ServerStream: ss,
			logger:       l.logger,
			method:       info.FullMethod,
			logPayloads:  l.config.LogPayloads,
		}

		err := handler(srv, wrappedStream)
		duration := time.Since(startTime)

		if l.config.LogResponses {
			l.logStreamEnd(ctx, info.FullMethod, err, duration)
		}

		return err
	}
}

/* LOGGING HELPERS */

func (l *LoggingInterceptor) logRequest(ctx context.Context, method string, req interface{}) {
	fields := logger.Fields{
		"type":   "grpc_request",
		"method": method,
	}

	if reqCtx, ok := GetRequestContext(ctx); ok {
		if reqCtx.UserID != "" {
			fields["user_id"] = reqCtx.UserID
		}
		fields["request_id"] = reqCtx.RequestID
		fields["service"] = reqCtx.ServiceName
		fields["client_ip"] = reqCtx.ClientIP
	}

	if peer, ok := peer.FromContext(ctx); ok {
		fields["peer_addr"] = peer.Addr.String()
	}

	if l.config.LogPayloads && req != nil {
		fields["request"] = req
	}

	l.logger.Info("gRPC request received", fields)
}

func (l *LoggingInterceptor) logResponse(ctx context.Context, method string, resp interface{}, err error, duration time.Duration) {
	fields := logger.Fields{
		"type":        "grpc_response",
		"method":      method,
		"duration_ms": duration.Milliseconds(),
	}

	if err != nil {
		st, _ := status.FromError(err)
		fields["status_code"] = st.Code().String()
		fields["error"] = st.Message()
		fields["success"] = false

		if st.Code() == codes.Internal || st.Code() == codes.Unknown {
			l.logger.Error("gRPC response failed", err, fields)
			return
		}
	} else {
		fields["status_code"] = codes.OK.String()
		fields["success"] = true
		if l.config.LogPayloads && resp != nil {
			fields["response"] = resp
		}
	}

	l.logger.Info("gRPC response sent", fields)
}

func (l *LoggingInterceptor) logSlowRequest(ctx context.Context, method string, duration time.Duration) {
	l.logger.Warn("Slow gRPC request detected", logger.Fields{
		"type":        "slow_request",
		"method":      method,
		"duration_ms": duration.Milliseconds(),
		"threshold":   l.config.SlowRequestThreshold,
	})
}

func (l *LoggingInterceptor) logStreamStart(ctx context.Context, method string) {
	l.logger.Info("gRPC stream started", logger.Fields{
		"type":   "grpc_stream_start",
		"method": method,
	})
}

func (l *LoggingInterceptor) logStreamEnd(ctx context.Context, method string, err error, duration time.Duration) {
	fields := logger.Fields{
		"type":        "grpc_stream_end",
		"method":      method,
		"duration_ms": duration.Milliseconds(),
	}
	if err != nil {
		fields["error"] = err.Error()
		l.logger.Error("gRPC stream ended with error", err, fields)
	} else {
		l.logger.Info("gRPC stream ended successfully", fields)
	}
}

func (l *LoggingInterceptor) isExcluded(method string) bool {
	for _, m := range l.config.ExcludedMethods {
		if method == m {
			return true
		}
	}
	return false
}

func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		LogRequests:          true,
		LogResponses:         true,
		LogPayloads:          false,
		LogMetadata:          true,
		SlowRequestThreshold: 1000,
		ExcludedMethods: []string{
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		},
	}
}

type loggingStream struct {
	grpc.ServerStream
	logger      *logger.Logger
	method      string
	logPayloads bool
}

func (s *loggingStream) SendMsg(m interface{}) error {
	if s.logPayloads {
		s.logger.Debug("Stream message sent", logger.Fields{"method": s.method, "msg": m})
	}
	return s.ServerStream.SendMsg(m)
}

func (s *loggingStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil && s.logPayloads {
		s.logger.Debug("Stream message received", logger.Fields{"method": s.method, "msg": m})
	}
	return err
}

/* HELPER FUNCTION */
func LoggingUnaryInterceptor(log *logger.Logger) grpc.UnaryServerInterceptor {
	return NewLoggingInterceptor(nil, log).UnaryServerInterceptor()
}

func LoggingStreamInterceptor(log *logger.Logger) grpc.StreamServerInterceptor {
	return NewLoggingInterceptor(nil, log).StreamServerInterceptor()
}
