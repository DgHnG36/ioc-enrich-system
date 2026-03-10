package grpc

import (
	"fmt"
	"net"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/transport/grpc/handler"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/transport/grpc/interceptor"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"
	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type GRPCServerConfig struct {
	Host string
	Port int
}

type IoCGRPCServer struct {
	server *grpc.Server
	config *GRPCServerConfig
	logger *logger.Logger
}

func NewIoCGRPCServer(cfg *GRPCServerConfig, log *logger.Logger, iocHandler *handler.IoCHandler, recoveryInterceptor *interceptor.RecoveryInterceptor, contextInterceptor *interceptor.ContextInterceptor, loggingInterceptor *interceptor.LoggingInterceptor) *IoCGRPCServer {
	unaryInterceptors := grpc.ChainUnaryInterceptor(
		recoveryInterceptor.UnaryServerInterceptor(),
		contextInterceptor.UnaryServerInterceptor(),
		loggingInterceptor.UnaryServerInterceptor(),
	)

	streamInterceptors := grpc.ChainStreamInterceptor(
		recoveryInterceptor.StreamServerInterceptor(),
		contextInterceptor.StreamServerInterceptor(),
		loggingInterceptor.StreamServerInterceptor(),
	)

	grpcServer := grpc.NewServer(
		unaryInterceptors,
		streamInterceptors,
	)

	iocpb.RegisterIoCServiceServer(grpcServer, iocHandler)
	reflection.Register(grpcServer)

	return &IoCGRPCServer{
		server: grpcServer,
		config: cfg,
		logger: log,
	}
}

func (s *IoCGRPCServer) Start() error {
	address := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		s.logger.Error("Failed to listen address", err, logger.Fields{
			"address": address,
		})
	}

	s.logger.Info("gRPC ioc-core Server is starting", logger.Fields{
		"host": s.config.Host,
		"port": s.config.Port,
	})

	// Block if error exist
	if err := s.server.Serve(listener); err != nil {
		s.logger.Error("Failed to server gRPC", err)
	}

	return nil
}

func (s *IoCGRPCServer) Stop() {
	s.logger.Info("gRPC ioc-core Server is stopping")
	s.server.GracefulStop()
	s.logger.Info("gRPC ioc-core Server has stopped")
}
