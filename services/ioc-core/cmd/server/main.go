package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/application"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/client"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/config"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/repository/postgres"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/repository/redis"
	grpchandler "github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/transport/grpc/handler" // Đổi import theo path thực tế chứa handler
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/internal/transport/grpc/interceptor"
	"github.com/DgHnG36/ioc-enrich-system/ioc-core/pkg/logger"

	iocpb "github.com/DgHnG36/ioc-enrich-system/shared/go/ioc/v1"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	appLogger := logger.New()
	if appLogger == nil {
		panic("Failed to initialize logger")
	}

	appLogger.Info("Starting ioc-core service...", logger.Fields{
		"version": cfg.App.Version,
		"env":     cfg.App.Environment,
	})

	// PostgresSQL configuration
	dbConn, err := postgres.NewConnection(&cfg.Database, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to connect to PostgreSQL", err, nil)
	}
	defer dbConn.DB.Close()

	// Redis configuration
	redisConn, err := redis.NewConnection(&cfg.Cache, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to connect to Redis", err, nil)
	}
	defer redisConn.Client.Close()

	// GRPC client configuration
	enrichClient, err := client.NewGRPCEnrichmentClient(&cfg.EnrichSvc, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to create Enrichment gRPC Client", err, nil)
	}
	defer enrichClient.Close()

	/* DEPENDENCY INJECTIONS */

	// Repositories (PostgreSQL)
	iocRepo := postgres.NewIoCRepository(dbConn.DB, appLogger)
	relatedRepo := postgres.NewRelatedIoCRepository(dbConn.DB, appLogger)
	threatRepo := postgres.NewThreatRepository(dbConn.DB, appLogger)

	// Cache Repositories (Redis)
	baseCache := redis.NewCacheRepository(redisConn.Client)
	iocCache := redis.NewIoCCacheRepository(baseCache, cfg.App.CacheTTL)       // fix env
	threatCache := redis.NewThreatCacheRepository(baseCache, cfg.App.CacheTTL) // fix env

	// Adapter and services
	enrichAdapter := application.NewEnrichAdapter(enrichClient, appLogger)

	iocServiceConfig := &application.IoCServiceConfig{
		EnableCache:      cfg.App.EnableCache,
		EnableEnrichment: cfg.App.EnableEnrichmentService,
		CacheTTL:         cfg.App.CacheTTL,
	}
	iocService := application.NewIoCService(
		iocRepo, relatedRepo, iocCache, enrichAdapter, appLogger, iocServiceConfig,
	)

	threatServiceConfig := &application.ThreatServiceConfig{
		EnableCache: cfg.App.EnableCache,
		CacheTTL:    cfg.App.CacheTTL,
	}
	threatService := application.NewThreatService(
		threatRepo, iocRepo, threatCache, threatServiceConfig, appLogger,
	)

	// Converter and handlers
	converter := grpchandler.NewConverter()
	iocHandler := grpchandler.NewIoCHandler(iocService, appLogger, converter)
	threatHandler := grpchandler.NewThreatHandler(threatService, appLogger, converter)

	// Interceptors configuration
	recoveryInterceptor := interceptor.NewRecoveryInterceptor(nil, appLogger)
	loggingInterceptor := interceptor.NewLoggingInterceptor(nil, appLogger)
	contextInterceptor := interceptor.NewContextInterceptorConfig(nil, appLogger)

	// GRPC Server configuration
	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(500),
		grpc.MaxRecvMsgSize(50*1024*1024),
		grpc.MaxSendMsgSize(50*1024*1024),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 10 * time.Second,
			Time:                  30 * time.Second,
			Timeout:               10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.ChainUnaryInterceptor(
			recoveryInterceptor.UnaryServerInterceptor(),
			loggingInterceptor.UnaryServerInterceptor(),
			contextInterceptor.UnaryServerInterceptor(),
		),
		grpc.ChainStreamInterceptor(
		// Stream interceptors (if needed)
		// recoveryInterceptor.StreamServerInterceptor(),
		// loggingInterceptor.StreamServerInterceptor(),
		),
	)

	iocpb.RegisterIoCServiceServer(grpcServer, iocHandler)
	iocpb.RegisterThreatServiceServer(grpcServer, threatHandler)

	if cfg.IsDevelopment() {
		reflection.Register(grpcServer)
	}

	listenAddr := fmt.Sprintf(":%d", cfg.GRPC.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		appLogger.Fatal("Failed to listen on port", err, logger.Fields{"addr": listenAddr})
	}

	// Run gRPC server in a separate goroutine
	go func() {
		appLogger.Info(fmt.Sprintf("gRPC ioc-core server is running on %s", listenAddr), nil)
		if err := grpcServer.Serve(listener); err != nil {
			appLogger.Fatal("gRPC ioc-core server failed", err, nil)
		}
	}()

	fmt.Printf(`
	
	`) // Format string when open service in terminal

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	appLogger.Info("Received shutdown signal. Initiating graceful shutdown...", nil)

	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	t := time.NewTimer(10 * time.Second)
	select {
	case <-t.C:
		appLogger.Warn("Graceful shutdown timed out, forcing server stop", nil)
		grpcServer.Stop()
	case <-stopped:
		t.Stop()
	}

	appLogger.Info("ioc-core service shutdown completed.", nil)
}
