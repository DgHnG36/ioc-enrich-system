package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/client"
	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/middleware"
	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/router"
	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/handler"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Logger initialized failed: %v", err)
	}
	defer logger.Sync()

	// Can be fixed later
	port := getEnvOrDefault("PORT", "8080")
	grpcCoreAddr := getEnvOrDefault("GRPC_CORE_ADDR", "localhost:55001")
	redisAddr := getEnvOrDefault("REDIS_ADDR", "localhost:6379")
	redisPassword := getEnvOrDefault("REDIS_PASSWORD", "")
	redisDB := getEnvAsInt("REDIS_DB", 0)
	jwtSecret := getEnvOrDefault("JWT_SECRET", "JWT_SECRET_DEFAULT")
	allowedOrigins := getEnvOrDefault("ALLOWED_ORIGIN", "*")

	// Redis configuration
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Fatal("Connect to Redis failed", zap.Error(err))
	}
	logger.Info("Connect to Redis successfully", zap.String("addr", redisAddr))

	// gRPC client configuration
	grpcClientConfig := client.Config{
		IoCCoreAddr:    grpcCoreAddr,
		ConnectTimeout: 5 * time.Second,
	}
	grpcGatewayClient, err := client.NewGatewayClient(grpcClientConfig, logger)
	if err != nil {
		logger.Fatal("Initialize gRPC client failed", zap.Error(err))
	}

	// Converter and handlers configuration
	converter := handler.NewConverter()
	iocHandler := handler.NewIoCHandler(grpcGatewayClient, converter, logger)
	threatHandler := handler.NewThreatHandler(grpcGatewayClient, converter, logger)

	// Middleware configuration
	authMiddleware := middleware.NewAuthMiddleware([]byte(jwtSecret), logger)
	rateLimitMiddleware := middleware.NewRateLimitMiddleware(
		redisClient,
		getEnvAsInt("RATE_LIMIT_MAX_REQ", 100),
		getEnvAsInt("RATE_LIMIT_WINDOW_SEC", 60),
		logger,
	)

	corsMiddleware := middleware.NewCORSMiddleware(strings.Split(allowedOrigins, ","))

	// Router configuration
	engine := router.SetupRouter(
		iocHandler,
		threatHandler,
		authMiddleware,
		rateLimitMiddleware,
		corsMiddleware,
		logger,
	)

	// HTTP Server configuration
	httpReadTimeout := getEnvAsTime("HTTP_READ_TIMEOUT", 10*time.Second)
	httpWriteTimeout := getEnvAsTime("HTTP_WRITE_TIMEOUT", 10*time.Second)
	httpIdleTimeout := getEnvAsTime("HTTP_IDLE_TIMEOUT", 120*time.Second)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      engine,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
		IdleTimeout:  httpIdleTimeout,
	}

	// Run server in a separate goroutine
	go func() {
		logger.Info("Starting IoC API Gateway server...", zap.String("addr", srv.Addr), zap.String("port", port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("Run HTTP Server failed", zap.Error(err))
		}

		fmt.Printf(`
		
		
		`) // Fix render image letter
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutdown IoC API Gateway server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exiting")
}

/* HELPER METHODS */

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	strValue := getEnvOrDefault(key, "")
	if strValue == "" {
		return fallback
	}

	value, err := strconv.Atoi(strValue)
	if err != nil {
		return fallback
	}

	return value
}

func getEnvAsTime(key string, fallback time.Duration) time.Duration {
	strValue := getEnvOrDefault(key, "")
	if strValue == "" {
		return fallback
	}
	value, err := time.ParseDuration(strValue)
	if err != nil {
		return fallback
	}
	return value
}
