package router

import (
	"net/http"
	"time"

	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/middleware"
	"github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/transport/grpc/handler"
	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func SetupRouter(
	iocHandler *handler.IoCHandler,
	threatHandler *handler.ThreatHandler,
	authMiddleware *middleware.AuthMiddleware,
	rateLimitMiddleware *middleware.RateLimitMiddleware,
	corsMiddleware *middleware.CORSMiddleware,
	logger *zap.Logger,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Global middleware
	r.Use(gin.Recovery())
	r.Use(requestID())
	r.Use(requestLogger(logger))
	r.Use(corsMiddleware.Handle())

	// Public routers
	r.GET("/health", healthCheck)
	r.GET("/ready", readinessCheck(iocHandler, threatHandler))
	r.GET("/metrics", metricsHandler)

	// API v1
	v1 := r.Group("/api/v1")
	{
		protected := v1.Group("")
		protected.Use(authMiddleware.Handle())
		protected.Use(rateLimitMiddleware.Handle())
		{
			// IoC routes
			iocs := protected.Group("/iocs")
			{
				iocs.GET("/:id", iocHandler.GetIoC)
				iocs.GET("/value/:value", iocHandler.GetByValue)
				iocs.POST("/find", iocHandler.FindIoCs)
				iocs.POST("/batch", iocHandler.BatchUpsertIoCs)
				iocs.DELETE("/batch", iocHandler.DeleteIoCs)
				iocs.GET("/stats", iocHandler.GetIoCStatistics)
				iocs.GET("/expired", iocHandler.GetExpired)
				iocs.POST("/:id/detect", iocHandler.IncrementDetectionCount)
				iocs.POST("/:id/enrich", iocHandler.EnrichIoC)
				iocs.GET("/:id/enrich/status", iocHandler.GetEnrichmentStatus)
				iocs.GET("/:id/related", iocHandler.GetRelatedIoCs)
			}

			// Threat routes
			threats := protected.Group("/threats")
			{
				threats.GET("/:id", threatHandler.GetThreat)
				threats.POST("/find", threatHandler.FindThreats)
				threats.POST("/batch", threatHandler.BatchUpsertThreats)
				threats.DELETE("/batch", threatHandler.DeleteThreats)
				threats.GET("/stats", threatHandler.GetThreatStatistics)
				threats.GET("/by-ioc/:ioc_id", threatHandler.GetThreatsByIoC)
				threats.GET("/by-ttp", threatHandler.GetThreatsByTTP)
				threats.POST("/correlate", threatHandler.CorrelateThreat)
				threats.POST("/:id/link", threatHandler.LinkIoCs)
				threats.POST("/:id/unlink", threatHandler.UnlinkIoCs)
			}
		}
	}
	return r
}
func requestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		path := ctx.Request.URL.Path

		ctx.Next()

		latency := time.Since(start)
		logger.Info(
			"HTTP Request",
			zap.Int("status", ctx.Writer.Status()),
			zap.String("method", ctx.Request.Method),
			zap.String("path", path),
			zap.Duration("latency", latency),
			zap.String("ip", ctx.ClientIP()),
			zap.String("request_id", ctx.GetString("request_id")),
			zap.String("user_id", ctx.GetString("user_id")),
		)
	}
}

func requestID() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		reqID := ctx.GetHeader("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}

		ctx.Set("request_id", reqID)
		ctx.Header("X-Request-ID", reqID)
		ctx.Next()
	}
}

func healthCheck(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

func readinessCheck(iocHandler *handler.IoCHandler, threatHandler *handler.ThreatHandler) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if err := iocHandler.Ping(); err != nil {
			ctx.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "IoC service is not ready",
			})

			return
		}
		if err := threatHandler.Ping(); err != nil {
			ctx.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "Threat service is not ready",
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"status": "ready",
		})
	}
}

func metricsHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"status": "metrics endpoint",
	})
}
