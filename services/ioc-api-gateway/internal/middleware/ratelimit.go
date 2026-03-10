package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RateLimitMiddleware struct {
	redisClient   *redis.Client
	maxRequests   int
	windowSeconds int
	logger        *zap.Logger
}

func NewRateLimitMiddleware(
	redisClient *redis.Client,
	maxRequests int,
	windowSeconds int,
	logger *zap.Logger,
) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		redisClient:   redisClient,
		maxRequests:   maxRequests,
		windowSeconds: windowSeconds,
		logger:        logger,
	}
}

func (m *RateLimitMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("roles")
		if exists {
			if roleList, ok := roles.([]string); ok {
				for _, role := range roleList {
					if role == "admin" {
						c.Next()
						return
					}
				}
			}
		}

		identifier := c.GetString("user_id")
		if identifier == "" {
			identifier = c.ClientIP()
		}

		key := fmt.Sprintf("ratelimit:%s", identifier)
		ctx := c.Request.Context()

		count, err := m.redisClient.Incr(ctx, key).Result()
		if err != nil {
			m.logger.Error("Redis rate limit error", zap.Error(err))

			c.Next()
			return
		}
		if count == 1 {
			m.redisClient.Expire(ctx, key, time.Duration(m.windowSeconds)*time.Second)
		}

		remaining := m.maxRequests - int(count)
		if remaining < 0 {
			remaining = 0
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(m.maxRequests))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if count > int64(m.maxRequests) {
			m.logger.Warn("Rate limit exceeded",
				zap.String("identifier", identifier),
				zap.Int64("count", count),
			)

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success":             false,
				"message":             "Rate limit exceeded. Please try again later.",
				"retry_after_seconds": m.windowSeconds,
			})
			return
		}

		c.Next()
	}
}
