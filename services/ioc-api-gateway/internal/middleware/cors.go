package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type CORSMiddleware struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
}

func NewCORSMiddleware(allowedOrigins []string) *CORSMiddleware {
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	}

	// Default CORS configuration
	return &CORSMiddleware{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-length", "X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
}

func (m *CORSMiddleware) Handle() gin.HandlerFunc {
	allowMethods := strings.Join(m.AllowMethods, ", ")
	allowHeaders := strings.Join(m.AllowHeaders, ", ")
	exposeHeaders := strings.Join(m.ExposeHeaders, ", ")

	maxAgeStr := strconv.Itoa(int(m.MaxAge.Seconds()))

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if origin != "" && m.isOriginAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", allowMethods)
			c.Header("Access-Control-Allow-Headers", allowHeaders)
			c.Header("Access-Control-Expose-Headers", exposeHeaders)
			if m.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
			c.Header("Access-Control-Max-Age", maxAgeStr)
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (m *CORSMiddleware) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range m.AllowOrigins {
		if m.matchOrigin(origin, allowed) {
			return true
		}
	}

	return false
}

func (m *CORSMiddleware) matchOrigin(origin, allowed string) bool {
	if origin == allowed {
		return true
	}

	if strings.HasPrefix(allowed, "*.") {
		domain := strings.TrimPrefix(allowed, "*.")
		return strings.HasSuffix(origin, "."+domain)
	}

	if allowed == "*" {
		return true
	}

	return false
}
