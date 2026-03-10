package iocapigatewayunit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	middleware "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/middleware"
	"github.com/DgHnG36/ioc-enrich-system/test/unit/services/commons"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupRateLimitTestRouter(t *testing.T, maxRequests int) (*gin.Engine, func()) {
	t.Helper()

	mini, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	mw := middleware.NewRateLimitMiddleware(redisClient, maxRequests, 60, zap.NewNop())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(mw.Handle())
	r.GET("/limited", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	cleanup := func() {
		_ = redisClient.Close()
		mini.Close()
	}

	return r, cleanup
}

func TestRateLimitMiddleware_AllowsUntilLimitThenBlocks(t *testing.T) {
	commons.LogTestResult(t)

	r, cleanup := setupRateLimitTestRouter(t, 2)
	defer cleanup()

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "request %d expected status %d, got %d", i+1, http.StatusOK, w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/limited", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code, "expected status %d, got %d", http.StatusTooManyRequests, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err, "failed to parse response body: %v", err)

	assert.Equal(t, "Rate limit exceeded. Please try again later.", body["message"], "unexpected message: %v", body["message"])
}

func TestRateLimitMiddleware_SetsRateLimitHeaders(t *testing.T) {
	commons.LogTestResult(t)
	r, cleanup := setupRateLimitTestRouter(t, 3)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/limited", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "expected status %d, got %d", http.StatusOK, w.Code)
	assert.Equal(t, "3", w.Header().Get("X-RateLimit-Limit"), "expected X-RateLimit-Limit=3, got %q", w.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "2", w.Header().Get("X-RateLimit-Remaining"), "expected X-RateLimit-Remaining=2, got %q", w.Header().Get("X-RateLimit-Remaining"))
}

func TestRateLimitMiddleware_AdminBypass(t *testing.T) {
	commons.LogTestResult(t)
	mini, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mini.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer redisClient.Close()

	mw := middleware.NewRateLimitMiddleware(redisClient, 1, 60, zap.NewNop())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.Use(mw.Handle())
	r.GET("/limited", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "admin request %d expected status %d, got %d", i+1, http.StatusOK, w.Code)
	}
}
