package iocapigatewayunit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	middleware "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/middleware"
	"github.com/DgHnG36/ioc-enrich-system/test/unit/services/commons"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddleware_AllowsConfiguredOrigin(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	r := gin.New()
	mw := middleware.NewCORSMiddleware([]string{"http://localhost:3000"})
	r.Use(mw.Handle())
	r.GET("/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "expected status %d, got %d", http.StatusOK, w.Code)

	got := w.Header().Get("Access-Control-Allow-Origin")
	assert.Equal(t, "http://localhost:3000", got, "expected allow origin header to be set, got %q", got)
	got = w.Header().Get("Access-Control-Allow-Credentials")
	assert.Equal(t, "true", got, "expected allow credentials true, got %q", got)
}

func TestCORSMiddleware_PreflightReturnsNoContent(t *testing.T) {
	commons.LogTestResult(t)
	gin.SetMode(gin.TestMode)

	r := gin.New()
	mw := middleware.NewCORSMiddleware([]string{"http://localhost:3000"})
	r.Use(mw.Handle())
	r.OPTIONS("/resource", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code, "expected status %d, got %d", http.StatusNoContent, w.Code)
	got := w.Header().Get("Access-Control-Max-Age")
	assert.NotEmpty(t, got, "expected Access-Control-Max-Age header")
}

func TestCORSMiddleware_DoesNotSetHeaderForDisallowedOrigin(t *testing.T) {
	commons.LogTestResult(t)
	gin.SetMode(gin.TestMode)

	r := gin.New()
	mw := middleware.NewCORSMiddleware([]string{"http://localhost:3000"})
	r.Use(mw.Handle())
	r.GET("/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Origin", "http://evil.local")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "expected status %d, got %d", http.StatusOK, w.Code)
	got := w.Header().Get("Access-Control-Allow-Origin")
	assert.Equal(t, "", got, "expected no allow origin header, got %q", got)
}
