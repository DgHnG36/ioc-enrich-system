package iocapigatewayunit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	middleware "github.com/DgHnG36/ioc-enrich-system/ioc-api-gateway/internal/middleware"
	"github.com/DgHnG36/ioc-enrich-system/test/unit/services/commons"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAuthMiddleware_SkipPathHealth(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	r := gin.New()
	mw := middleware.NewAuthMiddleware([]byte("super-secret"), zap.NewNop())
	r.Use(mw.Handle())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "expected status %d, got %d", http.StatusOK, w.Code)
}

func TestAuthMiddleware_MissingAuthorizationHeader(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	r := gin.New()

	jwtSecret := []byte("super-secret")
	mw := middleware.NewAuthMiddleware(jwtSecret, zap.NewNop())
	r.Use(mw.Handle())

	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok": true,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected status %d, got %d", http.StatusUnauthorized, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err, "Failed to decode response: %v", err)
	assert.Equal(t, "Missing authorization header", body["message"], "expected missing authorization message, got %v", body["message"])
}

func TestAuthMiddleware_InvalidAuthorizationFormat(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	jwtSecret := []byte("super-secret")
	r := gin.New()

	mw := middleware.NewAuthMiddleware(jwtSecret, zap.NewNop())
	r.Use(mw.Handle())
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok": true,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "invalid token format")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected status %d, got %d", http.StatusUnauthorized, w.Code)

}

func TestAuthMiddleware_ValidTokenSetsContext(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	secret := "super-secret"
	token, err := middleware.GenerateToken(secret, "1234567890", "tester", []string{"user"}, 30)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	r := gin.New()
	mw := middleware.NewAuthMiddleware([]byte(secret), zap.NewNop())
	r.Use(mw.Handle())

	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":  c.GetString("user_id"),
			"username": c.GetString("username"),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "expected status %d, got %d", http.StatusOK, w.Code)

	var body map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err, "Failed to decode response: %v", err)

	assert.Equal(t, "1234567890", body["user_id"], "expected user_id 1234567890, got %v", body["user_id"])
	assert.Equal(t, "tester", body["username"], "expected username tester, got %v", body["username"])
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	secret := "super-secret"
	token, err := middleware.GenerateToken(secret, "1234567890", "tester", []string{"user"}, -1)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	r := gin.New()
	mw := middleware.NewAuthMiddleware([]byte(secret), zap.NewNop())
	r.Use(mw.Handle())

	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":  c.GetString("user_id"),
			"username": c.GetString("username"),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected status %d, got %d", http.StatusUnauthorized, w.Code)

}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	commons.LogTestResult(t)

	gin.SetMode(gin.TestMode)

	secret := "super-secret"
	invalidToken := "this.is.an.invalid.token"

	r := gin.New()
	mw := middleware.NewAuthMiddleware([]byte(secret), zap.NewNop())
	r.Use(mw.Handle())
	r.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":  c.GetString("user_id"),
			"username": c.GetString("username"),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected status %d, got %d", http.StatusUnauthorized, w.Code)
}
