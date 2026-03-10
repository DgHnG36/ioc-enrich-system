package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type JWTClaims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

type AuthMiddleware struct {
	jwtSecret    []byte
	jwtAlgorithm string
	logger       *zap.Logger
	skipPaths    map[string]bool
}

func NewAuthMiddleware(jwtSecret []byte, logger *zap.Logger) *AuthMiddleware {
	skipPathsMap := map[string]bool{
		"/health":  true,
		"/metrics": true,
		"/ready":   true,
	}

	return &AuthMiddleware{
		jwtSecret:    jwtSecret,
		jwtAlgorithm: "HS256",
		logger:       logger,
		skipPaths:    skipPathsMap,
	}
}

func (m *AuthMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.skipPaths[c.Request.URL.Path] {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.unauthorizedResponse(c, "Missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			m.unauthorizedResponse(c, "Invalid authorization header format")
			return
		}

		tokenString := parts[1]
		claims, err := m.validateToken(tokenString)
		if err != nil {
			m.logger.Warn("Invalid token attempt", zap.Error(err))
			m.unauthorizedResponse(c, "Invalid or expired token")
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

func (m *AuthMiddleware) validateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

func (m *AuthMiddleware) unauthorizedResponse(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"message": message,
	})
	c.Abort()
}

/* HELPER METHODS */

func GenerateToken(jwtSecret string, userID string, username string, roles []string, expirationMinutes int) (string, error) {
	claims := &JWTClaims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expirationMinutes) * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "ioc-api-gateway",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func RefreshToken(jwtSecret string, tokenString string, expirationMinutes int) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	}, jwt.WithExpirationRequired())

	if err != nil {
		return "", fmt.Errorf("could not parse token: %v", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Duration(expirationMinutes) * time.Minute))
		claims.IssuedAt = jwt.NewNumericDate(time.Now())

		newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		return newToken.SignedString([]byte(jwtSecret))
	}
	return "", fmt.Errorf("invalid token claims")
}
