package auth

import (
	"mygin/models"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {
	user := &models.User{
		Username: "testuser",
	}

	token, err := GenerateToken(user)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Test token validation
	parsedToken, err := jwt.ParseWithClaims(token, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(*CustomClaims)
	assert.True(t, ok)
	assert.Equal(t, user.Username, claims.Username)
}

func TestAuthMiddleware(t *testing.T) {
	// Setup Gin router
	r := gin.New()
	r.Use(AuthMiddleware())
	r.GET("/protected", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "protected")
	})

	// Test case 1: No token
	t.Run("No token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/protected", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Authorization header required")
	})

	// Test case 2: Invalid token format
	t.Run("Invalid token format", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "InvalidTokenFormat")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid authorization header format")
	})

	// Test case 3: Valid token
	t.Run("Valid token", func(t *testing.T) {
		user := &models.User{
			Username: "testuser",
		}
		token, _ := GenerateToken(user)

		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "protected", w.Body.String())
	})

	// Test case 4: Expired token
	t.Run("Expired token", func(t *testing.T) {
		// Create an expired token
		claims := &CustomClaims{
			Username: "testuser",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, _ := token.SignedString(mySigningKey)

		req, _ := http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+signedToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Token is either expired or not active yet")
	})
}
