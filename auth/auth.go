package auth

import (
	"errors"
	"fmt"
	"mygin/database"
	"mygin/models"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// mySigningKey should be a strong, randomly generated secret key,
// and it should be stored securely (e.g., in environment variables,
// a key management service, etc.), NOT hardcoded in your source code.
var mySigningKey = []byte("mySigningKey")

// CustomClaims represents the custom claims you want to include in your JWT.
type CustomClaims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// AuthMiddleware is a Gin middleware that validates JWTs.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the Authorization header.
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Authorization header required"})
			return
		}

		// Check the token format (Bearer <token>).
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization header format"})
			return
		}
		tokenString := parts[1]

		// Parse and validate the token.
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return mySigningKey, nil
		})

		// Handle parsing errors.
		if err != nil {
			if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorMalformed != 0 {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Malformed token"})
				} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
					// Token is either expired or not active yet
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Token is either expired or not active yet"})
				} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token signature"})
				} else {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Couldn't handle this token:" + err.Error()})
				}
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Couldn't handle this token:" + err.Error()})
			}
			return
		}

		// Check if the token is valid and extract claims.
		if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
			// Store user information in the context for later use.
			c.Set("user_id", claims.UserID)
			c.Set("username", claims.Username)
			c.Next() // Proceed to the next handler.
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			return
		}
	}
}

// GenerateToken creates a new JWT for the given user.
func GenerateToken(user *models.User) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour) // Token expires in 1 hour.
	claims := &CustomClaims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "my-app",    // Replace with your application's name.
			Subject:   "user-auth", // Purpose of the token.
			//ID:        "some-unique-id",  // Optional: unique ID for the token.  Good for revocation.
			Audience: []string{"my-app-users"}, // Intended audience for the token.
		},
	}

	// Create the token with the claims and sign it.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// LoginHandler is a simplified example of a login handler.
func LoginHandler(c *gin.Context) {
	var loginVals struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginVals); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	var user models.User
	result := database.DB.Where("username = ?", loginVals.Username).First(&user)
	if result.Error != nil {
		// In a real application, don't reveal whether the user exists or not.
		// Just return a generic "Invalid credentials" error.
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}

	// Verify the password (using bcrypt).
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginVals.Password)); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}

	// Generate a token.
	token, err := GenerateToken(&user)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// UserHasPermissions checks if the user has all required permissions
func UserHasPermissions(userID uint, requiredPermissions ...string) (bool, error) {
	if len(requiredPermissions) == 0 {
		return true, nil
	}

	var user models.User
	// Preload Roles and Permissions for checking
	err := database.DB.Preload("Roles.Permissions").First(&user, userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// If the user is not found, it is also considered as no permission, but a specific signal or false is returned
			return false, fmt.Errorf("user with ID %d not found", userID)
		}
		return false, fmt.Errorf("database error checking permissions for user %d: %w", userID, err)
	}

	// Put all permissions that the user has into a map for quick lookup
	userPermissions := make(map[string]struct{})

	for _, role := range user.Roles {
		for _, perm := range role.Permissions {
			userPermissions[perm.Name] = struct{}{}
		}
	}

	// Check if the user has all required permissions
	for _, reqPerm := range requiredPermissions {
		if _, ok := userPermissions[reqPerm]; !ok {
			// If any of the required permissions are not in the user's permissions set, return false
			return false, nil
		}
	}
	return true, nil
}
