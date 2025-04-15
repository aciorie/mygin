package auth

import (
	"errors"
	"fmt"
	"mygin-restful/database"
	"mygin-restful/models"
	"net/http"
	"strings"
	"time"

	restful "github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// mySigningKey should be a strong, randomly generated secret key,
// and it should be stored securely (e.g., in environment variables,
// a key management service, etc.), NOT hardcoded in your source code.
var mySigningKey = []byte("mySigningKey")

// SetSigningKey allows setting the key from outside the package.
func SetSigningKey(key []byte) {
	if len(key) > 0 {
		mySigningKey = key
	}
}

// CustomClaims represents the custom claims you want to include in your JWT.
type CustomClaims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// // AuthMiddleware is a Gin middleware that validates JWTs.
// func AuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// Get the token from the Authorization header.
// 		authHeader := c.GetHeader("Authorization")
// 		if authHeader == "" {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Authorization header required"})
// 			return
// 		}

// 		// Check the token format (Bearer <token>).
// 		parts := strings.Split(authHeader, " ")
// 		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization header format"})
// 			return
// 		}
// 		tokenString := parts[1]

// 		// Parse and validate the token.
// 		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
// 			// Validate the signing method.
// 			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 			}
// 			return mySigningKey, nil
// 		})

// 		// Handle parsing errors.
// 		if err != nil {
// 			if ve, ok := err.(*jwt.ValidationError); ok {
// 				if ve.Errors&jwt.ValidationErrorMalformed != 0 {
// 					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Malformed token"})
// 				} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
// 					// Token is either expired or not active yet
// 					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Token is either expired or not active yet"})
// 				} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
// 					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token signature"})
// 				} else {
// 					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Couldn't handle this token:" + err.Error()})
// 				}
// 			} else {
// 				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Couldn't handle this token:" + err.Error()})
// 			}
// 			return
// 		}

// 		// Check if the token is valid and extract claims.
// 		if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
// 			// Store user information in the context for later use.
// 			c.Set("user_id", claims.UserID)
// 			c.Set("username", claims.Username)
// 			c.Next() // Proceed to the next handler.
// 		} else {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
// 			return
// 		}
// 	}
// }

// GenerateToken creates a new JWT for the given user.
func GenerateToken(user *models.User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token expires in 1 hour.
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

// // LoginHandler is a simplified example of a login handler.
// func LoginHandler(c *gin.Context) {
// 	var loginVals struct {
// 		Username string `json:"username" binding:"required"`
// 		Password string `json:"password" binding:"required"`
// 	}

// 	if err := c.ShouldBindJSON(&loginVals); err != nil {
// 		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
// 		return
// 	}

// 	var user models.User
// 	result := database.DB.Where("username = ?", loginVals.Username).First(&user)
// 	if result.Error != nil {
// 		// In a real application, don't reveal whether the user exists or not.
// 		// Just return a generic "Invalid credentials" error.
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
// 		return
// 	}

// 	// Verify the password (using bcrypt).
// 	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginVals.Password)); err != nil {
// 		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
// 		return
// 	}

// 	// Generate a token.
// 	token, err := GenerateToken(&user)
// 	if err != nil {
// 		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Could not generate token"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"token": token})
// }

// UserHasPermissions checks if the user has all required permissions
func UserHasPermissions(userID uint, requiredPermissions ...string) (bool, error) {
	if len(requiredPermissions) == 0 {
		return true, nil
	}

	var user models.User

	if database.DB == nil {
		return false, errors.New("database connection is not initialized for permission check")
	}

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

// ParseAndValidateToken : used for gRPC and middlewares
func ParseAndValidateToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return mySigningKey, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, errors.New("malformed token")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return nil, errors.New("token is either expired or not active yet")
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, errors.New("invalid token signature")
			}
		}
		return nil, fmt.Errorf("couldn't handle this token: %w", err)
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// AuthFilter creates a go-restful FilterFunction for JWT authentication.
func AuthFilter() restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		authHeader := req.HeaderParameter("Authorization")
		if authHeader == "" {
			_ = resp.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Authorization header required"}, restful.MIME_JSON)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			_ = resp.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Invalid authorization header format"}, restful.MIME_JSON)
			return
		}
		tokenString := parts[1]

		claims, err := ParseAndValidateToken(tokenString)
		if err != nil {
			_ = resp.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": err.Error()}, restful.MIME_JSON)
			return
		}

		// Store user information in request attributes for use by subsequent processing functions
		req.SetAttribute("user_id", claims.UserID)
		req.SetAttribute("username", claims.Username)

		// Continue handling the chain
		chain.ProcessFilter(req, resp)
	}
}

// --- go-restful login processing function ---

// LoginCredentials defines the structure of the login request
type LoginCredentials struct {
	Username string `json:"username" description:"Username for login"`
	Password string `json:"password" description:"Password for login"`
}

// LoginResponse defines the structure of the login response
type LoginResponse struct {
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// LoginRouteHandler handles the /login route using go-restful.
func LoginRouteHandler(request *restful.Request, response *restful.Response) {
	creds := new(LoginCredentials)
	err := request.ReadEntity(creds)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, LoginResponse{Message: "Invalid request body: " + err.Error()}, restful.MIME_JSON)
		return
	}

	if creds.Username == "" || creds.Password == "" {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, LoginResponse{Message: "Username and password are required"}, restful.MIME_JSON)
		return
	}

	var user models.User
	// Assume database.DB is globally accessible or obtained via dependency injection
	result := database.DB.Where("username = ?", creds.Username).First(&user)
	if result.Error != nil {
		// Avoid revealing whether the user exists
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, LoginResponse{Message: "Invalid credentials"}, restful.MIME_JSON)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, LoginResponse{Message: "Invalid credentials"}, restful.MIME_JSON)
		return
	}

	token, err := GenerateToken(&user)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusInternalServerError, LoginResponse{Message: "Could not generate token"}, restful.MIME_JSON)
		return
	}

	_ = response.WriteHeaderAndJson(http.StatusOK, LoginResponse{Token: token}, restful.MIME_JSON)
}
