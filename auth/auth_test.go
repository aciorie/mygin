package auth

// import (
// 	"encoding/json"
// 	"fmt"
// 	"mygin-restful/database"
// 	"mygin-restful/models"
// 	"strings"

// 	"net/http"
// 	"net/http/httptest"
// 	"testing"
// 	"time"

// 	"github.com/gin-gonic/gin"
// 	"github.com/golang-jwt/jwt/v4"
// 	"github.com/stretchr/testify/assert"
// 	"golang.org/x/crypto/bcrypt"
// 	"gorm.io/driver/sqlite"
// 	"gorm.io/gorm"
// )

// // setupTestDB initializes an in-memory SQLite database for testing
// func setupTestDB() *gorm.DB {
// 	// Use memory mode, ":memory:" means each connection is a brand new database
// 	// Use "file::memory:?cache=shared" to share data between different connections in the same process, but be careful to manage
// 	// Here we use a simple ":memory:" to ensure that each setup call is isolated
// 	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
// 	if err != nil {
// 		panic("Failed to connect to test database: " + err.Error())
// 	}

// 	err = db.AutoMigrate(&models.User{})
// 	if err != nil {
// 		panic("Failed to migrate test database: " + err.Error())
// 	}
// 	return db
// }

// func TestGenerateToken(t *testing.T) {
// 	user := &models.User{
// 		Model:    gorm.Model{ID: 1},
// 		Username: "testuser",
// 	}

// 	token, err := GenerateToken(user)
// 	assert.NoError(t, err)
// 	assert.NotEmpty(t, token)

// 	// Test token validation
// 	parsedToken, err := jwt.ParseWithClaims(token, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
// 		return mySigningKey, nil
// 	})
// 	assert.NoError(t, err)
// 	assert.True(t, parsedToken.Valid)

// 	claims, ok := parsedToken.Claims.(*CustomClaims)
// 	assert.True(t, ok)
// 	assert.Equal(t, user.ID, claims.UserID)
// 	assert.Equal(t, user.Username, claims.Username)
// }

// func TestAuthMiddleware(t *testing.T) {
// 	// Setup Gin router
// 	gin.SetMode(gin.TestMode)

// 	originalDB := database.DB
// 	defer func() { database.DB = originalDB }()

// 	// Test case 1: No token
// 	t.Run("No token", func(t *testing.T) {
// 		r := gin.New()
// 		r.Use(AuthMiddleware())
// 		r.GET("/protected", func(ctx *gin.Context) { ctx.String(http.StatusOK, "protected") })

// 		req, _ := http.NewRequest("GET", "/protected", nil)
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 		assert.Contains(t, w.Body.String(), "Authorization header required")
// 	})

// 	// Test case 2: Invalid token format
// 	t.Run("Invalid token format", func(t *testing.T) {
// 		r := gin.New()
// 		r.Use(AuthMiddleware())

// 		req, _ := http.NewRequest("GET", "/protected", nil)
// 		req.Header.Set("Authorization", "InvalidTokenFormat")
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 		assert.Contains(t, w.Body.String(), "Invalid authorization header format")
// 	})

// 	// Test case 3: Valid token
// 	t.Run("Valid token", func(t *testing.T) {
// 		testDB := setupTestDB()
// 		database.DB = testDB

// 		r := gin.New()
// 		r.Use(AuthMiddleware())

// 		r.GET("/protected", func(ctx *gin.Context) {
// 			userID, exists := ctx.Get("user_id")
// 			assert.True(t, exists)
// 			assert.Equal(t, uint(1), userID.(uint))
// 			username, exists := ctx.Get("username")
// 			assert.True(t, exists)
// 			assert.Equal(t, "testuser", username.(string))
// 			ctx.String(http.StatusOK, "protected")
// 		})

// 		testUser := models.User{Username: "testuser", Password: "password"} // 密码无关紧要，因为中间件不检查
// 		result := testDB.Create(&testUser)                                  // 创建用户，GORM 会自动填充 ID
// 		assert.NoError(t, result.Error)
// 		assert.NotZero(t, testUser.ID)

// 		tokenUser := models.User{Model: gorm.Model{ID: testUser.ID}, Username: testUser.Username}
// 		token, err := GenerateToken(&tokenUser)
// 		assert.NoError(t, err)

// 		req, _ := http.NewRequest("GET", "/protected", nil)
// 		req.Header.Set("Authorization", "Bearer "+token)
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusOK, w.Code)
// 		assert.Equal(t, "protected", w.Body.String())
// 	})

// 	// Test case 4: Expired token
// 	t.Run("Expired token", func(t *testing.T) {
// 		testDB := setupTestDB()
// 		database.DB = testDB

// 		r := gin.New()
// 		r.Use(AuthMiddleware())
// 		r.GET("/protected", func(ctx *gin.Context) { ctx.String(http.StatusOK, "protected") })

// 		testUser := models.User{Username: "testuser", Password: "password"}
// 		testDB.Create(&testUser)

// 		// Create an expired token
// 		claims := &CustomClaims{
// 			UserID:   testUser.ID,
// 			Username: "testuser",
// 			RegisteredClaims: jwt.RegisteredClaims{
// 				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
// 				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
// 			},
// 		}
// 		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 		signedToken, _ := token.SignedString(mySigningKey)

// 		req, _ := http.NewRequest("GET", "/protected", nil)
// 		req.Header.Set("Authorization", "Bearer "+signedToken)
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 		assert.Contains(t, w.Body.String(), "Token is either expired or not active yet")
// 	})

// }

// func TestLoginHandler(t *testing.T) {
// 	gin.SetMode(gin.TestMode)
// 	originalDB := database.DB
// 	defer func() { database.DB = originalDB }()

// 	// Helper function to create a request
// 	createLoginRequest := func(username, password string) *http.Request {
// 		loginJSON := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
// 		req, _ := http.NewRequest("POST", "/login", strings.NewReader(loginJSON))
// 		req.Header.Set("Content-Type", "application/json")
// 		return req
// 	}

// 	t.Run("Successful login", func(t *testing.T) {
// 		testDB := setupTestDB()
// 		database.DB = testDB

// 		r := gin.New()
// 		r.POST("/login", LoginHandler)

// 		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
// 		testUser := models.User{Username: "testuser", Password: string(hashedPassword)}
// 		result := testDB.Create(&testUser)
// 		assert.NoError(t, result.Error)

// 		req := createLoginRequest("testuser", "password")
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusOK, w.Code)
// 		var resp map[string]string
// 		err := json.Unmarshal(w.Body.Bytes(), &resp)
// 		assert.NoError(t, err)
// 		assert.NotEmpty(t, resp["token"], "Token should be present in successful login response")

// 		// Verify that the token is valid and contains the correct user information
// 		parsedToken, err := jwt.ParseWithClaims(resp["token"], &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
// 			return mySigningKey, nil
// 		})
// 		assert.NoError(t, err)
// 		assert.True(t, parsedToken.Valid)
// 		claims, ok := parsedToken.Claims.(*CustomClaims)
// 		assert.True(t, ok)
// 		assert.Equal(t, testUser.ID, claims.UserID) // Verify that the UserID matches the user created in the database
// 		assert.Equal(t, "testuser", claims.Username)
// 	})

// 	t.Run("Invalid credentials", func(t *testing.T) {
// 		testDB := setupTestDB()
// 		database.DB = testDB

// 		r := gin.New()
// 		r.POST("/login", LoginHandler)

// 		req := createLoginRequest("nonexistent", "wrongpassword")
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 		assert.Contains(t, w.Body.String(), "Invalid credentials")
// 	})

// 	t.Run("Incorrect password", func(t *testing.T) {
// 		testDB := setupTestDB()
// 		database.DB = testDB

// 		r := gin.New()
// 		r.POST("/login", LoginHandler)

// 		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
// 		testUser := models.User{Username: "testuser", Password: string(hashedPassword)}
// 		testDB.Create(&testUser)

// 		// Try to log in with an incorrect password
// 		req := createLoginRequest("testuser", "wrongpassword")
// 		w := httptest.NewRecorder()
// 		r.ServeHTTP(w, req)

// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 		assert.Contains(t, w.Body.String(), "Invalid credentials")
// 	})
// }

// // IDatabase is used to mock database
// type IDatabase interface {
// 	Where(query interface{}, args ...interface{}) *gorm.DB
// 	First(dest interface{}, conds ...interface{}) *gorm.DB
// 	Error() error
// 	Preload(column string, conditions ...interface{}) *gorm.DB
// }
