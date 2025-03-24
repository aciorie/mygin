package controllers

import (
	"bytes"
	"encoding/json"
	"mygin/database"
	"mygin/models"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/magiconair/properties/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var r *gin.Engine

// setupTestDB initializes a test database and returns a *gorm.DB instance
func setupTestDB() *gorm.DB {
	testDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to test database")
	}
	testDB.AutoMigrate(&models.User{}) // Automatically migrate the User model
	return testDB
}

func TestCreateUser(t *testing.T) {
	if r == nil {
		r = gin.New()
		r.POST("/users", CreateUser) // Set up the route for user creation
	}

	// Test case 1: Create a user normally
	t.Run("Success", func(t *testing.T) {
		db := setupTestDB() // Get a new database connection for each test case
		tx := db.Begin()    // Start a transaction
		defer tx.Rollback() // Rollback at the end of the test
		database.DB = tx    // Use the transaction

		user := models.User{Username: "testuser1", Password: "password"}
		reqBody, _ := json.Marshal(user)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code) // Assert that the status code is 201

		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)                         // Unmarshal the response body
		assert.Equal(t, "User created successfully", resp["message"]) // Assert the success message

		// Check within the transaction
		var createdUser models.User
		tx.Where("username = ?", "testuser1").First(&createdUser) // Query the created user
		assert.Equal(t, "testuser1", createdUser.Username)        // Assert that the username matches

	})

	// Test case 2: Username already exists
	t.Run("Username already exists", func(t *testing.T) {
		db := setupTestDB() // Get a new database connection for each test case
		tx := db.Begin()
		defer tx.Rollback()
		database.DB = tx

		// Pre-insert a user
		tx.Create(&models.User{Username: "existinguser", Password: "password"})

		user := models.User{Username: "existinguser", Password: "password"}
		reqBody, _ := json.Marshal(user)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code) // Assert that the status code is 409
	})

	// Test case 3: Invalid request body
	t.Run("Invalid request body", func(t *testing.T) {
		db := setupTestDB() // Get a new database connection for each test case
		tx := db.Begin()
		defer tx.Rollback()
		database.DB = tx

		reqBody := []byte(`{"username": "testuser2"}`) // Missing password field
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code) // Assert that the status code is 400
	})
}
