package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mygin/auth"
	"mygin/database"
	"mygin/models"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var r *gin.Engine

// Global variables store test router instances
var testRouter *gin.Engine

// ------Helper function------
// Helper: Create a user with the specified role (password will be hashed)
func createTestUserWithRoles(db *gorm.DB, username, password, email string, roleNames ...string) (models.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	user := models.User{
		Username: username,
		Password: string(hashedPassword),
		Email:    email,
	}

	if err := db.Create(&user).Error; err != nil {
		return models.User{}, fmt.Errorf("failed to create user %s: %w", username, err)
	}

	if len(roleNames) > 0 {
		var roles []models.Role
		if err := db.Where("name IN ?", roleNames).Find(&roles).Error; err != nil {
			return user, fmt.Errorf("failed to find roles %v: %w", roleNames, err)
		}
		if len(roles) > 0 {
			if err := db.Model(&user).Association("Roles").Append(roles); err != nil {
				return user, fmt.Errorf("failed to associate roles with user %s: %w", username, err)
			}
		} else {
			fmt.Printf("Warning: Roles %v not found for user %s\n", roleNames, username)
		}
	}
	// Users need to be reloaded to include associated roles
	db.Preload("Roles").First(&user, user.ID)
	return user, nil
}

// Helper: Create a role with specified permissions
func createTestRoleWithPermissions(db *gorm.DB, roleName, description string, permissionNames ...string) (models.Role, error) {
	role := models.Role{
		Name:        roleName,
		Description: description,
	}
	// Try to find or create a role
	if err := db.Where(models.Role{Name: roleName}).FirstOrCreate(&role).Error; err != nil {
		return models.Role{}, fmt.Errorf("failed to find or create role %s: %w", roleName, err)
	}

	if len(permissionNames) > 0 {
		var permissions []models.Permission
		// Make sure permissions exist
		for _, pName := range permissionNames {
			perm := models.Permission{Name: pName}
			if err := db.Where(models.Permission{Name: pName}).FirstOrCreate(&perm).Error; err != nil {
				return role, fmt.Errorf("failed to ensure permission %s exists: %w", pName, err)
			}
			permissions = append(permissions, perm)
		}

		// Replace the association to ensure only the specified permissions are available
		if err := db.Model(&role).Association("Permissions").Replace(permissions); err != nil {
			return role, fmt.Errorf("failed to associate permissions with role %s: %w", roleName, err)
		}
	}
	// Reload the role to include the permissions
	db.Preload("Permissions").First(&role, role.ID)
	return role, nil
}

// Helper: Generate Token for User
func generateTokenForUser(user models.User) (string, error) {
	// Note: GenerateToken requires user.ID, make sure the passed user object has an ID
	if user.ID == 0 {
		return "", fmt.Errorf("user must have a valid ID to generate token")
	}
	return auth.GenerateToken(&user)
}

// --- Ensure basic roles and permissions exist in TestMain or setupTestDB ---
// If SeedInitialData has already created the 'user', 'admin' roles and related permissions,
// and the test relies on these default settings, then explicit creation may not be necessary here.
// But for test independence and clarity, it is usually better to explicitly create the roles and permissions required by the test.
func setupRolesAndPermissions(db *gorm.DB) {
	// Ensure basic permissions exist (if AutoMigrate does not process seed data)
	permissions := []string{
		"users:read:self", "users:update:self", "users:delete:self", // User permissions
		"users:read:all", "users:update:all", "users:delete:all", "users:list", // Admin/Manager permissions
		"roles:manage",
	}
	for _, pName := range permissions {
		perm := models.Permission{Name: pName}
		// FirstOrCreate avoid duplicate creation
		if err := db.Where(models.Permission{Name: pName}).FirstOrCreate(&perm).Error; err != nil {
			panic(fmt.Sprintf("Failed to ensure permission %s: %v", pName, err))
		}
	}

	// Create the roles required for testing and associate permissions
	_, err := createTestRoleWithPermissions(db, "test_user_role", "Basic user role for testing", "users:read:self", "users:update:self")
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_user_role: %v", err))
	}
	_, err = createTestRoleWithPermissions(db, "test_admin_role", "Admin role for testing", "users:read:all", "users:update:all", "users:list")
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_admin_role: %v", err))
	}
	_, err = createTestRoleWithPermissions(db, "test_viewer_role", "Viewer role for testing", "users:read:all", "users:list")
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_viewer_role: %v", err))
	}
	_, err = createTestRoleWithPermissions(db, "test_no_perms_role", "Role with no user permissions", "roles:manage") // Example role with unrelated perms
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_no_perms_role: %v", err))
	}
}

// --- Modify setupTestDB to call role permission settings ---
func setupTestDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to test database: " + err.Error())
	}
	err = db.AutoMigrate(&models.User{}, &models.Role{}, &models.Permission{})
	if err != nil {
		panic("Failed to migrate test database: " + err.Error())
	}
	// Set up roles and permissions required for testing after migration
	setupRolesAndPermissions(db)
	return db
}

// setupRouter sets up a Gin engine and necessary routes for testing
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Register user controller related routes
	r.POST("/users", CreateUser)
	// Add routes to be tested
	// Note: Routes that require authentication are usually placed in a Group and AuthMiddleware is applied
	// For simplicity, register directly here, but you still need to manually simulate the authentication process (add Token) when testing
	userRoutes := r.Group("/users")
	userRoutes.Use(auth.AuthMiddleware()) // Apply authentication middleware to routes under /users
	{
		userRoutes.GET("/:id", GetUserByID)
		userRoutes.PUT("/:id", UpdateUser)
		userRoutes.GET("", ListUsers) // GET /users
		// If there is DeleteUser, also add userRoutes.DELETE("/:id", DeleteUser) here
	}

	return r
}

// TestMain will be executed before all tests in the package are run
func TestMain(m *testing.M) {
	// Setting up a global test router
	fmt.Println("Setting up test router...") // Add log to confirm execution
	testRouter = setupRouter()

	// Run all tests in a package
	exitCode := m.Run()

	// Exit
	os.Exit(exitCode)
}

// TestCreateUser tests the user creation function
func TestCreateUser(t *testing.T) {
	// Each test function gets its own routing instance
	r := testRouter
	assert.NotNil(t, r, "Test router should not be nil") // Make sure testRouter is initialized

	// --- Test Case 1: Successfully created user ---
	t.Run("Success", func(t *testing.T) {
		// Get a new database connection for each test case
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close() // Close the database connection after the test is completed

		// Use transactions to isolate database operations
		tx := db.Begin()
		// **Key**: Save the original global DB and point the global DB to the current transaction
		originalDB := database.DB
		database.DB = tx
		// **Key**: After testing, be sure to rollback the transaction and restore the original global DB
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()

		// Prepare the request body
		userInput := gin.H{
			"username": "testuser_success",
			"password": "password123",
			"email":    "success@example.com",
			"nickname": "tester",
		}
		reqBody, _ := json.Marshal(userInput)

		// Build a HTTP request
		req, _ := http.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")

		// Execute the request
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code) // Assert that the status code is 201

		var resp UserResponse // Assume CreateUser returns a UserResponse structure
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "testuser_success", resp.Username)
		assert.Equal(t, "success@example.com", resp.Email)
		assert.Equal(t, "tester", resp.Nickname)
		assert.NotZero(t, resp.ID) // ID should be automatically populated by GORM

		// Assert database status (check inside a transaction)
		var createdUser models.User
		result := tx.Where("username = ?", "testuser_success").First(&createdUser)
		assert.NoError(t, result.Error)
		assert.Equal(t, "testuser_success", createdUser.Username)
		assert.Equal(t, "success@example.com", createdUser.Email)
		assert.Equal(t, "tester", createdUser.Nickname)
		assert.NotEmpty(t, createdUser.Password) // The password should be hashed, not empty
	})

	// --- Test Case 2: Username already exists ---
	t.Run("Username already exists", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()

		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()

		// Pre-insert a user inside the transcations
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		existingUser := models.User{Username: "existinguser", Password: string(hashedPassword), Email: "existing@example.com"}
		tx.Create(&existingUser)

		// Prepare the request body (using an existing username)
		userInput := gin.H{
			"username": "existinguser",
			"password": "password123",
			"email":    "another@example.com",
		}
		reqBody, _ := json.Marshal(userInput)

		// Create and execute the request
		req, _ := http.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		// Assert error response message
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp["message"], "Username already exists")
	})

	// --- Test Case 3: Email already exists ---
	t.Run("Email already exists", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()

		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()

		// Pre-insert a user
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		existingUser := models.User{Username: "anotheruser", Password: string(hashedPassword), Email: "existingemail@example.com"}
		tx.Create(&existingUser)

		// Prepare the request body (using an existing Email)
		userInput := gin.H{
			"username": "newuser",
			"password": "password123",
			"email":    "existingemail@example.com",
		}
		reqBody, _ := json.Marshal(userInput)

		req, _ := http.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp["message"], "Email already exists")
	})

	// --- Test Case 4: Invalid request body (missing required fields) ---
	t.Run("Invalid request body - missing password", func(t *testing.T) {
		// This test case theoretically does not access the database, but for consistency, DB is still set
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()

		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()

		// Prepare the request body for a missing password
		reqBody := []byte(`{"username": "testuser_invalid", "email": "invalid@example.com"}`)

		req, _ := http.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// Assert error response message (should contain field validation error information)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp["message"], "Invalid request body")

		// Can further assert specific binding errors, but this depends on the specific error format of Gin
		// assert.Contains(t, resp["message"], "Password")
	})

	// --- Test Case 5: Invalid Email Format ---
	t.Run("Invalid email format", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()

		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()

		userInput := gin.H{
			"username": "testuser_email",
			"password": "password123",
			"email":    "invalid-email-format", // Invalid format
		}
		reqBody, _ := json.Marshal(userInput)

		req, _ := http.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		// Gin binding errors usually contain field information
		assert.Contains(t, resp["message"], "Email")
		assert.Contains(t, resp["message"], "email") // The email format is incorrect
	})
}

/*
UpdateUser, GetUserByID and ListUsers:

1. Authentication and Authorization: These interfaces require user authentication, and most have permission requirements. During testing, it is necessary to:

	Create users, roles, and permissions in the test database.
	Generate a JWT Token for the user initiating the request.
	Include Authorization: Bearer <token> in the request header.
	Test behaviors under different permission combinations (success, access denied).

2. Data Preparation: Based on the test scenarios, prepare the data in the database after the transaction begins and before executing the HTTP requests (for example, the user to be updated or retrieved, the list of users to be listed).

3. Scenario Coverage: Test successful paths, resource not found (404), insufficient permissions (403), unauthenticated (401), invalid input (400), and other situations.

4. Reuse Setup: Continue using setupTestDB and setupRouter, and you may need to add some helper functions to create users with specific roles or generate Tokens to reduce code duplication.
*/

// TestUpdateUser Test update user information
func TestUpdateUser(t *testing.T) {
	r := setupRouter()

	// --- Test Case: Successfully updated my information (nickname and email) ---
	t.Run("Success - Update Self Nickname and Email", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()

		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()

		// Prepare users and tokens (requires users:update:self permission)
		testUser, err := createTestUserWithRoles(tx, "updateuser", "password", "update@example.com", "test_user_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(testUser)
		assert.NoError(t, err)

		// Prepare the request body
		updateData := gin.H{
			"nickname": "Updated Nickname",
			"email":    "updated.email@example.com",
		}
		reqBody, _ := json.Marshal(updateData)

		// Send the request
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(testUser.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp UserResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "Updated Nickname", resp.Nickname)
		assert.Equal(t, "updated.email@example.com", resp.Email)
		assert.Equal(t, testUser.Username, resp.Username) // Username should not be changed

		// Asserting database status
		var updatedUser models.User
		tx.First(&updatedUser, testUser.ID)
		assert.Equal(t, "Updated Nickname", updatedUser.Nickname)
		assert.Equal(t, "updated.email@example.com", updatedUser.Email)
	})

	// --- Test Case: Successfully updated own password ---
	t.Run("Success - Update Self Password", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		testUser, err := createTestUserWithRoles(tx, "updatepass", "oldpassword", "pass@example.com", "test_user_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(testUser)
		assert.NoError(t, err)

		updateData := gin.H{"password": "newStrongPassword"}
		reqBody, _ := json.Marshal(updateData)

		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(testUser.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify that the password in the database has been updated (compare hashes)
		var updatedUser models.User
		tx.First(&updatedUser, testUser.ID)
		// Verify that the new password matches the updated hash
		err = bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte("newStrongPassword"))
		assert.NoError(t, err, "New password should match the updated hash")
		// Verify that the old password no longer matches
		err = bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte("oldpassword"))
		assert.Error(t, err, "Old password should no longer match")
	})

	// --- Test Case: Administrator successfully updates other user information ---
	t.Run("Success - Admin Update Other User", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create administrator and target user
		adminUser, err := createTestUserWithRoles(tx, "adminupdater", "password", "admin@update.com", "test_admin_role") // 需要 users:update:all
		assert.NoError(t, err)
		targetUser, err := createTestUserWithRoles(tx, "targetuser", "password", "target@update.com", "test_user_role")
		assert.NoError(t, err)

		adminToken, err := generateTokenForUser(adminUser)
		assert.NoError(t, err)

		updateData := gin.H{"nickname": "Updated by Admin"}
		reqBody, _ := json.Marshal(updateData)

		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(targetUser.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// ... assert the response body and database ...
		var updatedUser models.User
		tx.First(&updatedUser, targetUser.ID)
		assert.Equal(t, "Updated by Admin", updatedUser.Nickname)

	})

	// --- Test Case: Failure - Tried to update other people's information but didn't have permission ---
	t.Run("Failure - Update Other No Permission", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create normal users A and B
		userA, err := createTestUserWithRoles(tx, "userA_update", "password", "a@update.com", "test_user_role") // 只有 update:self
		assert.NoError(t, err)
		userB, err := createTestUserWithRoles(tx, "userB_update", "password", "b@update.com", "test_user_role")
		assert.NoError(t, err)

		tokenA, err := generateTokenForUser(userA)
		assert.NoError(t, err)

		updateData := gin.H{"nickname": "Attempted Update"}
		reqBody, _ := json.Marshal(updateData)

		// User A try to update User B
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(userB.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokenA)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code) // Insufficient permissions
	})

	// --- Test Case: Failure - updating a non-existent user ---
	t.Run("Failure - User Not Found", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create an administrator with the authority to update anyone
		adminUser, err := createTestUserWithRoles(tx, "adminupdater_nf", "password", "admin_nf@update.com", "test_admin_role")
		assert.NoError(t, err)
		adminToken, err := generateTokenForUser(adminUser)
		assert.NoError(t, err)

		nonExistentUserID := uint(99999)
		updateData := gin.H{"nickname": "Wont Update"}
		reqBody, _ := json.Marshal(updateData)

		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(nonExistentUserID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	//--- Test Case: Failure - Email Conflict ---
	t.Run("Failure - Email Conflict", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		user1, err := createTestUserWithRoles(tx, "emailuser1", "password", "email1@conflict.com", "test_user_role")
		assert.NoError(t, err)
		user2, err := createTestUserWithRoles(tx, "emailuser2", "password", "email2@conflict.com", "test_user_role") // User 2 的 email
		assert.NoError(t, err)

		token1, err := generateTokenForUser(user1)
		assert.NoError(t, err)

		// User 1 tries to update his email to the email already used by User 2
		updateData := gin.H{"email": user2.Email}
		reqBody, _ := json.Marshal(updateData)

		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(user1.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token1)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Contains(t, resp["message"], "Email address is already in use")
	})

	// --- Test Case: Failed - Token not provided ---
	t.Run("Failure - No Auth Token", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		user, err := createTestUserWithRoles(tx, "noauthupdate", "password", "noauth@update.com", "test_user_role")
		assert.NoError(t, err)

		updateData := gin.H{"nickname": "No Auth Update"}
		reqBody, _ := json.Marshal(updateData)

		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(user.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// AuthMiddleware should be banned
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// TODO: Add more test cases (invalid input: wrong email format, password too short, etc.)
}

// TestGetUserByID Test to obtain single user information
func TestGetUserByID(t *testing.T) {
	r := setupRouter()

	// --- Test Case: Successfully obtain your own information ---
	t.Run("Success - Read Self", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// The user needs users:read:self permission
		testUser, err := createTestUserWithRoles(tx, "readselfuser", "password", "self@read.com", "test_user_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(testUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(testUser.ID), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp UserResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, testUser.ID, resp.ID)
		assert.Equal(t, testUser.Username, resp.Username)
		assert.Equal(t, testUser.Email, resp.Email)
	})

	// --- Test Case: Successfully obtain other people's information (requires users:read:all) ---
	t.Run("Success - Read Other With Permission", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create administrator and target user
		adminUser, err := createTestUserWithRoles(tx, "adminreader", "password", "admin@read.com", "test_admin_role") // 有 read:all
		assert.NoError(t, err)
		targetUser, err := createTestUserWithRoles(tx, "targetreader", "password", "target@read.com", "test_user_role")
		assert.NoError(t, err)

		adminToken, err := generateTokenForUser(adminUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(targetUser.ID), nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp UserResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, targetUser.ID, resp.ID)
		assert.Equal(t, targetUser.Username, resp.Username)

	})

	// --- Test Case: Failed - Tried to get other people's information but didn't have permission ---
	t.Run("Failure - Read Other No Permission", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		userA, err := createTestUserWithRoles(tx, "userA_read", "password", "a@read.com", "test_user_role") // 只有 read:self
		assert.NoError(t, err)
		userB, err := createTestUserWithRoles(tx, "userB_read", "password", "b@read.com", "test_user_role")
		assert.NoError(t, err)

		tokenA, err := generateTokenForUser(userA)
		assert.NoError(t, err)

		// User A try to access User B
		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(userB.ID), nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// --- Test Case: Failed - Tried to get self information but did not have read:self permission ---
	t.Run("Failure - Read Self No Permission", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create a user without the read:self permission
		noPermUser, err := createTestUserWithRoles(tx, "noperm_read", "password", "noperm@read.com", "test_no_perms_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(noPermUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(noPermUser.ID), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code) // Should be banned
	})

	// --- Test Case: Failure - Get a non-existent user ---
	t.Run("Failure - User Not Found", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		adminUser, err := createTestUserWithRoles(tx, "adminreader_nf", "password", "admin_nf@read.com", "test_admin_role") // 需要有权限才能尝试读取
		assert.NoError(t, err)
		adminToken, err := generateTokenForUser(adminUser)
		assert.NoError(t, err)

		nonExistentUserID := uint(99998)
		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(nonExistentUserID), nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// --- Test Case: Failed - Token not provided ---
	t.Run("Failure - No Auth Token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/users/1", nil) // It doesn't matter whether ID 1 exists
		// No Authorization header
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// TestListUsers Test to get the user list (pagination)
func TestListUsers(t *testing.T) {
	r := setupRouter()

	// --- Test Case: Successfully obtain the user list (requires users:list permission) ---
	t.Run("Success - List Users With Permission", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create a user with list permission
		listUser, err := createTestUserWithRoles(tx, "listuser", "password", "list@example.com", "test_admin_role") // admin role has 'users:list'
		assert.NoError(t, err)
		token, err := generateTokenForUser(listUser)
		assert.NoError(t, err)

		// Create some other users for list display
		_, err = createTestUserWithRoles(tx, "user1_list", "password", "u1@list.com", "test_user_role")
		assert.NoError(t, err)
		_, err = createTestUserWithRoles(tx, "user2_list", "password", "u2@list.com", "test_user_role")
		assert.NoError(t, err)
		// ... May need to create more users to test paging ...
		var totalUsers int64
		tx.Model(&models.User{}).Count(&totalUsers) // Get the total number of users

		req, _ := http.NewRequest(http.MethodGet, "/users?page=1&page_size=10", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp PaginatedUsersResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)

		assert.Equal(t, totalUsers, resp.Total) // Verify the total number of users
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, 10, resp.PageSize)
		// Verify the number of users returned (depends on pageSize and totalUsers)
		expectedCount := int(totalUsers)
		if expectedCount > 10 {
			expectedCount = 10
		}
		assert.Len(t, resp.Users, expectedCount)
		// Can further check whether the returned user information is correct, such as user name, etc.
		foundListUser := false
		for _, u := range resp.Users {
			if u.Username == "listuser" {
				foundListUser = true
				break
			}
		}
		assert.True(t, foundListUser, "Requesting user should be in the list")

	})

	// --- Test Case: Successfully obtain the user list - test paging ---
	t.Run("Success - List Users Pagination", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		listUser, err := createTestUserWithRoles(tx, "pageruser", "password", "pager@example.com", "test_admin_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(listUser)
		assert.NoError(t, err)

		// Create more than one page of users (for example, create 12, plus listUser 13 in total)
		for i := 0; i < 12; i++ {
			_, err = createTestUserWithRoles(tx, fmt.Sprintf("page_user_%d", i), "password", fmt.Sprintf("page%d@list.com", i), "test_user_role")
			assert.NoError(t, err)
		}
		var totalUsers int64
		tx.Model(&models.User{}).Count(&totalUsers) // Should be 13

		// Request the second page, 5 items per page
		req, _ := http.NewRequest(http.MethodGet, "/users?page=2&page_size=5", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp PaginatedUsersResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)

		assert.Equal(t, totalUsers, resp.Total)
		assert.Equal(t, 2, resp.Page)
		assert.Equal(t, 5, resp.PageSize)
		assert.Len(t, resp.Users, 5) // Page 2 should have 5

		// Request last page
		req, _ = http.NewRequest(http.MethodGet, "/users?page=3&page_size=5", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, totalUsers, resp.Total)
		assert.Equal(t, 3, resp.Page)
		assert.Equal(t, 5, resp.PageSize)
		assert.Len(t, resp.Users, 3) // The last page has only 3 (13 total, 5 per page)
	})

	// --- Test Case: Failure - Tried to get list but no permission ---
	t.Run("Failure - List Users No Permission", func(t *testing.T) {
		db := setupTestDB()
		sqlDB, _ := db.DB()
		defer sqlDB.Close()
		tx := db.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()

		// Create a user without list permission
		noListUser, err := createTestUserWithRoles(tx, "nolistuser", "password", "nolist@example.com", "test_user_role") // user_role 没有 users:list
		assert.NoError(t, err)
		token, err := generateTokenForUser(noListUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// --- Test Case: Failed - Token not provided ---
	t.Run("Failure - No Auth Token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/users", nil)
		// No Authorization header
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
