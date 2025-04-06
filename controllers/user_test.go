package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mygin/auth"
	"mygin/database"
	"mygin/models"
	"mygin/repositories"
	"mygin/services"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Global variables are only used to store the underlying in-memory database instance
var baseDB *gorm.DB

// ------Helper function------
// Helper: Create a user with the specified role (password will be hashed)
// IMPORTANT: This helper now accepts a *gorm.DB (which should be the transaction tx)
func createTestUserWithRoles(tx *gorm.DB, username, password, email string, roleNames ...string) (models.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	user := models.User{
		Username: username,
		Password: string(hashedPassword),
		Email:    email,
	}

	// Use the transaction to create the user
	if err := tx.Create(&user).Error; err != nil {
		return models.User{}, fmt.Errorf("failed to create user %s: %w", username, err)
	}

	if len(roleNames) > 0 {
		var roles []models.Role
		// Use the transaction to find roles
		if err := tx.Where("name IN ?", roleNames).Find(&roles).Error; err != nil {
			return user, fmt.Errorf("failed to find roles %v: %w", roleNames, err)
		}
		if len(roles) > 0 {
			// Use the transaction to associate roles
			if err := tx.Model(&user).Association("Roles").Append(roles); err != nil {
				return user, fmt.Errorf("failed to associate roles with user %s: %w", username, err)
			}
		} else {
			fmt.Printf("Warning: Roles %v not found for user %s\n", roleNames, username)
		}
	}
	// Users need to be reloaded within the same transaction to include associated roles
	tx.Preload("Roles").First(&user, user.ID)
	return user, nil
}

// Helper: Create a role with specified permissions
// IMPORTANT: This helper now accepts a *gorm.DB (which should be the transaction tx)
func createTestRoleWithPermissions(tx *gorm.DB, roleName, description string, permissionNames ...string) (models.Role, error) {
	role := models.Role{
		Name:        roleName,
		Description: description,
	}
	// Use the transaction to find or create a role
	if err := tx.Where(models.Role{Name: roleName}).FirstOrCreate(&role).Error; err != nil {
		return models.Role{}, fmt.Errorf("failed to find or create role %s: %w", roleName, err)
	}

	if len(permissionNames) > 0 {
		var permissions []models.Permission
		// Use the transaction to ensure permissions exist
		for _, pName := range permissionNames {
			perm := models.Permission{Name: pName}
			if err := tx.Where(models.Permission{Name: pName}).FirstOrCreate(&perm).Error; err != nil {
				return role, fmt.Errorf("failed to ensure permission %s exists: %w", pName, err)
			}
			permissions = append(permissions, perm)
		}

		// Use the transaction to replace the association
		if err := tx.Model(&role).Association("Permissions").Replace(permissions); err != nil {
			return role, fmt.Errorf("failed to associate permissions with role %s: %w", roleName, err)
		}
	}
	// Reload the role within the same transaction to include the permissions
	tx.Preload("Permissions").First(&role, role.ID)
	return role, nil
}

// Helper: Generate Token for User (No DB interaction, so no tx needed)
func generateTokenForUser(user models.User) (string, error) {
	if user.ID == 0 {
		return "", fmt.Errorf("user must have a valid ID to generate token")
	}
	// Ensure the user object passed has necessary fields (ID, Username)
	tokenUser := models.User{Model: gorm.Model{ID: user.ID}, Username: user.Username}
	return auth.GenerateToken(&tokenUser)
}

// setupRolesAndPermissions now accepts a *gorm.DB
func setupRolesAndPermissions(db *gorm.DB) {
	permissions := []string{
		"users:read:self", "users:update:self", "users:delete:self",
		"users:read:all", "users:update:all", "users:delete:all", "users:list",
		"roles:manage",
		// Add any other permissions required by tests
		"users:create", // Assuming CreateUser might need this later
	}
	for _, pName := range permissions {
		perm := models.Permission{Name: pName}
		if err := db.Where(models.Permission{Name: pName}).FirstOrCreate(&perm).Error; err != nil {
			panic(fmt.Sprintf("Failed to ensure permission %s: %v", pName, err))
		}
	}

	// Use the transaction-aware helper
	_, err := createTestRoleWithPermissions(db, "test_user_role", "Basic user role for testing", "users:read:self", "users:update:self", "users:delete:self")
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_user_role: %v", err))
	}
	_, err = createTestRoleWithPermissions(db, "test_admin_role", "Admin role for testing", "users:read:all", "users:update:all", "users:delete:all", "users:list", "roles:manage")
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_admin_role: %v", err))
	}
	_, err = createTestRoleWithPermissions(db, "test_viewer_role", "Viewer role for testing", "users:read:all", "users:list")
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_viewer_role: %v", err))
	}
	_, err = createTestRoleWithPermissions(db, "test_no_perms_role", "Role with no user permissions") // Example role with no user perms, maybe other perms
	if err != nil {
		panic(fmt.Sprintf("Failed to setup test_no_perms_role: %v", err))
	}
}

// setupBaseTestDB initializes the base in-memory SQLite database ONCE
func setupBaseTestDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		// Reduce log noise during tests
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic("Failed to connect to test database: " + err.Error())
	}
	err = db.AutoMigrate(&models.User{}, &models.Role{}, &models.Permission{})
	if err != nil {
		panic("Failed to migrate test database: " + err.Error())
	}
	// Set up roles and permissions on the base DB
	setupRolesAndPermissions(db)
	return db
}

// setupRouter now takes a *gorm.DB (the transaction) and returns a Gin engine
func setupRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New() // Use gin.New() for cleaner setup

	// Create repository and service bound to the provided DB (transaction)
	userRepository := repositories.NewUserRepository(db)
	userService := services.NewUserService(userRepository)
	userController := NewUserController(userService)

	// --- Public Routes ---
	// Register /register route (usually public)
	r.POST("/register", userController.CreateUser)
	// Login route (usually public)
	// Note: LoginHandler uses global database.DB, ensure it's set to tx during tests
	r.POST("/login", auth.LoginHandler)

	// --- Protected Routes ---
	userRoutes := r.Group("/users")
	// Apply authentication middleware. It will use the *global* database.DB
	// which MUST be set to the transaction 'tx' before calling ServeHTTP.
	userRoutes.Use(auth.AuthMiddleware())
	{
		userRoutes.GET("/:id", userController.GetUserByID)
		userRoutes.PUT("/:id", userController.UpdateUser)
		userRoutes.GET("", userController.ListUsers)
		userRoutes.DELETE("/:id", userController.DeleteUser) // Assuming DeleteUser exists
	}

	return r
}

// TestMain sets up the base DB for all tests in the package
func TestMain(m *testing.M) {
	fmt.Println("Setting up base test database...")
	baseDB = setupBaseTestDB() // Initialize the base in-memory DB

	// Run all tests
	exitCode := m.Run()

	// Close the base database connection after all tests run
	sqlDB, err := baseDB.DB()
	if err == nil {
		sqlDB.Close()
		fmt.Println("Closed base test database connection.")
	}

	// Exit
	os.Exit(exitCode)
}

// TestCreateUser tests the user creation function
func TestCreateUser(t *testing.T) {
	// This test focuses on the /register endpoint which is public,
	// but still good practice to use transactions for isolation.

	// --- Test Case 1: Successfully created user ---
	t.Run("Success", func(t *testing.T) {
		tx := baseDB.Begin() // Start transaction from base DB
		originalDB := database.DB
		database.DB = tx // Set global DB for any potential implicit use (though CreateUser shouldn't need auth)
		defer func() {
			tx.Rollback()
			database.DB = originalDB // Restore global DB
		}()

		// Setup router bound to the transaction
		router := setupRouter(tx)
		assert.NotNil(t, router, "Test router should not be nil")

		userInput := gin.H{
			"username": "testuser_success",
			"password": "password123",
			"email":    "success@example.com",
			"nickname": "tester",
		}
		reqBody, _ := json.Marshal(userInput)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp UserResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "testuser_success", resp.Username)
		assert.Equal(t, "success@example.com", resp.Email)
		assert.Equal(t, "tester", resp.Nickname)
		assert.NotZero(t, resp.ID)

		var createdUser models.User
		// Check within the transaction
		result := tx.Where("username = ?", "testuser_success").First(&createdUser)
		assert.NoError(t, result.Error)
		assert.Equal(t, "testuser_success", createdUser.Username)
		assert.Equal(t, "success@example.com", createdUser.Email)
		assert.Equal(t, "tester", createdUser.Nickname)
		assert.NotEmpty(t, createdUser.Password)
	})

	// --- Test Case 2: Username already exists ---
	t.Run("Username already exists", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()
		router := setupRouter(tx)

		// Pre-insert a user *within the transaction*
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		existingUser := models.User{Username: "existinguser", Password: string(hashedPassword), Email: "existing@example.com"}
		// Use a repository bound to the transaction
		txRepo := repositories.NewUserRepository(tx)
		err := txRepo.Create(&existingUser)
		assert.NoError(t, err)

		userInput := gin.H{
			"username": "existinguser", // Use existing username
			"password": "password123",
			"email":    "another@example.com",
		}
		reqBody, _ := json.Marshal(userInput)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		// Check the specific error message from the service layer
		assert.Equal(t, "Username already exists", resp["message"])
	})

	// --- Test Case 3: Email already exists ---
	t.Run("Email already exists", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()
		router := setupRouter(tx)

		// Pre-insert a user *within the transaction*
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
		existingUser := models.User{Username: "anotheruser", Password: string(hashedPassword), Email: "existingemail@example.com"}
		txRepo := repositories.NewUserRepository(tx)
		err := txRepo.Create(&existingUser)
		assert.NoError(t, err)

		userInput := gin.H{
			"username": "newuser",
			"password": "password123",
			"email":    "existingemail@example.com", // Use existing email
		}
		reqBody, _ := json.Marshal(userInput)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "Email already exists", resp["message"])
	})

	// --- Test Case 4: Invalid request body (missing required fields) ---
	t.Run("Invalid request body - missing password", func(t *testing.T) {
		tx := baseDB.Begin() // Still use transaction for consistency
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()
		router := setupRouter(tx)

		reqBody := []byte(`{"username": "testuser_invalid", "email": "invalid@example.com"}`) // Missing password
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp["message"], "Invalid request body")
		assert.Contains(t, resp["message"], "Password") // Gin binding error usually mentions the field
	})

	// --- Test Case 5: Invalid Email Format ---
	t.Run("Invalid email format", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() {
			tx.Rollback()
			database.DB = originalDB
		}()
		router := setupRouter(tx)

		userInput := gin.H{
			"username": "testuser_email",
			"password": "password123",
			"email":    "invalid-email-format", // Invalid format
		}
		reqBody, _ := json.Marshal(userInput)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp["message"], "Invalid request body")
		assert.Contains(t, resp["message"], "Email") // Gin binding error includes field info
	})
}

// TestUpdateUser Test update user information
func TestUpdateUser(t *testing.T) {

	// --- Test Case: Successfully updated my information (nickname and email) ---
	t.Run("Success - Update Self Nickname and Email", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx // Set global DB for AuthMiddleware
		defer func() {
			tx.Rollback()
			database.DB = originalDB // Restore
		}()
		router := setupRouter(tx) // Router uses the transaction

		// Prepare user and token *within the transaction*
		// User needs 'users:update:self' permission
		testUser, err := createTestUserWithRoles(tx, "updateuser", "password", "update@example.com", "test_user_role")
		assert.NoError(t, err)
		assert.NotZero(t, testUser.ID)
		token, err := generateTokenForUser(testUser)
		assert.NoError(t, err)

		updateData := gin.H{
			"nickname": "Updated Nickname",
			"email":    "updated.email@example.com",
		}
		reqBody, _ := json.Marshal(updateData)
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(testUser.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp UserResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "Updated Nickname", resp.Nickname)
		assert.Equal(t, "updated.email@example.com", resp.Email)
		assert.Equal(t, testUser.Username, resp.Username) // Username should not change

		var updatedUser models.User
		// Check DB state *within the transaction*
		tx.First(&updatedUser, testUser.ID)
		assert.Equal(t, "Updated Nickname", updatedUser.Nickname)
		assert.Equal(t, "updated.email@example.com", updatedUser.Email)
	})

	// --- Test Case: Successfully updated own password ---
	t.Run("Success - Update Self Password", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		testUser, err := createTestUserWithRoles(tx, "updatepass", "oldpassword", "pass@example.com", "test_user_role") // needs update:self
		assert.NoError(t, err)
		token, err := generateTokenForUser(testUser)
		assert.NoError(t, err)

		updateData := gin.H{"password": "newStrongPassword"}
		reqBody, _ := json.Marshal(updateData)
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(testUser.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var updatedUser models.User
		tx.First(&updatedUser, testUser.ID)
		err = bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte("newStrongPassword"))
		assert.NoError(t, err, "New password should match the updated hash")
		err = bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte("oldpassword"))
		assert.Error(t, err, "Old password should no longer match")
	})

	// --- Test Case: Administrator successfully updates other user information ---
	t.Run("Success - Admin Update Other User", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// Admin needs 'users:update:all'
		adminUser, err := createTestUserWithRoles(tx, "adminupdater", "password", "admin@update.com", "test_admin_role")
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

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var updatedUser models.User
		tx.First(&updatedUser, targetUser.ID)
		assert.Equal(t, "Updated by Admin", updatedUser.Nickname)
	})

	// --- Test Case: Failure - Tried to update other people's information but didn't have permission ---
	t.Run("Failure - Update Other No Permission", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// User A only has 'users:update:self'
		userA, err := createTestUserWithRoles(tx, "userA_update", "password", "a@update.com", "test_user_role")
		assert.NoError(t, err)
		userB, err := createTestUserWithRoles(tx, "userB_update", "password", "b@update.com", "test_user_role")
		assert.NoError(t, err)
		tokenA, err := generateTokenForUser(userA)
		assert.NoError(t, err)

		updateData := gin.H{"nickname": "Attempted Update"}
		reqBody, _ := json.Marshal(updateData)
		// User A tries to update User B
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(userB.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokenA)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code) // Expect 403 Forbidden
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "Forbidden: You can only update your own profile or require 'users:update:all' permission", resp["message"])
	})

	// --- Test Case: Failure - updating a non-existent user ---
	t.Run("Failure - User Not Found", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// Admin has permission to update anyone
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

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code) // Expect 404 Not Found
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "User not found", resp["message"])
	})

	//--- Test Case: Failure - Email Conflict ---
	t.Run("Failure - Email Conflict", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		user1, err := createTestUserWithRoles(tx, "emailuser1", "password", "email1@conflict.com", "test_user_role") // Needs update:self
		assert.NoError(t, err)
		user2, err := createTestUserWithRoles(tx, "emailuser2", "password", "email2@conflict.com", "test_user_role")
		assert.NoError(t, err)
		token1, err := generateTokenForUser(user1)
		assert.NoError(t, err)

		// User 1 tries to update their email to user2's email
		updateData := gin.H{"email": user2.Email}
		reqBody, _ := json.Marshal(updateData)
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(user1.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token1)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code) // Expect 409 Conflict
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		// Check specific error message from service
		assert.Equal(t, "Email address is already in use by another account", resp["message"])
	})

	// --- Test Case: Failed - Token not provided ---
	t.Run("Failure - No Auth Token", func(t *testing.T) {
		tx := baseDB.Begin() // Need transaction to potentially create user
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// Create a user, ID doesn't matter much here as auth fails first
		user, err := createTestUserWithRoles(tx, "noauthupdate", "password", "noauth@update.com", "test_user_role")
		assert.NoError(t, err)

		updateData := gin.H{"nickname": "No Auth Update"}
		reqBody, _ := json.Marshal(updateData)
		req, _ := http.NewRequest(http.MethodPut, "/users/"+fmt.Sprint(user.ID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header!
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code) // Expect 401 Unauthorized
	})

	// TODO: Add more test cases (invalid input: wrong email format, password too short, etc.)
	// e.g., t.Run("Failure - Invalid Email Format", func(t *testing.T) { ... })
	// e.g., t.Run("Failure - Password Too Short", func(t *testing.T) { ... })
}

// TestGetUserByID Test to obtain single user information
func TestGetUserByID(t *testing.T) {

	// --- Test Case: Successfully obtain your own information ---
	t.Run("Success - Read Self", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// User needs 'users:read:self' permission
		testUser, err := createTestUserWithRoles(tx, "readselfuser", "password", "self@read.com", "test_user_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(testUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(testUser.ID), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

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
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// Admin needs 'users:read:all'
		adminUser, err := createTestUserWithRoles(tx, "adminreader", "password", "admin@read.com", "test_admin_role")
		assert.NoError(t, err)
		targetUser, err := createTestUserWithRoles(tx, "targetreader", "password", "target@read.com", "test_user_role")
		assert.NoError(t, err)
		adminToken, err := generateTokenForUser(adminUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(targetUser.ID), nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp UserResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, targetUser.ID, resp.ID)
		assert.Equal(t, targetUser.Username, resp.Username)
	})

	// --- Test Case: Failed - Tried to get other people's information but didn't have permission ---
	t.Run("Failure - Read Other No Permission", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// User A only has 'users:read:self'
		userA, err := createTestUserWithRoles(tx, "userA_read", "password", "a@read.com", "test_user_role")
		assert.NoError(t, err)
		userB, err := createTestUserWithRoles(tx, "userB_read", "password", "b@read.com", "test_user_role")
		assert.NoError(t, err)
		tokenA, err := generateTokenForUser(userA)
		assert.NoError(t, err)

		// User A tries to access User B
		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(userB.ID), nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code) // Expect 403
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		// Check specific error message from service/controller
		assert.Equal(t, "Forbidden: You need 'users:read:all' permission to view other profiles", resp["message"])
	})

	// --- Test Case: Failed - Tried to get self information but did not have read:self permission ---
	// Note: The current service logic allows reading self IF isSelf AND canReadSelf.
	// If a user truly has NO read permissions at all, this test makes sense.
	t.Run("Failure - Read Self No Permission", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// Create user with a role that lacks 'users:read:self'
		noPermUser, err := createTestUserWithRoles(tx, "noperm_read", "password", "noperm@read.com", "test_no_perms_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(noPermUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(noPermUser.ID), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code) // Expect 403
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "Forbidden: You need 'users:read:all' permission to view other profiles", resp["message"]) // Check the message
	})

	// --- Test Case: Failure - Get a non-existent user ---
	t.Run("Failure - User Not Found", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// Admin user has permission to read anyone ('users:read:all')
		adminUser, err := createTestUserWithRoles(tx, "adminreader_nf", "password", "admin_nf@read.com", "test_admin_role")
		assert.NoError(t, err)
		adminToken, err := generateTokenForUser(adminUser)
		assert.NoError(t, err)

		nonExistentUserID := uint(99998)
		req, _ := http.NewRequest(http.MethodGet, "/users/"+fmt.Sprint(nonExistentUserID), nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code) // Expect 404
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "User not found", resp["message"])
	})

	// --- Test Case: Failed - Token not provided ---
	t.Run("Failure - No Auth Token", func(t *testing.T) {
		tx := baseDB.Begin() // No DB interaction needed before auth, but setup requires it
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		req, _ := http.NewRequest(http.MethodGet, "/users/1", nil) // ID 1 might not exist, doesn't matter
		// No Authorization header
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code) // Expect 401
	})
}

// TestListUsers Test to get the user list (pagination)
func TestListUsers(t *testing.T) {

	// --- Test Case: Successfully obtain the user list (requires users:list permission) ---
	t.Run("Success - List Users With Permission", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// User needs 'users:list' permission (admin role has it)
		listUser, err := createTestUserWithRoles(tx, "listuser", "password", "list@example.com", "test_admin_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(listUser)
		assert.NoError(t, err)

		// Create other users to populate the list
		_, err = createTestUserWithRoles(tx, "user1_list", "password", "u1@list.com", "test_user_role")
		assert.NoError(t, err)
		_, err = createTestUserWithRoles(tx, "user2_list", "password", "u2@list.com", "test_user_role")
		assert.NoError(t, err)

		// Get total count *within the transaction*
		var totalUsers int64
		tx.Model(&models.User{}).Count(&totalUsers)

		req, _ := http.NewRequest(http.MethodGet, "/users?page=1&page_size=10", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp PaginatedUsersResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)

		assert.Equal(t, totalUsers, resp.Total)
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, 10, resp.PageSize)
		assert.Len(t, resp.Users, int(totalUsers)) // Assuming totalUsers <= 10 here

		foundListUser := false
		for _, u := range resp.Users {
			assert.NotEmpty(t, u.Username) // Basic check on returned data
			if u.Username == "listuser" {
				foundListUser = true
			}
		}
		assert.True(t, foundListUser, "Requesting user should be in the list")
	})

	// --- Test Case: Successfully obtain the user list - test paging ---
	t.Run("Success - List Users Pagination", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// User needs 'users:list'
		listUser, err := createTestUserWithRoles(tx, "pageruser", "password", "pager@example.com", "test_admin_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(listUser)
		assert.NoError(t, err)

		// Create 12 more users (total 13 with listUser)
		for i := 0; i < 12; i++ {
			_, err = createTestUserWithRoles(tx, fmt.Sprintf("page_user_%d", i), "password", fmt.Sprintf("page%d@list.com", i), "test_user_role")
			assert.NoError(t, err)
		}
		var totalUsers int64
		tx.Model(&models.User{}).Count(&totalUsers)
		assert.EqualValues(t, 13, totalUsers) // Verify total count

		// Request page 2, size 5
		req, _ := http.NewRequest(http.MethodGet, "/users?page=2&page_size=5", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp PaginatedUsersResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, totalUsers, resp.Total)
		assert.Equal(t, 2, resp.Page)
		assert.Equal(t, 5, resp.PageSize)
		assert.Len(t, resp.Users, 5) // Page 2 should have 5

		// Request page 3, size 5
		req, _ = http.NewRequest(http.MethodGet, "/users?page=3&page_size=5", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, totalUsers, resp.Total)
		assert.Equal(t, 3, resp.Page)
		assert.Equal(t, 5, resp.PageSize)
		assert.Len(t, resp.Users, 3) // Last page has remaining 3 (13 total = 5 + 5 + 3)
	})

	// --- Test Case: Failure - Tried to get list but no permission ---
	t.Run("Failure - List Users No Permission", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		// User role lacks 'users:list' permission
		noListUser, err := createTestUserWithRoles(tx, "nolistuser", "password", "nolist@example.com", "test_user_role")
		assert.NoError(t, err)
		token, err := generateTokenForUser(noListUser)
		assert.NoError(t, err)

		req, _ := http.NewRequest(http.MethodGet, "/users", nil) // Default page=1, size=10
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code) // Expect 403
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "Forbidden: You need 'users:list' permission", resp["message"])
	})

	// --- Test Case: Failed - Token not provided ---
	t.Run("Failure - No Auth Token", func(t *testing.T) {
		tx := baseDB.Begin()
		originalDB := database.DB
		database.DB = tx
		defer func() { tx.Rollback(); database.DB = originalDB }()
		router := setupRouter(tx)

		req, _ := http.NewRequest(http.MethodGet, "/users", nil)
		// No Authorization header
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code) // Expect 401
	})
}

// TODO: Add TestDeleteUser following the same transaction and permission patterns
// func TestDeleteUser(t *testing.T) {
//     t.Run("Success - Delete Self", func(t *testing.T) { ... })
//     t.Run("Success - Admin Delete Other", func(t *testing.T) { ... })
//     t.Run("Failure - Delete Other No Permission", func(t *testing.T) { ... })
//     t.Run("Failure - Delete Non-Existent User", func(t *testing.T) { ... })
//     t.Run("Failure - No Auth Token", func(t *testing.T) { ... })
// }