package controllers

import (
	"errors"
	"fmt"
	"mygin/auth"
	"mygin/database"
	"mygin/models"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// --- Structs for Input/Output ---
type CreateUserInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"omitempty,email"` // Optional, must be valid email if provided
	Nickname string `json:"nickname"`
}

type UpdateUserInput struct {
	// Allow updating email and nickname. Password update requires specific handling.
	Email    *string `json:"email" binding:"omitempty,email"` // Use pointer to distinguish between empty and not provided, validate if present
	Nickname *string `json:"nickname"`
	Password *string `json:"password" binding:"omitempty,min=6"` // Optional, min length 6 if provided

}

type UserResponse struct {
	ID        uint      `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Nickname  string    `json:"nickname"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PaginatedUsersResponse struct {
	Users    []UserResponse `json:"users"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

// --- Helper Functions ---
func getUserFromContext(c *gin.Context) (uint, bool) {
	userIDAny, exists := c.Get("user_id")
	if !exists {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "User ID not found in context"})
		return 0, false
	}
	userID, ok := userIDAny.(uint)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "User ID context type assertion failed"})
		return 0, false
	}
	return userID, true
}

func mapUserToResponse(user models.User) UserResponse {
	return UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Nickname:  user.Nickname,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func (e *AppError) Error() string {
	return fmt.Sprintf("Code: %d, Message: %s", e.Code, e.Message)
}

// --- Controller Functions ---

// CreateUser handles the creation of a new user.
// Permissions: None (public registration assumed) or specific ("users:create")
func CreateUser(c *gin.Context) {
	var input CreateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body: " + err.Error()})
		return
	}

	// Check if username or email already exists
	var existingUser models.User
	if err := database.DB.Where("username = ? OR email = ?", input.Username, input.Email).First(&existingUser).Error; err == nil {
		message := "Username already exists"
		if existingUser.Email == input.Email && input.Email != "" { // Check if email conflict specifically
			message = "Email already exists"
		}
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"message": message})
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Database error checking existing user"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Could not hash password"})
		return
	}

	user := models.User{
		Username: input.Username,
		Password: string(hashedPassword),
		Email:    input.Email,
		Nickname: input.Nickname,
	}

	// Assign default role (e.g., "user")
	var defaultRole models.Role
	if err := database.DB.Where("name = ?", "user").First(&defaultRole).Error; err == nil {
		user.Roles = append(user.Roles, defaultRole)
	} else {
		fmt.Println("Warning: Default 'user' role not found, user created without roles.")
		// Decide if this should be a hard error
	}

	// Create user
	result := database.DB.Create(&user)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Failed to create user: " + result.Error.Error()})
		return
	}

	c.JSON(http.StatusCreated, mapUserToResponse(user)) // Return the created user details (excluding password)
}

// UpdateUser updates a user's details.
// Permissions: "users:update:self" or "users:update:all"
func UpdateUser(c *gin.Context) {
	targetUserIDStr := c.Param("id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID format"})
		return
	}

	requestingUserID, ok := getUserFromContext(c)
	if !ok {
		return
	}

	// Permission Check
	canUpdateAny, _ := auth.UserHasPermissions(requestingUserID, "users:update:all")
	canUpdateSelf, _ := auth.UserHasPermissions(requestingUserID, "users:update:self")

	isSelf := uint(targetUserID) == requestingUserID

	if !isSelf && !canUpdateAny {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden: You can only update your own profile or require 'users:update:all' permission"})
		return
	}
	if !isSelf && !canUpdateSelf && !canUpdateAny {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden: Insufficient permissions to update this profile"})
		return
	}

	// Bind input, using pointer fields to check if they were provided
	var input UpdateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body: " + err.Error()})
		return
	}

	// Fetch the user to update
	var user models.User
	result := database.DB.First(&user, targetUserID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"message": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Database error retrieving user for update"})
		}
		return
	}

	// --- Update Fields ---
	needsSave := false

	// Update Email
	if input.Email != nil {
		// Check if the new email is already taken by *another* user
		var existingUser models.User
		err := database.DB.Where("email = ? AND id != ?", *&input.Email, user.ID).First(&existingUser).Error
		if err == nil {
			// Found another user with this email
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"message": "Email address is already in use by another account"})
			return
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			// Handle potential DB error
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Database error checking email uniqueness"})
			return
		}

		// If email is unique or check passed, update it
		if user.Email != *input.Email {
			user.Email = *input.Email
			needsSave = true
		}
	}

	// Update Nickname
	if input.Nickname != nil && user.Nickname != *input.Nickname {
		user.Nickname = *input.Nickname
		needsSave = true
	}

	// Update Password
	if input.Password != nil {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Could not hash new password"})
			return
		}
		user.Password = string(hashedPassword)
		needsSave = true
	}

	// Save changes if any fields were updated
	if needsSave {
		if err := database.DB.Save(&user).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Failed to save user updates: " + err.Error()})
			return
		}
	}

	// Return updated user data (potentially re-fetch to get updated associations like roles if changed)
	var updatedUser models.User
	database.DB.First(&updatedUser, user.ID) // Re-fetch fresh data

	c.JSON(http.StatusOK, mapUserToResponse(updatedUser))
}

// GetUserByID retrieves a single user by their ID.
// Permissions: "users:read:self" or "users:read:all"
func GetUserByID(c *gin.Context) {
	targetUserIDStr := c.Param("id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID format"})
		return
	}

	requestingUserID, ok := getUserFromContext(c) // Get the user ID that initiated the request
	if !ok {
		return // getUserFromContext will handle the error response internally
	}

	// --- Permission check ---
	canReadAny, _ := auth.UserHasPermissions(requestingUserID, "users:read:all")
	canReadSelf, _ := auth.UserHasPermissions(requestingUserID, "users:read:self")
	isSelf := uint(targetUserID) == requestingUserID

	// Permission logic:
	// 1. If the user wants to view his own information and has the "users:read:self" permission -> allow
	// 2. If the user wants to view other people's information and has the "users:read:all" permission -> allow
	// 3. Other cases -> prohibit
	if !((isSelf && canReadSelf) || (!isSelf && canReadAny)) {
		// If you are not viewing yourself, you must have the read:all permission
		// If you are viewing yourself, you must have the read:self permission.
		if isSelf && !canReadSelf {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden: You need 'users:read:self' permission"})
			return
		}
		if !isSelf && !canReadAny {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden: You need 'users:read:all' permission to view other profiles"})
			return
		}
		// If neither of the above two ifs are satisfied, theoretically it should be allowed, but for safety reasons we add a final judgment
		if !isSelf && !canReadAny && !(isSelf && canReadSelf) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden: Insufficient permissions"})
			return
		}
	}
	// --- End of permission check ---

	var user models.User
	// Usually you don't need to preload Role and Permission unless your UserResponse needs to display this information
	result := database.DB.First(&user, targetUserID)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"message": "User not found"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Database error retrieving user"})
		}
		return
	}

	// Use mapUserToResponse to avoid exposing sensitive information such as passwords
	c.JSON(http.StatusOK, mapUserToResponse(user))
}

// ListUsers retrieves a paginated list of users.
// Permissions: "users:list"
func ListUsers(c *gin.Context) {
	requestingUserID, ok := getUserFromContext(c)
	if !ok {
		return
	}

	// --- Permission check ---
	canList, err := auth.UserHasPermissions(requestingUserID, "users:list")
	if err != nil {
		// Handling possible errors returned by UserHasPermissions
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Error checking permissions"})
		return
	}
	if !canList {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden: You need 'users:list' permission"})
		return
	}
	// --- End of permission check ---

	// Paging parameter processing
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 {
		pageSize = 10
	} else if pageSize > 100 { // Preventing requests for pages that are too large
		pageSize = 100
	}

	offset := (page - 1) * pageSize

	var users []models.User
	var total int64

	// Total number of queries
	if err := database.DB.Model(&models.User{}).Count(&total).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Database error counting users"})
		return
	}

	// Query the user data of the current page
	result := database.DB.Offset(offset).Limit(pageSize).Find(&users)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Database error retrieving users"})
		return
	}

	// Mapping results
	userResponses := make([]UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = mapUserToResponse(user)
	}

	// Constructing a paginated response
	response := PaginatedUsersResponse{
		Users:    userResponses,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		// Optionally add information such as total number of pages
		// TotalPages: int(math.Ceil(float64(total) / float64(pageSize))),
	}

	c.JSON(http.StatusOK, response)
}

// DeleteUser deletes a user.
// Permissions: "users:delete:self" or "users:delete:all"
