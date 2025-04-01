package controllers

import (
	"mygin/services"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Define the Service interface that the Controller depends on
type UserController struct {
	userService services.UserService
}

// Constructor, used to create a UserController instance
func NewUserController(userService services.UserService) *UserController {
	return &UserController{userService: userService}
}

// UserResponse Defines the response structure of user information
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

// CreateUser handles the creation of a new user.
// Permissions: None (public registration assumed) or specific ("users:create")
func (ctl *UserController) CreateUser(c *gin.Context) {
	var input services.CreateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body: " + err.Error()})
		return
	}

	user, err := ctl.userService.CreateUser(&input)
	if err != nil {
		statusCode := http.StatusInternalServerError
		message := "Failed to create user"

		if err.Error() == "Username already exists" || err.Error() == "Email already exists" {
			statusCode = http.StatusConflict
			message = err.Error() // 使用Service层返回的特定错误信息
		}

		c.AbortWithStatusJSON(statusCode, gin.H{"message": message})
		return
	}

	// Mapping the user object to the response struct
	userResponse := UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Nickname: user.Nickname,
	}

	c.JSON(http.StatusCreated, userResponse)
}

// GetUserByID retrieves a single user by their ID.
// Permissions: "users:read:self" or "users:read:all"
func (ctl *UserController) GetUserByID(c *gin.Context) {
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

	user, err := ctl.userService.GetUserByID(uint(targetUserID), requestingUserID)

	if err != nil {
		statusCode := http.StatusInternalServerError
		message := "Failed to obtain user list"
		if err.Error() == "User not found" {
			statusCode = http.StatusNotFound
			message = err.Error()
		} else if err.Error() == "Forbidden: You need 'users:read:all' permission to view other profiles" {
			statusCode = http.StatusForbidden
			message = "Forbidden: You need 'users:read:all' permission to view other profiles" //自定义权限错误消息
		}
		c.AbortWithStatusJSON(statusCode, gin.H{"message": message})
		return
	}

	//Mapping the user object to the response struct
	userResponse := UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Nickname: user.Nickname,
	}

	c.JSON(http.StatusOK, userResponse)
}

// UpdateUser updates a user's details.
// Permissions: "users:update:self" or "users:update:all"
func (ctl *UserController) UpdateUser(c *gin.Context) {
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

	var input services.UpdateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body: " + err.Error()})
		return
	}

	updatedUser, err := ctl.userService.UpdateUser(uint(targetUserID), requestingUserID, &input)
	if err != nil {
		statusCode := http.StatusInternalServerError
		message := "Failed to update user list"
		if err.Error() == "User not found" {
			statusCode = http.StatusNotFound
			message = err.Error()
		} else if err.Error() == "Forbidden: You can only update your own profile or require 'users:update:all' permission" {
			statusCode = http.StatusForbidden
			message = err.Error()
		} else if err.Error() == "Email address is already in use by another account" {
			statusCode = http.StatusConflict
			message = err.Error()
		}
		c.AbortWithStatusJSON(statusCode, gin.H{"message": message})
		return
	}

	//Mapping the user object to the response struct
	userResponse := UserResponse{
		ID:       updatedUser.ID,
		Username: updatedUser.Username,
		Email:    updatedUser.Email,
		Nickname: updatedUser.Nickname,
	}

	c.JSON(http.StatusOK, userResponse)
}

// ListUsers retrieves a paginated list of users.
// Permissions: "users:list"
// ListUsers retrieves a paginated list of users.
// Permissions: "users:list"
func (ctl *UserController) ListUsers(c *gin.Context) {
	requestingUserID, ok := getUserFromContext(c)
	if !ok {
		return
	}

	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 {
		pageSize = 10
	}

	users, total, err := ctl.userService.ListUsers(page, pageSize, requestingUserID)

	if err != nil {
		statusCode := http.StatusInternalServerError
		message := "Failed to obtain user list"
		if strings.Contains(err.Error(), "Forbidden: You need 'users:list' permission") {
			statusCode = http.StatusForbidden
			message = "Forbidden: You need 'users:list' permission"
		}
		c.AbortWithStatusJSON(statusCode, gin.H{"message": message})
		return
	}

	// Mapping the user object to the response struct
	userResponses := make([]UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = UserResponse{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			Nickname: user.Nickname,
		}
	}

	response := PaginatedUsersResponse{
		Users:    userResponses,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}

	c.JSON(http.StatusOK, response)
}

// DeleteUser Delete user information based on user ID
func (ctl *UserController) DeleteUser(c *gin.Context) {
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

	err = ctl.userService.DeleteUser(uint(targetUserID), requestingUserID)

	if err != nil {
		statusCode := http.StatusInternalServerError
		message := "Failed to delete user"
		if err.Error() == "No permission to delete this user information" {
			statusCode = http.StatusForbidden
			message = "Forbidden: You can only delete your own profile or require 'users:delete:all' permission"
		}
		c.AbortWithStatusJSON(statusCode, gin.H{"message": message})
		return
	}

	c.Status(http.StatusOK)
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
