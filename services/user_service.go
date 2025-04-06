package services

import (
	"errors"
	"fmt"
	"mygin/auth"
	"mygin/models"
	"mygin/repositories"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// The UserService interface defines the methods that user services need to implement
type UserService interface {
	CreateUser(input *CreateUserInput) (*models.User, error)
	GetUserByID(userID uint, requestingUserID uint) (*models.User, error)
	UpdateUser(userID uint, requestingUserID uint, input *UpdateUserInput) (*models.User, error)
	ListUsers(page int, pageSize int, requestingUserID uint) ([]models.User, int64, error)
	DeleteUser(userID uint, requestingUserID uint) error
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

// The userService structure is the implementation of the UserService interface
type userService struct {
	// db *gorm.DB
	repo repositories.UserRepository
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

var _ UserService = (*userService)(nil)

// NewUserService creates a new UserService instance
func NewUserService(repo repositories.UserRepository) UserService {
	return &userService{repo: repo}
}

// CreateUser handles the creation of a new user.
// Permissions: None (public registration assumed) or specific ("users:create")
func (s *userService) CreateUser(input *CreateUserInput) (*models.User, error) {
	// Check if username or email already exists
	_, err := s.repo.FindByUsername(input.Username)
	if err == nil {
		return nil, errors.New("Username already exists")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("Database error checking existing user")
	}

	if input.Email != "" {
		_, err = s.repo.FindByEmail(input.Email)
		if err == nil {
			return nil, errors.New("Email already exists")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("Database error checking existing user")
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("Could not hash password")
	}

	user := models.User{
		Username: input.Username,
		Password: string(hashedPassword),
		Email:    input.Email,
		Nickname: input.Nickname,
	}

	// Create user
	err = s.repo.Create(&user)
	if err != nil {
		return nil, errors.New("Failed to create user: " + err.Error())
	}

	return &user, nil // Return the created user details (excluding password)
}

// GetUserByID retrieves a single user by their ID.
// Permissions: "users:read:self" or "users:read:all"
func (s *userService) GetUserByID(targetUserID uint, requestingUserID uint) (*models.User, error) {
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

		return nil, errors.New("Forbidden: You need 'users:read:all' permission to view other profiles")

	}
	// --- End of permission check ---

	user, err := s.repo.FindByID(targetUserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("User not found")
		} else {
			return nil, errors.New("Database error retrieving user")
		}

	}

	return user, nil
}

// UpdateUser updates a user's details.
// Permissions: "users:update:self" or "users:update:all"
func (s *userService) UpdateUser(targetUserID uint, requestingUserID uint, input *UpdateUserInput) (*models.User, error) {
	// Permission Check
	canUpdateAny, _ := auth.UserHasPermissions(requestingUserID, "users:update:all")
	// canUpdateSelf, _ := auth.UserHasPermissions(requestingUserID, "users:update:self")

	isSelf := uint(targetUserID) == requestingUserID

	if !isSelf && !canUpdateAny {
		return nil, errors.New("Forbidden: You can only update your own profile or require 'users:update:all' permission")

	}

	// Fetch the user to update
	user, err := s.repo.FindByID(targetUserID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("User not found")
		} else {
			return nil, errors.New("Database error retrieving user for update")
		}

	}

	// --- Update Fields ---
	needsSave := false

	// Update Email
	if input.Email != nil {
		// Check if the new email is already taken by *another* user
		existingUser, err := s.repo.FindByEmail(*input.Email)
		if err == nil && existingUser.ID != user.ID {
			// Found another user with this email
			return nil, errors.New("Email address is already in use by another account")

		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			// Handle potential DB error
			return nil, errors.New("Database error checking email uniqueness")

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
			return nil, errors.New("Could not hash new password")

		}
		user.Password = string(hashedPassword)
		needsSave = true
	}

	// Save changes if any fields were updated
	if needsSave {
		if err := s.repo.Update(user); err != nil {
			return nil, errors.New("Failed to save user updates: " + err.Error())

		}
	}

	// Return updated user data (potentially re-fetch to get updated associations like roles if changed)
	updatedUser, err := s.repo.FindByID(user.ID)
	if err != nil {
		return nil, err
	}

	return updatedUser, nil
}

// ListUsers retrieves a paginated list of users.
// Permissions: "users:list"
func (s *userService) ListUsers(page int, pageSize int, requestingUserID uint) ([]models.User, int64, error) {
	// --- Permission check ---
	canList, err := auth.UserHasPermissions(requestingUserID, "users:list")
	if err != nil {
		// Handling possible errors returned by UserHasPermissions
		return nil, 0, fmt.Errorf("Error checking permissions:%w", err)
	}
	if !canList {
		return nil, 0, errors.New("Forbidden: You need 'users:list' permission")

	}
	// --- End of permission check ---

	users, total, err := s.repo.FindAll(page, pageSize)
	if err != nil {
		return nil, 0, errors.New("Database error retrieving users")
	}

	return users, total, nil
}

// DeleteUser Delete user information based on user ID
func (s *userService) DeleteUser(userID uint, requestingUserID uint) error {
	// Permission Check
	canDeleteAny, _ := auth.UserHasPermissions(requestingUserID, "users:delete:all")
	canDeleteSelf, _ := auth.UserHasPermissions(requestingUserID, "users:delete:self")
	isSelf := userID == requestingUserID

	if !((isSelf && canDeleteSelf) || (!isSelf && canDeleteAny)) {
		return errors.New("No permission to delete this user information")
	}

	// Query user information
	user, err := s.repo.FindByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("User not exist")
		}
		return fmt.Errorf("Failed to obtain user information: %w", err)
	}

	// Deleting User Information
	err = s.repo.Delete(user)
	if err != nil {
		return fmt.Errorf("Failed to delete user information: %w", err)
	}

	return nil
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
