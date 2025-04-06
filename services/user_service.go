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
	// Size 1 buffer to avoid blocking goroutine if main thread isn't ready
	errChanUsername, errChanEmail := make(chan error, 1), make(chan error, 1)

	// Goroutine for username check
	go func() {
		_, err := s.repo.FindByUsername(input.Username)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			errChanUsername <- fmt.Errorf("db error checking username: %w", err) // Send actual DB error
		} else if err == nil {
			errChanUsername <- errors.New("Username already exists") // Send conflict error
		} else {
			errChanUsername <- nil // Indicate success (not found)
		}
	}()

	// Goroutine for email check (if applicable)
	emailCheckNeeded := input.Email != ""
	if emailCheckNeeded {
		go func() {
			_, err := s.repo.FindByEmail(input.Email)
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				errChanEmail <- fmt.Errorf("db error checking email: %w", err) // Send actual DB error
			} else if err == nil {
				errChanEmail <- errors.New("Email already exists") // Send conflict error
			} else {
				errChanEmail <- nil // Indicate success (not found)
			}
		}()
	}

	// Wait for results
	usernameErr := <-errChanUsername
	if usernameErr != nil {
		return nil, usernameErr
	}

	if emailCheckNeeded {
		emailErr := <-errChanEmail
		if emailErr != nil {
			return nil, emailErr
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
	// Channels to receive results from goroutines
	permissionChan := make(chan struct {
		canReadSelf bool
		canReadAny  bool
		err         error
	}, 1)
	userChan := make(chan struct {
		user *models.User
		err  error
	}, 1)

	// Goroutine for permission checks
	go func() {
		canReadAny, err := auth.UserHasPermissions(requestingUserID, "users:read:all")
		if err != nil {
			permissionChan <- struct {
				canReadSelf bool
				canReadAny  bool
				err         error
			}{canReadSelf: false, canReadAny: false, err: err}
			return
		}
		canReadSelf, err := auth.UserHasPermissions(requestingUserID, "users:read:self")
		permissionChan <- struct {
			canReadSelf bool
			canReadAny  bool
			err         error
		}{canReadSelf: canReadSelf, canReadAny: canReadAny, err: err}
	}()

	// Goroutine for fetching user
	go func() {
		user, err := s.repo.FindByID(targetUserID)
		userChan <- struct {
			user *models.User
			err  error
		}{user: user, err: err}
	}()

	// Await results from channels
	permissions := <-permissionChan
	userResult := <-userChan

	// Handle errors from goroutines
	if permissions.err != nil {
		return nil, fmt.Errorf("permission check failed: %w", permissions.err)
	}
	if userResult.err != nil {
		if errors.Is(userResult.err, gorm.ErrRecordNotFound) {
			return nil, errors.New("User not found")
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", userResult.err)
	}

	isSelf := uint(targetUserID) == requestingUserID
	if !((isSelf && permissions.canReadSelf) || (!isSelf && permissions.canReadAny)) {
		return nil, errors.New("Forbidden: You need 'users:read:all' permission to view other profiles")
	}

	return userResult.user, nil
}

// UpdateUser updates a user's details.
// Permissions: "users:update:self" or "users:update:all"
func (s *userService) UpdateUser(targetUserID uint, requestingUserID uint, input *UpdateUserInput) (*models.User, error) {
	// Channels for concurrent operations
	permissionChan := make(chan struct {
		canUpdateAny bool
		err          error
	}, 1)
	userChan := make(chan struct {
		user *models.User
		err  error
	}, 1)
	emailChan := make(chan struct {
		existingUser *models.User
		err          error
	}, 1)

	// Launch goroutines
	go func() {
		canUpdateAny, err := auth.UserHasPermissions(requestingUserID, "users:update:all")
		permissionChan <- struct {
			canUpdateAny bool
			err          error
		}{canUpdateAny: canUpdateAny, err: err}
	}()
	go func() {
		user, err := s.repo.FindByID(targetUserID)
		userChan <- struct {
			user *models.User
			err  error
		}{
			user: user,
			err:  err,
		}
	}()

	// Email check goroutine (only if email is being updated)
	if input.Email != nil {
		go func() {
			existingUser, err := s.repo.FindByEmail(*input.Email)
			emailChan <- struct {
				existingUser *models.User
				err          error
			}{existingUser: existingUser, err: err}
		}()
	} else {
		// Send a nil result immediately if no email update is happening
		emailChan <- struct {
			existingUser *models.User
			err          error
		}{existingUser: nil, err: nil}
	}

	// Await results
	permissions := <-permissionChan
	userResult := <-userChan
	emailResult := <-emailChan

	// Error handling
	if permissions.err != nil {
		return nil, fmt.Errorf("permission check failed: %w", permissions.err)
	}
	if userResult.err != nil {
		if errors.Is(userResult.err, gorm.ErrRecordNotFound) {
			return nil, errors.New("User not found")
		}
		return nil, fmt.Errorf("failed to retrieve user: %w", userResult.err)
	}

	// Permission check
	isSelf := uint(targetUserID) == requestingUserID
	if !isSelf && !permissions.canUpdateAny {
		return nil, errors.New("Forbidden: You can only update your own profile or require 'users:update:all' permission")
	}

	user := userResult.user

	// --- Update Fields ---
	needsSave := false

	// Update Email
	if input.Email != nil {
		if emailResult.err == nil && emailResult.existingUser.ID != user.ID {
			return nil, errors.New("Email address is already in use by another account")
		} else if !errors.Is(emailResult.err, gorm.ErrRecordNotFound) {
			return nil, errors.New("Database error checking email uniqueness")
		}

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
	// Channels for concurrent operations
	permissionChan := make(chan struct {
		canList bool
		err     error
	}, 1)
	usersChan := make(chan struct {
		users []models.User
		total int64
		err   error
	}, 1)

	// Launch goroutines
	go func() {
		canList, err := auth.UserHasPermissions(requestingUserID, "users:list")
		permissionChan <- struct {
			canList bool
			err     error
		}{canList: canList, err: err}
	}()

	go func() {
		users, total, err := s.repo.FindAll(page, pageSize)
		usersChan <- struct {
			users []models.User
			total int64
			err   error
		}{users: users, total: total, err: err}
	}()

	// Await results
	permissions := <-permissionChan
	usersResult := <-usersChan

	// Error handling
	if permissions.err != nil {
		return nil, 0, fmt.Errorf("permission check failed: %w", permissions.err)
	}
	if !permissions.canList {
		return nil, 0, errors.New("Forbidden: You need 'users:list' permission")
	}
	if usersResult.err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve users: %w", usersResult.err)
	}

	return usersResult.users, usersResult.total, nil
}

// DeleteUser Delete user information based on user ID
func (s *userService) DeleteUser(userID uint, requestingUserID uint) error {
	// Channels for concurrent operations
	permissionChan := make(chan struct {
		canDeleteSelf bool
		canDeleteAny  bool
		err           error
	}, 1)
	userChan := make(chan struct {
		user *models.User
		err  error
	}, 1)

	// Launch goroutines
	go func() {
		canDeleteAny, err := auth.UserHasPermissions(requestingUserID, "users:delete:all")
		if err != nil {
			permissionChan <- struct {
				canDeleteSelf bool
				canDeleteAny  bool
				err           error
			}{canDeleteSelf: false, canDeleteAny: false, err: err}
			return
		}
		canDeleteSelf, err := auth.UserHasPermissions(requestingUserID, "users:delete:self")
		permissionChan <- struct {
			canDeleteSelf bool
			canDeleteAny  bool
			err           error
		}{canDeleteSelf: canDeleteSelf, canDeleteAny: canDeleteAny, err: err}
	}()

	go func() {
		user, err := s.repo.FindByID(userID)
		userChan <- struct {
			user *models.User
			err  error
		}{user: user, err: err}
	}()

	// Await results
	permissions := <-permissionChan
	userResult := <-userChan

	// Error handling
	if permissions.err != nil {
		return fmt.Errorf("permission check failed: %w", permissions.err)
	}
	if userResult.err != nil {
		if errors.Is(userResult.err, gorm.ErrRecordNotFound) {
			return errors.New("User not exist")
		}
		return fmt.Errorf("failed to retrieve user: %w", userResult.err)
	}

	// Permission check
	isSelf := userID == requestingUserID
	if !((isSelf && permissions.canDeleteSelf) || (!isSelf && permissions.canDeleteAny)) {
		return errors.New("No permission to delete this user information")
	}

	// Deleting User Information
	err := s.repo.Delete(userResult.user)
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
