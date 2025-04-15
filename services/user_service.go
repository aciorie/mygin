package services

import (
	"errors"
	"fmt"
	"mygin-restful/auth"
	"mygin-restful/models"
	"mygin-restful/repositories"
	"strings"
	"time"

	"go.uber.org/zap"
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
	repo   repositories.UserRepository
	logger *zap.SugaredLogger // Add logger
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

// Ensure userService implements UserService
var _ UserService = (*userService)(nil)

// NewUserService creates a new UserService instance
func NewUserService(repo repositories.UserRepository, logger *zap.SugaredLogger) UserService {
	return &userService{
		repo:   repo,
		logger: logger,
	}
}

// CreateUser handles the creation of a new user.
// Permissions: None (public registration assumed) or specific ("users:create")
func (s *userService) CreateUser(input *CreateUserInput) (*models.User, error) {
	s.logger.Infow("Service: Attempting to create user", "username", input.Username)
	errChanUsername, errChanEmail := make(chan error, 1), make(chan error, 1)

	// Goroutine for username check
	go func() {
		_, err := s.repo.FindByUsername(input.Username)
		if err == nil {
			errChanUsername <- errors.New("Username already exists") // Conflict
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			s.logger.Errorw("Service: DB error checking username", "username", input.Username, "error", err)
			errChanUsername <- fmt.Errorf("internal error checking username") // Generic internal error
		} else {
			errChanUsername <- nil // Username is available
		}
	}()

	// Goroutine for email check (if applicable)
	emailCheckNeeded := input.Email != ""
	if emailCheckNeeded {
		go func() {
			_, err := s.repo.FindByEmail(input.Email)
			if err == nil {
				errChanEmail <- errors.New("Email already exists") // Conflict
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				s.logger.Errorw("Service: DB error checking email", "email", input.Email, "error", err)
				errChanEmail <- fmt.Errorf("internal error checking email") // Generic internal error
			} else {
				errChanEmail <- nil // Email is available or not provided
			}
		}()
	}

	// Wait for username check
	usernameErr := <-errChanUsername
	if usernameErr != nil {
		return nil, usernameErr // Return conflict or internal error
	}

	// Wait for email check if needed
	if emailCheckNeeded {
		emailErr := <-errChanEmail
		if emailErr != nil {
			return nil, emailErr // Return conflict or internal error
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Errorw("Service: Failed to hash password", "username", input.Username, "error", err)
		return nil, errors.New("could not process password") // More generic internal error
	}

	user := models.User{
		Username: input.Username,
		Password: string(hashedPassword),
		Email:    input.Email,
		Nickname: input.Nickname,
		// Assign default role "user" upon creation? Requires fetching role.
	}

	// Create user in DB
	err = s.repo.Create(&user)
	if err != nil {
		s.logger.Errorw("Service: Failed to create user in repository", "username", input.Username, "error", err)
		// Could check for specific DB errors (like duplicate key if concurrent check failed somehow)
		return nil, errors.New("failed to save user") // Generic internal error
	}

	s.logger.Infow("Service: User created successfully", "user_id", user.ID, "username", user.Username)
	return &user, nil
}

// GetUserByID retrieves a single user by their ID.
// Permissions: "users:read:self" or "users:read:all"
func (s *userService) GetUserByID(targetUserID uint, requestingUserID uint) (*models.User, error) {
	s.logger.Infow("Service: Attempting to get user by ID", "target_user_id", targetUserID, "requesting_user_id", requestingUserID)
	// Check if requesting user exists (important for permission checks)
	if requestingUserID != 0 { // Skip check for internal calls represented by ID 0
		_, err := s.repo.FindByID(requestingUserID)
		if err != nil {
			s.logger.Warnw("Service: Requesting user not found for GetUserByID", "requesting_user_id", requestingUserID, "target_user_id", targetUserID, "error", err)
			return nil, errors.New("requesting user invalid")
		}
	}

	// --- Permission Check (Concurrent) ---
	// CORRECTED: Struct definition seems okay, the population and usage were likely the issue.
	type permResult struct {
		canReadSelf bool  // Boolean field for self-read permission
		canReadAny  bool  // Boolean field for any-read permission
		err         error // Single error field
	}
	permissionChan := make(chan permResult, 1)

	go func() {
		// CORRECTED: Assign results to the correct fields
		var result permResult
		result.canReadAny, result.err = auth.UserHasPermissions(requestingUserID, "users:read:all")
		// Only check self permission if the first check didn't already fail fatally
		if result.err == nil {
			var errSelf error
			result.canReadSelf, errSelf = auth.UserHasPermissions(requestingUserID, "users:read:self")
			result.err = errors.Join(result.err, errSelf) // Combine potential errors (join nil is safe)
		}
		permissionChan <- result
	}()

	// --- Fetch User (Concurrent) --- remains the same
	type userResult struct {
		user *models.User
		err  error
	}
	userChan := make(chan userResult, 1)
	go func() {
		user, err := s.repo.FindByID(targetUserID)
		userChan <- userResult{user: user, err: err}
	}()

	// Await results
	perms := <-permissionChan
	uResult := <-userChan

	// Handle errors - **FIRST check for errors from the goroutines**
	if perms.err != nil {
		// Check if it's just "user not found" for the *requesting* user
		if requestingUserID != 0 && strings.Contains(perms.err.Error(), fmt.Sprintf("user with ID %d not found", requestingUserID)) {
			s.logger.Warnw("Service: Requesting user vanished during permission check", "requesting_user_id", requestingUserID)
			return nil, errors.New("requesting user invalid")
		}
		s.logger.Errorw("Service: Permission check failed internally", "requesting_user_id", requestingUserID, "error", perms.err)
		return nil, fmt.Errorf("internal error during permission check")
	}
	if uResult.err != nil {
		if errors.Is(uResult.err, gorm.ErrRecordNotFound) {
			return nil, errors.New("User not found") // Use specific error message
		}
		s.logger.Errorw("Service: Failed to retrieve target user", "target_user_id", targetUserID, "error", uResult.err)
		return nil, fmt.Errorf("failed to retrieve user")
	}

	// Check permissions based on results - **NOW use the boolean fields**
	isSelf := targetUserID == requestingUserID
	s.logger.Debugw("Service: Permission check values", "is_self", isSelf, "can_read_self", perms.canReadSelf, "can_read_any", perms.canReadAny)

	// CORRECTED: Access boolean fields directly
	if !((isSelf && perms.canReadSelf) || (!isSelf && perms.canReadAny)) {
		if isSelf && !perms.canReadSelf { // Check specific self-read denial
			return nil, errors.New("Forbidden: You need 'users:read:self' permission to view your own profile")
		}
		return nil, errors.New("Forbidden: You need 'users:read:all' permission to view other profiles")
	}

	s.logger.Infow("Service: User retrieved successfully", "target_user_id", targetUserID)
	return uResult.user, nil
}

// UpdateUser updates a user's details.
// Permissions: "users:update:self" or "users:update:all"
func (s *userService) UpdateUser(targetUserID uint, requestingUserID uint, input *UpdateUserInput) (*models.User, error) {
	s.logger.Infow("Service: Attempting to update user", "target_user_id", targetUserID, "requesting_user_id", requestingUserID)
	// Check if requesting user exists first (as in GetUserByID)
	if requestingUserID != 0 {
		_, err := s.repo.FindByID(requestingUserID)
		if err != nil {
			s.logger.Warnw("Service: Requesting user not found for UpdateUser", "requesting_user_id", requestingUserID, "target_user_id", targetUserID, "error", err)
			return nil, errors.New("requesting user invalid")
		}
	}

	// --- Permission Check (Concurrent) ---
	type permResult struct { // Define struct specific to update permissions needed
		canUpdateSelf bool
		canUpdateAny  bool
		err           error
	}
	permissionChan := make(chan permResult, 1)
	go func() {
		// CORRECTED: Assign to correct fields
		var result permResult
		result.canUpdateAny, result.err = auth.UserHasPermissions(requestingUserID, "users:update:all")
		if result.err == nil {
			var errSelf error
			result.canUpdateSelf, errSelf = auth.UserHasPermissions(requestingUserID, "users:update:self")
			result.err = errors.Join(result.err, errSelf)
		}
		permissionChan <- result
	}()

	// --- Fetch Target User (Concurrent) --- remains the same
	type userResult struct {
		user *models.User
		err  error
	}
	userChan := make(chan userResult, 1)
	go func() {
		user, err := s.repo.FindByID(targetUserID)
		userChan <- userResult{user: user, err: err}
	}()

	// --- Check Email Conflict (Concurrent, if email provided) --- remains the same
	type emailResult struct {
		existingUser *models.User
		err          error
	}
	emailChan := make(chan emailResult, 1)
	if input.Email != nil && *input.Email != "" {
		go func() {
			existingUser, err := s.repo.FindByEmail(*input.Email)
			emailChan <- emailResult{existingUser: existingUser, err: err}
		}()
	} else {
		emailChan <- emailResult{existingUser: nil, err: nil}
	}

	// Await results
	perms := <-permissionChan
	uResult := <-userChan
	eResult := <-emailChan

	// Handle errors - **Check errors first**
	if perms.err != nil {
		if requestingUserID != 0 && strings.Contains(perms.err.Error(), fmt.Sprintf("user with ID %d not found", requestingUserID)) {
			s.logger.Warnw("Service: Requesting user vanished during update permission check", "requesting_user_id", requestingUserID)
			return nil, errors.New("requesting user invalid")
		}
		s.logger.Errorw("Service: Update permission check failed internally", "requesting_user_id", requestingUserID, "error", perms.err)
		return nil, fmt.Errorf("internal error during permission check")
	}
	if uResult.err != nil {
		if errors.Is(uResult.err, gorm.ErrRecordNotFound) {
			return nil, errors.New("User not found")
		}
		s.logger.Errorw("Service: Failed to retrieve target user for update", "target_user_id", targetUserID, "error", uResult.err)
		return nil, fmt.Errorf("failed to retrieve user for update")
	}
	if input.Email != nil && eResult.err != nil && !errors.Is(eResult.err, gorm.ErrRecordNotFound) {
		// DB error during email check
		s.logger.Errorw("Service: DB error checking email uniqueness for update", "email", *input.Email, "error", eResult.err)
		return nil, errors.New("internal error checking email uniqueness")
	}

	// Check permissions - **Use boolean fields**
	isSelf := targetUserID == requestingUserID
	s.logger.Debugw("Service: Update permission check values", "is_self", isSelf, "can_update_self", perms.canUpdateSelf, "can_update_any", perms.canUpdateAny)

	// CORRECTED: Access boolean fields
	if !((isSelf && perms.canUpdateSelf) || (!isSelf && perms.canUpdateAny)) {
		if isSelf && !perms.canUpdateSelf {
			return nil, errors.New("Forbidden: You need 'users:update:self' permission to update your own profile")
		}
		return nil, errors.New("Forbidden: You need 'users:update:all' permission to update other profiles")
	}

	user := uResult.user
	needsSave := false

	// Validate and Update Email - **Check for conflict using awaited result**
	if input.Email != nil {
		// Use the result from the channel 'eResult'
		if eResult.existingUser != nil && eResult.existingUser.ID != user.ID {
			// Email conflict
			return nil, errors.New("Email address is already in use by another account")
		}
		// Only update if the email is actually different
		if user.Email != *input.Email {
			user.Email = *input.Email
			needsSave = true
			s.logger.Debugw("Service: Updating email", "user_id", user.ID, "new_email", *input.Email)
		}
	}

	// ... (Update Nickname, Password remain the same) ...
	// Update Nickname
	if input.Nickname != nil && user.Nickname != *input.Nickname {
		user.Nickname = *input.Nickname
		needsSave = true
		s.logger.Debugw("Service: Updating nickname", "user_id", user.ID, "new_nickname", *input.Nickname)
	}

	// Update Password
	if input.Password != nil {
		if len(*input.Password) < 6 { // Example validation
			return nil, errors.New("password must be at least 6 characters long") // Bad request type error
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*input.Password), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Errorw("Service: Failed to hash new password during update", "user_id", user.ID, "error", err)
			return nil, errors.New("could not process new password")
		}
		user.Password = string(hashedPassword)
		needsSave = true
		s.logger.Debugw("Service: Updating password", "user_id", user.ID)
	}

	// Save if changes were made
	if needsSave {
		s.logger.Infow("Service: Saving updated user data", "user_id", user.ID)
		if err := s.repo.Update(user); err != nil {
			s.logger.Errorw("Service: Failed to save user updates in repository", "user_id", user.ID, "error", err)
			return nil, errors.New("failed to save user updates")
		}
	} else {
		s.logger.Infow("Service: No fields needed updating", "user_id", user.ID)
	}

	return user, nil
}

// ListUsers retrieves a paginated list of users.
// Permissions: "users:list"
func (s *userService) ListUsers(page int, pageSize int, requestingUserID uint) ([]models.User, int64, error) {
	s.logger.Infow("Service: Attempting to list users", "requesting_user_id", requestingUserID, "page", page, "page_size", pageSize)
	// Check if requesting user exists first
	if requestingUserID != 0 {
		_, err := s.repo.FindByID(requestingUserID)
		if err != nil {
			s.logger.Warnw("Service: Requesting user not found for ListUsers", "requesting_user_id", requestingUserID, "error", err)
			return nil, 0, errors.New("requesting user invalid")
		}
	}

	// --- Permission Check (Concurrent) ---
	type permResult struct { // Struct specific to list permission
		canList bool
		err     error
	}
	permissionChan := make(chan permResult, 1)
	go func() {
		// CORRECTED: Assign to correct fields
		var result permResult
		result.canList, result.err = auth.UserHasPermissions(requestingUserID, "users:list")
		permissionChan <- result
	}()

	// --- Fetch Users (Concurrent) --- remains the same
	type usersResult struct {
		users []models.User
		total int64
		err   error
	}
	usersChan := make(chan usersResult, 1)
	go func() {
		users, total, err := s.repo.FindAll(page, pageSize)
		usersChan <- usersResult{users: users, total: total, err: err}
	}()

	// Await results
	perms := <-permissionChan
	uResult := <-usersChan

	// Handle errors - **Check errors first**
	if perms.err != nil {
		if requestingUserID != 0 && strings.Contains(perms.err.Error(), fmt.Sprintf("user with ID %d not found", requestingUserID)) {
			s.logger.Warnw("Service: Requesting user vanished during list permission check", "requesting_user_id", requestingUserID)
			return nil, 0, errors.New("requesting user invalid")
		}
		s.logger.Errorw("Service: List permission check failed internally", "requesting_user_id", requestingUserID, "error", perms.err)
		return nil, 0, fmt.Errorf("internal error during permission check")
	}
	if uResult.err != nil {
		s.logger.Errorw("Service: Failed to retrieve users from repository", "error", uResult.err)
		return nil, 0, fmt.Errorf("failed to retrieve users")
	}

	// Check permissions - **Use boolean field**
	// CORRECTED: Access boolean field
	if !perms.canList {
		return nil, 0, errors.New("Forbidden: You need 'users:list' permission")
	}

	s.logger.Infow("Service: Users listed successfully", "count", len(uResult.users), "total", uResult.total)
	return uResult.users, uResult.total, nil
}

// DeleteUser Delete user information based on user ID
func (s *userService) DeleteUser(targetUserID uint, requestingUserID uint) error {
	s.logger.Infow("Service: Attempting to delete user", "target_user_id", targetUserID, "requesting_user_id", requestingUserID)
	// Check if requesting user exists first
	if requestingUserID != 0 {
		_, err := s.repo.FindByID(requestingUserID)
		if err != nil {
			s.logger.Warnw("Service: Requesting user not found for DeleteUser", "requesting_user_id", requestingUserID, "error", err)
			return errors.New("requesting user invalid")
		}
	}

	// --- Permission Check (Concurrent) ---
	type permResult struct { // Struct specific to delete permissions
		canDeleteSelf bool
		canDeleteAny  bool
		err           error
	}
	permissionChan := make(chan permResult, 1)
	go func() {
		// CORRECTED: Assign to correct fields
		var result permResult
		result.canDeleteAny, result.err = auth.UserHasPermissions(requestingUserID, "users:delete:all")
		if result.err == nil {
			var errSelf error
			result.canDeleteSelf, errSelf = auth.UserHasPermissions(requestingUserID, "users:delete:self")
			result.err = errors.Join(result.err, errSelf)
		}
		permissionChan <- result
	}()

	// --- Fetch User (Concurrent) --- remains the same
	type userResult struct {
		user *models.User
		err  error
	}
	userChan := make(chan userResult, 1)
	go func() {
		user, err := s.repo.FindByID(targetUserID)
		userChan <- userResult{user: user, err: err}
	}()

	// Await results
	perms := <-permissionChan
	uResult := <-userChan

	// Handle errors - **Check errors first**
	if perms.err != nil {
		if requestingUserID != 0 && strings.Contains(perms.err.Error(), fmt.Sprintf("user with ID %d not found", requestingUserID)) {
			s.logger.Warnw("Service: Requesting user vanished during delete permission check", "requesting_user_id", requestingUserID)
			return errors.New("requesting user invalid")
		}
		s.logger.Errorw("Service: Delete permission check failed internally", "requesting_user_id", requestingUserID, "error", perms.err)
		return fmt.Errorf("internal error during permission check")
	}
	if uResult.err != nil {
		if errors.Is(uResult.err, gorm.ErrRecordNotFound) {
			return errors.New("User not found")
		}
		s.logger.Errorw("Service: Failed to retrieve target user for delete", "target_user_id", targetUserID, "error", uResult.err)
		return fmt.Errorf("failed to retrieve user for delete")
	}

	// Check permissions - **Use boolean fields**
	isSelf := targetUserID == requestingUserID
	s.logger.Debugw("Service: Delete permission check values", "is_self", isSelf, "can_delete_self", perms.canDeleteSelf, "can_delete_any", perms.canDeleteAny)

	// CORRECTED: Access boolean fields
	if !((isSelf && perms.canDeleteSelf) || (!isSelf && perms.canDeleteAny)) {
		if isSelf && !perms.canDeleteSelf {
			return errors.New("Forbidden: You need 'users:delete:self' permission to delete your own profile")
		}
		return errors.New("Forbidden: You need 'users:delete:all' permission to delete other profiles")
	}

	// Perform deletion
	err := s.repo.Delete(uResult.user)
	if err != nil {
		s.logger.Errorw("Service: Failed to delete user from repository", "target_user_id", targetUserID, "error", err)
		return fmt.Errorf("failed to delete user")
	}

	s.logger.Infow("Service: User deleted successfully", "target_user_id", targetUserID)
	return nil
}
