package controllers

import (
	"mygin-restful/auth"
	"mygin-restful/models"
	"mygin-restful/services"
	"net/http"
	"strconv"
	"strings"
	"time"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	restful "github.com/emicklei/go-restful/v3"
	"go.uber.org/zap"
)

// Define the Service interface that the Controller depends on
type UserController struct {
	userService services.UserService
	logger      *zap.SugaredLogger // Add logger
}

// Constructor, used to create a UserController instance
func NewUserController(userService services.UserService, logger *zap.SugaredLogger) *UserController {
	return &UserController{
		userService: userService,
		logger:      logger,
	}
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

// --- Helper to map model to response ---
func mapModelToUserResponse(user *models.User) UserResponse {
	if user == nil {
		// Handle nil user case if necessary, though usually errors prevent this
		return UserResponse{}
	}
	return UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Nickname:  user.Nickname,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

// --- go-restful Route Definitions ---

// RegisterRoutes sets up the user-related routes for a go-restful WebService.
func (ctl *UserController) RegisterRoutes(ws *restful.WebService) {
	// Define path and basic metadata
	ws.Path("/users").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)

	// --- Public Registration Route (moved from main, logically belongs here) ---
	// It's common to have registration outside the main "/users" authenticated group
	// We can define it separately or adjust the path/filter logic.
	// For simplicity, let's add it here but *without* the AuthFilter.
	ws.Route(ws.POST("/register").To(ctl.createUserHandler).
		Doc("Register a new user").
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Reads(services.CreateUserInput{}).
		Returns(http.StatusCreated, "User created successfully", UserResponse{}).
		Returns(http.StatusBadRequest, "Invalid request body", nil).
		Returns(http.StatusConflict, "Username or Email already exists", nil))

	ws.Route(ws.GET("/{user-id}").Filter(auth.AuthFilter()).To(ctl.getUserByIDHandler).
		Doc("Get user by ID").
		Param(ws.PathParameter("user-id", "Identifier of the user").DataType("integer")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Writes(UserResponse{}).
		Returns(http.StatusOK, "User found", UserResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil).
		Returns(http.StatusNotFound, "User not found", nil))

	ws.Route(ws.PUT("/{user-id}").Filter(auth.AuthFilter()).To(ctl.updateUserHandler).
		Doc("Update user by ID").
		Param(ws.PathParameter("user-id", "Identifier of the user to update").DataType("integer")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Reads(services.UpdateUserInput{}).
		Writes(UserResponse{}).
		Returns(http.StatusOK, "User updated successfully", UserResponse{}).
		Returns(http.StatusBadRequest, "Invalid request body or user ID", nil).
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil).
		Returns(http.StatusNotFound, "User not found", nil).
		Returns(http.StatusConflict, "Email conflict", nil))

	ws.Route(ws.GET("").Filter(auth.AuthFilter()).To(ctl.listUsersHandler).
		Doc("List users with pagination").
		Param(ws.QueryParameter("page", "Page number (default 1)").DataType("integer").DefaultValue("1")).
		Param(ws.QueryParameter("page_size", "Users per page (default 10)").DataType("integer").DefaultValue("10")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Writes(PaginatedUsersResponse{}).
		Returns(http.StatusOK, "Users listed successfully", PaginatedUsersResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil))

	ws.Route(ws.DELETE("/{user-id}").Filter(auth.AuthFilter()).To(ctl.deleteUserHandler).
		Doc("Delete user by ID").
		Param(ws.PathParameter("user-id", "Identifier of the user to delete").DataType("integer")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Returns(http.StatusOK, "User deleted successfully", nil).
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil).
		Returns(http.StatusNotFound, "User not found", nil))
}

// --- go-restful Handler Functions ---

// createUserHandler (Handles POST /users/register)
func (ctl *UserController) createUserHandler(request *restful.Request, response *restful.Response) {
	input := new(services.CreateUserInput)
	err := request.ReadEntity(input)
	if err != nil {
		ctl.logger.Warnw("Failed to read entity for user creation", "error", err)
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid request body: " + err.Error()}, restful.MIME_JSON)
		return
	}
	ctl.logger.Infow("Attempting to create user", "username", input.Username, "email", input.Email) // Log attempt

	if input.Username == "" || input.Password == "" {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Username and password are required"}, restful.MIME_JSON)
		return
	}

	user, err := ctl.userService.CreateUser(input) // Service layer handles detailed checks
	if err != nil {
		ctl.logger.Errorw("Failed to create user in service", "username", input.Username, "error", err)
		handleServiceError(response, err, ctl.logger) // Pass logger to error handler
		return
	}

	ctl.logger.Infow("User created successfully", "user_id", user.ID, "username", user.Username)
	_ = response.WriteHeaderAndJson(http.StatusCreated, mapModelToUserResponse(user), restful.MIME_JSON)
}

// getUserByIDHandler (Handles GET /users/{user-id})
func (ctl *UserController) getUserByIDHandler(request *restful.Request, response *restful.Response) {
	targetUserIDStr := request.PathParameter("user-id")
	ctl.logger.Infow("Attempting to get user by ID", "target_user_id_str", targetUserIDStr)
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		ctl.logger.Warnw("Invalid user ID format in path", "user_id_str", targetUserIDStr, "error", err)
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"}, restful.MIME_JSON)
		return
	}

	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		ctl.logger.Error("Could not get requesting user ID from context") // Auth filter should prevent this
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}
	ctl.logger.Infow("Fetching user details", "requesting_user_id", requestingUserID, "target_user_id", targetUserID)

	user, err := ctl.userService.GetUserByID(uint(targetUserID), requestingUserID)
	if err != nil {
		ctl.logger.Warnw("Failed to get user from service", "target_user_id", targetUserID, "requesting_user_id", requestingUserID, "error", err)
		handleServiceError(response, err, ctl.logger)
		return
	}

	ctl.logger.Infow("User retrieved successfully", "target_user_id", targetUserID)
	_ = response.WriteHeaderAndJson(http.StatusOK, mapModelToUserResponse(user), restful.MIME_JSON)
}

// updateUserHandler (Handles PUT /users/{user-id})
func (ctl *UserController) updateUserHandler(request *restful.Request, response *restful.Response) {
	targetUserIDStr := request.PathParameter("user-id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		ctl.logger.Warnw("Invalid user ID format for update", "user_id_str", targetUserIDStr, "error", err)
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"}, restful.MIME_JSON)
		return
	}

	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		ctl.logger.Error("Could not get requesting user ID from context for update")
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}
	ctl.logger.Infow("Attempting to update user", "requesting_user_id", requestingUserID, "target_user_id", targetUserID)

	input := new(services.UpdateUserInput)
	err = request.ReadEntity(input)
	if err != nil {
		ctl.logger.Warnw("Failed to read entity for user update", "target_user_id", targetUserID, "error", err)
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid request body: " + err.Error()}, restful.MIME_JSON)
		return
	}

	updatedUser, err := ctl.userService.UpdateUser(uint(targetUserID), requestingUserID, input)
	if err != nil {
		ctl.logger.Warnw("Failed to update user in service", "target_user_id", targetUserID, "requesting_user_id", requestingUserID, "error", err)
		handleServiceError(response, err, ctl.logger)
		return
	}

	ctl.logger.Infow("User updated successfully", "target_user_id", targetUserID)
	_ = response.WriteHeaderAndJson(http.StatusOK, mapModelToUserResponse(updatedUser), restful.MIME_JSON)
}

// listUsersHandler (Handles GET /users)
func (ctl *UserController) listUsersHandler(request *restful.Request, response *restful.Response) {
	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		ctl.logger.Error("Could not get requesting user ID from context for listing users")
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}

	pageStr := request.QueryParameter("page")
	pageSizeStr := request.QueryParameter("page_size")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 {
		pageSize = 10
	}
	ctl.logger.Infow("Attempting to list users", "requesting_user_id", requestingUserID, "page", page, "page_size", pageSize)

	users, total, err := ctl.userService.ListUsers(page, pageSize, requestingUserID)
	if err != nil {
		ctl.logger.Warnw("Failed to list users from service", "requesting_user_id", requestingUserID, "error", err)
		handleServiceError(response, err, ctl.logger)
		return
	}

	userResponses := make([]UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = mapModelToUserResponse(&user)
	}

	respData := PaginatedUsersResponse{
		Users:    userResponses,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}
	ctl.logger.Infow("Users listed successfully", "count", len(users), "total", total, "page", page)
	_ = response.WriteHeaderAndJson(http.StatusOK, respData, restful.MIME_JSON)
}

// deleteUserHandler (Handles DELETE /users/{user-id})
func (ctl *UserController) deleteUserHandler(request *restful.Request, response *restful.Response) {
	targetUserIDStr := request.PathParameter("user-id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		ctl.logger.Warnw("Invalid user ID format for delete", "user_id_str", targetUserIDStr, "error", err)
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"}, restful.MIME_JSON)
		return
	}

	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		ctl.logger.Error("Could not get requesting user ID from context for delete")
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}
	ctl.logger.Infow("Attempting to delete user", "requesting_user_id", requestingUserID, "target_user_id", targetUserID)

	err = ctl.userService.DeleteUser(uint(targetUserID), requestingUserID)
	if err != nil {
		ctl.logger.Warnw("Failed to delete user in service", "target_user_id", targetUserID, "requesting_user_id", requestingUserID, "error", err)
		handleServiceError(response, err, ctl.logger) // Reuse error handling
		return
	}

	ctl.logger.Infow("User deleted successfully", "target_user_id", targetUserID)
	response.WriteHeader(http.StatusOK) // Or http.StatusNoContent
}

// --- Utility Functions ---

// getRequestingUserID extracts the user ID set by the AuthFilter.
func getRequestingUserID(request *restful.Request) (uint, bool) {
	userIDAttr := request.Attribute("user_id")
	if userIDAttr == nil {
		return 0, false
	}
	userID, ok := userIDAttr.(uint)
	return userID, ok
}

// handleServiceError translates common service errors to HTTP responses.
func handleServiceError(response *restful.Response, err error, logger *zap.SugaredLogger) {
	errMsg := err.Error()
	statusCode := http.StatusInternalServerError
	message := "An internal error occurred" // Default user-facing message

	// Map specific errors
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "not exist") {
		statusCode = http.StatusNotFound
		message = errMsg
	} else if strings.Contains(errMsg, "Forbidden") || strings.Contains(errMsg, "permission") || strings.Contains(errMsg, "No permission") {
		statusCode = http.StatusForbidden
		message = errMsg // Use the specific permission error
	} else if strings.Contains(errMsg, "already in use") || strings.Contains(errMsg, "already exists") {
		statusCode = http.StatusConflict
		message = errMsg
	} else if strings.Contains(errMsg, "Invalid credentials") {
		statusCode = http.StatusUnauthorized
		message = errMsg
	} else {
		// Log the original internal error for debugging, return generic message
		logger.Errorw("Unhandled service error mapped to internal server error", "original_error", err)
		message = "An unexpected internal error occurred. Please try again later."
	}

	_ = response.WriteHeaderAndJson(statusCode, map[string]string{"message": message}, restful.MIME_JSON)
}
