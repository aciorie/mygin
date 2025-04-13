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
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}). // For OpenAPI documentation
		Reads(services.CreateUserInput{}).                       // Documents the input structure
		Returns(http.StatusCreated, "User created successfully", UserResponse{}).
		Returns(http.StatusBadRequest, "Invalid request body", nil).
		Returns(http.StatusConflict, "Username or Email already exists", nil))

	// --- Routes requiring Authentication (Apply AuthFilter) ---
	ws.Route(ws.GET("/{user-id}").Filter(auth.AuthFilter()).To(ctl.getUserByIDHandler).
		Doc("Get user by ID").
		Param(ws.PathParameter("user-id", "Identifier of the user").DataType("integer")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Writes(UserResponse{}). // Documents the successful response structure
		Returns(http.StatusOK, "User found", UserResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil).
		Returns(http.StatusNotFound, "User not found", nil))

	ws.Route(ws.PUT("/{user-id}").Filter(auth.AuthFilter()).To(ctl.updateUserHandler).
		Doc("Update user by ID").
		Param(ws.PathParameter("user-id", "Identifier of the user to update").DataType("integer")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Reads(services.UpdateUserInput{}). // Documents input
		Writes(UserResponse{}).            // Documents success output
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
		Writes(PaginatedUsersResponse{}). // Documents success output
		Returns(http.StatusOK, "Users listed successfully", PaginatedUsersResponse{}).
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil))

	ws.Route(ws.DELETE("/{user-id}").Filter(auth.AuthFilter()).To(ctl.deleteUserHandler).
		Doc("Delete user by ID").
		Param(ws.PathParameter("user-id", "Identifier of the user to delete").DataType("integer")).
		Metadata(restfulspec.KeyOpenAPITags, []string{"users"}).
		Returns(http.StatusOK, "User deleted successfully", nil). // No content on success usually for DELETE
		Returns(http.StatusUnauthorized, "Unauthorized", nil).
		Returns(http.StatusForbidden, "Forbidden", nil).
		Returns(http.StatusNotFound, "User not found", nil)) // Also handle not found here
}

// --- go-restful Handler Functions ---

// createUserHandler (Handles POST /users/register)
func (ctl *UserController) createUserHandler(request *restful.Request, response *restful.Response) {
	input := new(services.CreateUserInput)
	err := request.ReadEntity(input)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid request body: " + err.Error()}, restful.MIME_JSON)
		return
	}

	// Basic validation (can be improved with a library)
	if input.Username == "" || input.Password == "" {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Username and password are required"}, restful.MIME_JSON)
		return
	}
	// Add email format validation if needed, though service layer might handle it too

	user, err := ctl.userService.CreateUser(input)
	if err != nil {
		statusCode := http.StatusInternalServerError
		message := "Failed to create user"
		// Check for specific service errors
		errMsg := err.Error()
		if strings.Contains(errMsg, "already exists") {
			statusCode = http.StatusConflict
			message = errMsg
		} else if strings.Contains(errMsg, "Could not hash password") {
			// Log internal error, return generic message
			// logger.Error("Password hashing failed", zap.Error(err))
			message = "Internal server error during user creation"
		} // Add more specific error handling if needed

		_ = response.WriteHeaderAndJson(statusCode, map[string]string{"message": message}, restful.MIME_JSON)
		return
	}

	_ = response.WriteHeaderAndJson(http.StatusCreated, mapModelToUserResponse(user), restful.MIME_JSON)
}

// getUserByIDHandler (Handles GET /users/{user-id})
func (ctl *UserController) getUserByIDHandler(request *restful.Request, response *restful.Response) {
	targetUserIDStr := request.PathParameter("user-id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"}, restful.MIME_JSON)
		return
	}

	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}

	user, err := ctl.userService.GetUserByID(uint(targetUserID), requestingUserID)
	if err != nil {
		handleServiceError(response, err)
		return
	}

	_ = response.WriteHeaderAndJson(http.StatusOK, mapModelToUserResponse(user), restful.MIME_JSON)
}

// updateUserHandler (Handles PUT /users/{user-id})
func (ctl *UserController) updateUserHandler(request *restful.Request, response *restful.Response) {
	targetUserIDStr := request.PathParameter("user-id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"}, restful.MIME_JSON)
		return
	}

	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}

	input := new(services.UpdateUserInput)
	err = request.ReadEntity(input)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid request body: " + err.Error()}, restful.MIME_JSON)
		return
	}

	updatedUser, err := ctl.userService.UpdateUser(uint(targetUserID), requestingUserID, input)
	if err != nil {
		handleServiceError(response, err)
		return
	}

	_ = response.WriteHeaderAndJson(http.StatusOK, mapModelToUserResponse(updatedUser), restful.MIME_JSON)
}

// listUsersHandler (Handles GET /users)
func (ctl *UserController) listUsersHandler(request *restful.Request, response *restful.Response) {
	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
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

	users, total, err := ctl.userService.ListUsers(page, pageSize, requestingUserID)
	if err != nil {
		handleServiceError(response, err)
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
	_ = response.WriteHeaderAndJson(http.StatusOK, respData, restful.MIME_JSON)
}

// deleteUserHandler (Handles DELETE /users/{user-id})
func (ctl *UserController) deleteUserHandler(request *restful.Request, response *restful.Response) {
	targetUserIDStr := request.PathParameter("user-id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
	if err != nil {
		_ = response.WriteHeaderAndJson(http.StatusBadRequest, map[string]string{"message": "Invalid user ID format"}, restful.MIME_JSON)
		return
	}

	requestingUserID, ok := getRequestingUserID(request)
	if !ok {
		_ = response.WriteHeaderAndJson(http.StatusUnauthorized, map[string]string{"message": "Unauthorized: Cannot identify requesting user"}, restful.MIME_JSON)
		return
	}

	err = ctl.userService.DeleteUser(uint(targetUserID), requestingUserID)
	if err != nil {
		handleServiceError(response, err) // Reuse error handling
		return
	}

	// Typically, DELETE returns 200 OK or 204 No Content on success
	response.WriteHeader(http.StatusOK) // Or http.StatusNoContent if preferred
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
func handleServiceError(response *restful.Response, err error) {
	errMsg := err.Error()
	statusCode := http.StatusInternalServerError
	message := "An internal error occurred" // Default message

	// More specific error mapping
	if strings.Contains(errMsg, "not found") { // Covers "User not found" etc.
		statusCode = http.StatusNotFound
		message = errMsg
	} else if strings.Contains(errMsg, "Forbidden") || strings.Contains(errMsg, "permission") || strings.Contains(errMsg, "No permission") {
		statusCode = http.StatusForbidden
		message = errMsg // Use the specific permission error from the service
	} else if strings.Contains(errMsg, "already in use") || strings.Contains(errMsg, "already exists") { // Covers email/username conflicts
		statusCode = http.StatusConflict
		message = errMsg
	} else if strings.Contains(errMsg, "Invalid credentials") {
		statusCode = http.StatusUnauthorized // Should ideally be handled by login directly, but good fallback
		message = errMsg
	} else {
		// Log the internal error for debugging
		// logger.Error("Unhandled service error", zap.Error(err))
	}

	_ = response.WriteHeaderAndJson(statusCode, map[string]string{"message": message}, restful.MIME_JSON)
}
