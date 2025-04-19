package grpcserver

import (
	"context"
	"errors"
	"mygin-restful/interceptors"
	"mygin-restful/models"
	userpb "mygin-restful/proto/user" // Import generated user proto
	"mygin-restful/services"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

// userServiceServer implements the proto-defined UserServiceServer interface.
// It embeds the Unimplemented server for forward compatibility.
type userServiceServer struct {
	userpb.UnimplementedUserServiceServer
	userService services.UserService // Reuse the existing service logic
}

// NewUserServiceServer creates a new gRPC user service server.
func NewUserServiceServer(us services.UserService) userpb.UserServiceServer {
	return &userServiceServer{userService: us}
}

// Helper to convert model.User to proto.User
func modelToProtoUser(u *models.User) *userpb.User {
	if u == nil {
		return nil
	}

	return &userpb.User{
		Id:        uint64(u.ID),
		Username:  u.Username,
		Email:     u.Email,
		Nickname:  u.Nickname,
		CreatedAt: timestamppb.New(u.CreatedAt),
		UpdatedAt: timestamppb.New(u.UpdatedAt),
	}
}

// GetUser is the gRPC handler for retrieving a user.
func (s *userServiceServer) GetUser(ctx context.Context, req *userpb.GetUserRequest) (*userpb.User, error) {
	// --- Retrieve requesting user ID from context injected by interceptor ---
	requestingUserID, ok := interceptors.GetUserIDFromContext(ctx)
	if !ok {
		// This should ideally not happen if AuthInterceptor runs correctly for non-public methods
		// Log error, maybe return Internal? Or Unauthenticated? Depends on policy.
		// s.logger.Error("Failed to get user ID from context in GetUser handler")
		return nil, status.Error(codes.Internal, "could not identify requesting user from context")
	}
	// --- End Context Retrieval ---

	// Now use the actual requestingUserID for the service call
	user, err := s.userService.GetUserByID(uint(req.UserId), requestingUserID) // Pass the real ID
	if err != nil {
		errMsg := err.Error()
		if errors.Is(err, gorm.ErrRecordNotFound) || strings.Contains(errMsg, "not found") {
			return nil, status.Errorf(codes.NotFound, "user with ID %d not found", req.UserId)
		}
		// Use the actual error message for permission denied
		if strings.Contains(errMsg, "Forbidden") || strings.Contains(errMsg, "permission") {
			return nil, status.Errorf(codes.PermissionDenied, errMsg) // Return the specific message
		}
		// Log internal errors for debugging
		// s.logger.Errorf("Failed to get user %d: %v", req.UserId, err)
		return nil, status.Errorf(codes.Internal, "internal error fetching user %d", req.UserId)
	}
	return modelToProtoUser(user), nil
}

// ListUsers is the gRPC handler for listing users.
func (s *userServiceServer) ListUsers(ctx context.Context, req *userpb.ListUsersRequest) (*userpb.ListUsersResponse, error) {
	// Retrieve requesting user ID from context
	requestingUserID, ok := interceptors.GetUserIDFromContext(ctx)
	if !ok {
		// s.logger.Error("Failed to get user ID from context in ListUsers handler")
		return nil, status.Error(codes.Internal, "could not identify requesting user from context")
	}

	page, pageSize := int(req.Page), int(req.PageSize)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	// Use the actual requestingUserID
	users, total, err := s.userService.ListUsers(page, pageSize, requestingUserID)
	if err != nil {
		errMsg := err.Error()
		// Use the actual error message for permission denied
		if strings.Contains(errMsg, "Forbidden") || strings.Contains(errMsg, "permission") {
			return nil, status.Errorf(codes.PermissionDenied, errMsg)
		}
		// s.logger.Errorf("Failed to list users: %v", err)
		return nil, status.Errorf(codes.Internal, "internal error listing users")
	}

	protoUsers := make([]*userpb.User, len(users))
	for i, u := range users {
		protoUsers[i] = modelToProtoUser(&u)
	}

	return &userpb.ListUsersResponse{
		Users:    protoUsers,
		Total:    total,
		Page:     int32(page),
		PageSize: int32(pageSize),
	}, nil
}
