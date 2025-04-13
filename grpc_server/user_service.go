package grpcserver

import (
	"context"
	"mygin-restful/models"
	userpb "mygin-restful/proto/user" // Import generated user proto
	"mygin-restful/services"

	"google.golang.org/protobuf/types/known/timestamppb"
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
	// Note: Basic implementation. Production might need to extract requesting user ID from context (via gRPC metadata/interceptor)
	// For now, assuming any gRPC call has permission or using a dummy/system user ID for checks.
	// Let's assume requestingUserID 0 means internal call or permission checks happen elsewhere for now.
	requestingUserID := uint(0) // Simplified for example

	user, err := s.userService.GetUserByID(uint(req.UserId), requestingUserID)
	if err != nil {
		// Convert service errors to gRPC errors (e.g., NotFound, PermissionDenied)
		// For simplicity, returning the raw error now. Use status.Errorf later.
		return nil, err
	}
	return modelToProtoUser(user), nil
}

// ListUsers is the gRPC handler for listing users.
func (s *userServiceServer) ListUsers(ctx context.Context, req *userpb.ListUsersRequest) (*userpb.ListUsersResponse, error) {
	requestingUserID := uint(0) // Simplified for example

	page, pageSize := int(req.Page), int(req.PageSize)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	users, total, err := s.userService.ListUsers(page, pageSize, requestingUserID)
	if err != nil {
		// Convert service errors to gRPC errors
		return nil, err
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
