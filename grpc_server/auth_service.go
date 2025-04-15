package grpcserver

import (
	"context"
	"errors"
	"mygin-restful/auth"
	"mygin-restful/database"
	"mygin-restful/models"
	authpb "mygin-restful/proto/auth"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type authServiceServer struct {
	authpb.UnimplementedAuthServiceServer
}

func NewAuthServiceServer() authpb.AuthServiceServer {
	return &authServiceServer{}
}

func (s *authServiceServer) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	var user models.User
	// Ensure DB is available or injected
	if database.DB == nil {
		// s.logger.Error("Database connection not initialized for Login")
		return nil, status.Error(codes.Internal, "database connection error")
	}
	result := database.DB.Where("username = ?", req.Username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// Return specific response for logical failure, not gRPC error
			return &authpb.LoginResponse{Success: false, Message: "Invalid credentials"}, nil
		}
		return nil, status.Errorf(codes.Internal, "Database error: %v", result.Error) // Internal error for DB issues
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return &authpb.LoginResponse{Success: false, Message: "Invalid credentials"}, nil // Unsuccessful response
	}

	token, err := auth.GenerateToken(&user) // Reuse token generation
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Could not generate token: %v", err)
	}
	return &authpb.LoginResponse{Success: true, Token: token}, nil
}

func (s *authServiceServer) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	if req.Token == "" {
		// Although ParseAndValidateToken handles empty, explicit check is good
		return &authpb.ValidateTokenResponse{Valid: false, Error: "token is required"}, nil
	}
	claims, err := auth.ParseAndValidateToken(req.Token)
	if err != nil {
		// Return specific response for logical failure (invalid token)
		return &authpb.ValidateTokenResponse{Valid: false, Error: err.Error()}, nil
	}

	return &authpb.ValidateTokenResponse{
		Valid:    true,
		UserId:   uint64(claims.UserID),
		Username: claims.Username,
	}, nil
}

func (s *authServiceServer) CheckPermission(ctx context.Context, req *authpb.CheckPermissionRequest) (*authpb.CheckPermissionResponse, error) {
	if req.Permission == "" {
		// Use status.Error for invalid arguments
		return nil, status.Error(codes.InvalidArgument, "permission is required")
	}

	var userID uint
	var err error

	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required for permission check")
	}

	// Validate token first
	claims, err := auth.ParseAndValidateToken(req.Token)
	if err != nil {
		// Return specific response for logical failure (invalid token)
		return &authpb.CheckPermissionResponse{Granted: false, Error: "Invalid token: " + err.Error()}, nil
	}
	userID = claims.UserID

	// Check permissions using the existing logic
	granted, err := auth.UserHasPermissions(userID, req.Permission)
	if err != nil {
		// Log the internal error
		// s.logger.Errorf("Error checking permission '%s' for user %d: %v", req.Permission, userID, err)
		// Don't expose internal DB errors directly, map to a logical failure response
		if strings.Contains(err.Error(), "not found") { // Specific case if user vanished after token validation but before perm check
			return &authpb.CheckPermissionResponse{Granted: false, Error: "User not found during permission check"}, nil
		}
		return &authpb.CheckPermissionResponse{Granted: false, Error: "Internal error checking permissions"}, nil
	}

	if !granted {
		return &authpb.CheckPermissionResponse{Granted: false, Error: "Permission denied"}, nil
	}

	return &authpb.CheckPermissionResponse{Granted: true}, nil
}
