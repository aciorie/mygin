package grpcserver

import (
	"context"
	"errors"
	"mygin-restful/auth"
	"mygin-restful/database"
	"mygin-restful/models"
	authpb "mygin-restful/proto/auth"

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
	result := database.DB.Where("username = ?", req.Username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return &authpb.LoginResponse{Success: false, Message: "Invalid credentials"}, nil // Don't return error, return unsuccessful response
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
	claims, err := auth.ParseAndValidateToken(req.Token)
	if err != nil {
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
		return nil, status.Error(codes.InvalidArgument, "permission is required")
	}

	var userID uint
	var err error

	if req.Token != "" {
		// Validate token first
		claims, err := auth.ParseAndValidateToken(req.Token) // Reuse or create a helper
		if err != nil {
			return &authpb.CheckPermissionResponse{Granted: false, Error: "Invalid token: " + err.Error()}, nil
		}
		userID = claims.UserID
	} else {
		// Maybe allow checking based on user ID passed directly if token validated upstream?
		// For now, require token for permission checks via this method.
		return nil, status.Error(codes.InvalidArgument, "token is required for permission check")
	}

	// Check permissions using the existing logic
	// Need to ensure database.DB is accessible or injected
	granted, err := auth.UserHasPermissions(userID, req.Permission)
	if err != nil {
		// Log the internal error
		// log.Printf("Error checking permissions for user %d, permission %s: %v", userID, req.Permission, err)
		// Don't expose internal DB errors directly
		return &authpb.CheckPermissionResponse{Granted: false, Error: "Error checking permissions"}, nil
	}

	if !granted {
		return &authpb.CheckPermissionResponse{Granted: false, Error: "Permission denied"}, nil
	}

	return &authpb.CheckPermissionResponse{Granted: true}, nil
}
