package interceptors

import (
	"context"
	"mygin-restful/auth"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// UserIDKey is the context key for user ID.
	UserIDKey contextKey = "user_id"
	// UsernameKey is the context key for username.
	UsernameKey contextKey = "username"
)

// AuthInterceptor returns a new unary server interceptor for JWT authentication.
func AuthInterceptor(jwtSecret []byte) grpc.UnaryServerInterceptor {
	// Update SetSigningKey if it's not set elsewhere (e.g., during init)
	// auth.SetSigningKey(jwtSecret) // Might be redundant if set in main

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo, // Info about the RPC call
		handler grpc.UnaryHandler, // The next handler in the chain
	) (interface{}, error) {

		// --- Define public methods that bypass authentication ---
		publicMethods := map[string]bool{
			"/auth.AuthService/Login": true, // Login doesn't require prior auth
			// Add other public methods if any (e.g., health check, service discovery related?)
			// Example: "/grpc.health.v1.Health/Check": true, (if you want unauthenticated health checks)
			"/registry.RegistryService/Discover": true, // Assuming discovery might be public
			// Note: Consider if Register should be public or require some auth
		}

		// Check if the current method is public
		if _, isPublic := publicMethods[info.FullMethod]; isPublic {
			// Skip auth check for public methods
			return handler(ctx, req)
		}

		// --- Authentication Logic ---
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
		}

		values := md.Get("authorization") // Case-insensitive lookup
		if len(values) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization token is not provided")
		}

		authHeader := values[0]
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization header format")
		}
		tokenString := parts[1]

		// Validate the token using your existing auth logic
		claims, err := auth.ParseAndValidateToken(tokenString)
		if err != nil {
			// Map token validation errors to Unauthenticated
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		// --- Inject user info into context ---
		// Create a new context with user ID and username
		newCtx := context.WithValue(ctx, UserIDKey, claims.UserID)
		newCtx = context.WithValue(newCtx, UsernameKey, claims.Username)

		// Call the next handler with the new context containing user info
		return handler(newCtx, req)
	}
}

// Helper functions to retrieve user info from context in your gRPC service handlers

// GetUserIDFromContext extracts the user ID from the context.
func GetUserIDFromContext(ctx context.Context) (uint, bool) {
	userID, ok := ctx.Value(UserIDKey).(uint)
	return userID, ok
}

// GetUsernameFromContext extracts the username from the context.
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}
