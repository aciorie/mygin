package grpcserver

import (
	"context"
	"fmt" // Import fmt
	registrypb "mygin-restful/proto/registry"
	reg "mygin-restful/registry"
	"strings"

	"google.golang.org/grpc/codes"  // Import grpc/codes
	"google.golang.org/grpc/status" // Import grpc/status
)

type registryServiceServer struct {
	registrypb.UnimplementedRegistryServiceServer
	registry reg.ServiceRegistry
}

func NewRegistryServiceServer(r reg.ServiceRegistry) registrypb.RegistryServiceServer {
	return &registryServiceServer{registry: r}
}

// Register via gRPC: This endpoint's role is now less clear with Consul self-registration.
// Option 1: Deprecate it. Option 2: Make it proxy to Consul (complex). Option 3: Simple placeholder/error.
// Let's go with Option 3 for now.
func (s *registryServiceServer) Register(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	// Registration should primarily happen via Consul agent and self-registration in main.go.
	// This gRPC endpoint might be misleading or unused now.
	s.registry.List() // Example: Keep the field used to avoid unused errors, maybe log instead
	fmt.Printf("Received gRPC Register request for %s (typically handled by agent/main.go now)\n", req.Service.GetName())
	// Return an error or a message indicating this method might be deprecated/handled differently
	// return nil, status.Error(codes.Unimplemented, "Registration via gRPC API is deprecated; use Consul agent or service configuration")
	// Or just a simple success for now if needed by some client:
	return &registrypb.RegisterResponse{Success: true, Message: "Request received (registration handled by agent/main.go)"}, nil
}

// Discover via gRPC
func (s *registryServiceServer) Discover(ctx context.Context, req *registrypb.DiscoverRequest) (*registrypb.DiscoverResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "Service name required") // Use status.Error for invalid args
	}

	// Call the updated Discover interface method. Pass an empty tag for now.
	// The interface now returns a slice of addresses.
	addrs, err := s.registry.Discover(req.Name, "") // Pass "" for tag
	if err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "not found") {
			// Return a specific response for logical failure (not found)
			return &registrypb.DiscoverResponse{Found: false, Error: err.Error()}, nil
		}
		// For other errors, return an internal error
		// TODO: Log the internal error s.logger.Errorw(...)
		return nil, status.Errorf(codes.Internal, "Error discovering service '%s': %v", req.Name, err)
	}

	// Handle the slice of addresses. For the current proto (expecting one address),
	// return the first one found.
	if len(addrs) == 0 {
		// This case might be covered by the error check above, but good to be explicit
		return &registrypb.DiscoverResponse{Found: false, Error: fmt.Sprintf("No healthy instances found for service '%s'", req.Name)}, nil
	}

	// Return the first healthy address found
	return &registrypb.DiscoverResponse{Found: true, Address: addrs[0]}, nil
}
