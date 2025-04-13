package grpcserver

import (
	"context"
	registrypb "mygin-restful/proto/registry"
	reg "mygin-restful/registry"
)

type registryServiceServer struct {
	registrypb.UnimplementedRegistryServiceServer
	registry reg.ServiceRegistry
}

func NewRegistryServiceServer(r reg.ServiceRegistry) registrypb.RegistryServiceServer {
	return &registryServiceServer{registry: r}
}

func (s *registryServiceServer) Register(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	if req.Service == nil || req.Service.Name == "" || req.Service.Address == "" {
		return &registrypb.RegisterResponse{Success: false, Message: "Invalid service info"}, nil
	}
	err := s.registry.Register(req.Service.Name, req.Service.Address)
	if err != nil {
		return &registrypb.RegisterResponse{Success: false, Message: err.Error()}, nil
	}
	return &registrypb.RegisterResponse{Success: true, Message: "Service registered"}, nil
}

func (s *registryServiceServer) Discover(ctx context.Context, req *registrypb.DiscoverRequest) (*registrypb.DiscoverResponse, error) {
	if req.Name == "" {
		return &registrypb.DiscoverResponse{Found: false, Error: "Service name required"}, nil
	}
	addr, err := s.registry.Discover(req.Name)
	if err != nil {
		return &registrypb.DiscoverResponse{Found: false, Error: err.Error()}, nil
	}
	return &registrypb.DiscoverResponse{Found: true, Address: addr}, nil
}
