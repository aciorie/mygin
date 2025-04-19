A basic project using Gin framework and restful style. Try to learn and improve it!

# Update Log v0.2.1
- Replaced the web framework from Gin to go-restful.
- Rewrote the Controller and Auth sections to accommodate go-restful.
- Defined Protobuf messages and gRPC service interfaces (User, Auth, Registry).
- Implemented the gRPC server, reusing existing service layer logic.
- Created a simple in-memory service registry.
- Updated the configuration to include gRPC port and JWT secret.
- Modified `main.go` to start both gRPC and go-restful servers simultaneously and handle graceful shutdown.


# Update Log v0.2.2

- Standardized error handling (gRPC status codes).
- Integrated logging (Zap).
- Implemented service self-registration.
- Cleaned up old code.


# Update Log v0.2.3
- Replaced in-memory service registry with Consul integration (hashicorp/consul/api).
- Implemented service self-registration/deregistration to Consul with health checks (main.go).
- Added standard gRPC health check service (google.golang.org/grpc/health).
- Added gRPC interceptors (go-grpc-middleware) for Zap logging and JWT authentication.
- Updated gRPC handlers to use user info from context provided by auth interceptor.
- Added Consul configuration options (config/config.yaml, config.go).