package main

import (
	"context"
	"fmt"
	"log"
	"mygin-restful/auth"
	"mygin-restful/config"
	"mygin-restful/controllers"
	"mygin-restful/database"
	grpcHandler "mygin-restful/grpc_server"
	authpb "mygin-restful/proto/auth"
	registrypb "mygin-restful/proto/registry"
	userpb "mygin-restful/proto/user"
	"mygin-restful/registry"
	"mygin-restful/repositories"
	"mygin-restful/services"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	restful "github.com/emicklei/go-restful/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Define a general error structure
type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Define a login requirement structure
type Login struct {
	User     string `json:"user" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Error implements error.
func (a *AppError) Error() string {
	return fmt.Sprintf("AppError: Code=%d, Message=%s", a.Code, a.Message)
}

func main() {
	// --- 1. Initialization ---
	config.InitConfig()

	// Logger setup (remains the same)
	var logger *zap.Logger
	var err error
	// ... (logger initialization code) ...
	if config.AppConfig.LogLevel == "debug" {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	defer logger.Sync()
	sugar := logger.Sugar() // Use SugaredLogger for convenience

	// Setting the JWT Secret (remains the same)
	if config.AppConfig.JwtSecret != "" && config.AppConfig.JwtSecret != "default-very-insecure-secret-key" {
		auth.SetSigningKey([]byte(config.AppConfig.JwtSecret))
		sugar.Info("JWT signing key set from config.")
	} else {
		sugar.Warn("Using default insecure JWT secret key!")
	}

	// Database (remains the same)
	db := database.InitDB()

	// Service Registry (remains the same)
	serviceRegistry := registry.NewInMemoryRegistry()

	// Repositories (remains the same)
	userRepository := repositories.NewUserRepository(db)

	// Services (Inject Logger)
	userService := services.NewUserService(userRepository, sugar.Named("UserService")) // Inject logger

	// Controllers (Inject Logger)
	userController := controllers.NewUserController(userService, sugar.Named("UserController")) // Inject logger

	// gRPC Server Handlers (Inject Logger if needed, AuthService might benefit)
	grpcUserServer := grpcHandler.NewUserServiceServer(userService)
	grpcAuthServer := grpcHandler.NewAuthServiceServer( /* sugar.Named("AuthGRPCService") */ )
	grpcRegistryServer := grpcHandler.NewRegistryServiceServer(serviceRegistry)

	// --- 2. Setup gRPC Server ---
	grpcListenAddr := fmt.Sprintf(":%d", config.AppConfig.GRPCPort)
	lis, err := net.Listen("tcp", grpcListenAddr)
	if err != nil {
		sugar.Fatalf("Failed to listen for gRPC: %v", err)
	}
	// TODO: Add gRPC Interceptors for logging, auth validation, etc.
	grpcServer := grpc.NewServer()

	// Register gRPC services (remains the same)
	userpb.RegisterUserServiceServer(grpcServer, grpcUserServer)
	authpb.RegisterAuthServiceServer(grpcServer, grpcAuthServer)
	registrypb.RegisterRegistryServiceServer(grpcServer, grpcRegistryServer)
	reflection.Register(grpcServer)
	sugar.Infof("gRPC server listening on %s", grpcListenAddr)

	// --- 3. Setup RESTful (go-restful) Server ---
	restContainer := restful.NewContainer()
	restContainer.EnableContentEncoding(true)
	// Add CORS filter if needed

	// **Add Request Logging Filter**
	restContainer.Filter(LogRequestFilter(sugar.Named("REST"))) // Enable logging filter

	// Create and register WebServices (remains the same)
	userWs := new(restful.WebService)
	userController.RegisterRoutes(userWs)
	restContainer.Add(userWs)

	loginWs := new(restful.WebService)
	loginWs.Path("/login").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	loginWs.Route(loginWs.POST("").To(auth.LoginRouteHandler).
		Doc("User login").
		Metadata(restfulspec.KeyOpenAPITags, []string{"auth"}).
		Reads(auth.LoginCredentials{}).
		Writes(auth.LoginResponse{}))
	restContainer.Add(loginWs)

	rootWs := new(restful.WebService)
	rootWs.Route(rootWs.GET("/").To(func(r *restful.Request, w *restful.Response) {
		_, _ = w.Write([]byte("User Center Service OK"))
	}))
	rootWs.Route(rootWs.GET("/health").To(func(r *restful.Request, w *restful.Response) {
		// TODO: Add detailed health checks (DB ping, etc.)
		_ = w.WriteHeaderAndJson(http.StatusOK, map[string]string{"status": "UP"}, restful.MIME_JSON)
	}))
	restContainer.Add(rootWs)

	// --- 4. Start Servers & Self-Registration ---
	httpListenAddr := fmt.Sprintf(":%d", config.AppConfig.HTTPPort)
	httpServer := &http.Server{Addr: httpListenAddr, Handler: restContainer}
	sugar.Infof("HTTP server listening on %s", httpListenAddr)

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error, 2)

	// Start gRPC server
	go func() {
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			sugar.Errorf("gRPC server error: %v", err)
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Start HTTP server
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Errorf("HTTP server error: %v", err)
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// **Register this service instance** (after servers start listening)
	// Use localhost or discoverable IP if needed for address
	// For simplicity, using configured ports on localhost
	selfHTTPAddr := fmt.Sprintf("localhost%s", httpListenAddr) // Or discoverable IP
	selfGRPCAddr := fmt.Sprintf("localhost%s", grpcListenAddr) // Or discoverable IP

	// We might register different interfaces/protocols under the same service name
	// or use distinct names. Let's use the configured name + protocol.
	httpServiceName := config.AppConfig.ServiceName + "-http"
	grpcServiceName := config.AppConfig.ServiceName + "-grpc"

	err = serviceRegistry.Register(httpServiceName, selfHTTPAddr)
	if err != nil {
		sugar.Warnf("Failed to register HTTP service '%s': %v", httpServiceName, err)
		// Decide if this is fatal or just a warning
	}
	err = serviceRegistry.Register(grpcServiceName, selfGRPCAddr)
	if err != nil {
		sugar.Warnf("Failed to register gRPC service '%s': %v", grpcServiceName, err)
	}

	// --- 5. Graceful Shutdown (remains the same) ---
	select {
	case sig := <-shutdownChan:
		sugar.Infof("Received signal: %v. Shutting down...", sig)
	case err := <-errChan:
		sugar.Errorf("Server error: %v. Shutting down...", err)
	}

	// **Deregister service** (optional, but good practice)
	sugar.Infof("Deregistering service instances...")
	_ = serviceRegistry.Deregister(httpServiceName) // Ignore error on shutdown
	_ = serviceRegistry.Deregister(grpcServiceName)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	sugar.Info("Shutting down gRPC server...")
	grpcServer.GracefulStop()

	sugar.Info("Shutting down HTTP server...")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		sugar.Errorf("HTTP server shutdown error: %v", err)
	}

	sugar.Info("Servers shut down gracefully.")
}

// LogRequestFilter implementation (now uncommented and used)
func LogRequestFilter(logger *zap.SugaredLogger) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		start := time.Now()
		chain.ProcessFilter(req, resp) // Process the request first
		duration := time.Since(start)
		// Log key details about the request and response
		logger.Infow("Processed HTTP request",
			"method", req.Request.Method,
			"path", req.Request.URL.Path,
			"status", resp.StatusCode(),
			"duration_ms", duration.Milliseconds(),
			"remote_addr", req.Request.RemoteAddr,
			"user_agent", req.HeaderParameter("User-Agent"),
		)
	}
}
