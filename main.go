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
	"mygin-restful/interceptors"
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
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
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

// Helper function to get preferred outbound IP (simple version)
func getOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Connect to Google DNS UDP port
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}

func main() {
	// --- 1. Initialization ---
	config.InitConfig()

	// Logger setup
	var logger *zap.Logger
	var err error
	if config.AppConfig.LogLevel == "debug" {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// Setting the JWT Secret (remains the same)
	jwtSecretBytes := []byte{}
	if config.AppConfig.JwtSecret != "" && config.AppConfig.JwtSecret != "default-very-insecure-secret-key" {
		jwtSecretBytes = []byte(config.AppConfig.JwtSecret)
		auth.SetSigningKey(jwtSecretBytes) // Set it globally if needed elsewhere
		sugar.Info("JWT signing key set from config.")
	} else {
		sugar.Warn("Using default insecure JWT secret key!")
		jwtSecretBytes = []byte(config.AppConfig.JwtSecret) // Use the default insecure key
		auth.SetSigningKey(jwtSecretBytes)                  // Still need to set it for the interceptor
	}

	// Database (remains the same)
	db := database.InitDB()
	// Service Registry...
	serviceRegistry, err := registry.NewConsulRegistry(sugar)
	if err != nil {
		sugar.Fatalf("Failed to initialize Consul registry: %v", err)
	}
	// Repositories...
	userRepository := repositories.NewUserRepository(db)
	// Services...
	userService := services.NewUserService(userRepository, sugar.Named("UserService"))
	// Controllers...
	userController := controllers.NewUserController(userService, sugar.Named("UserController"))
	// gRPC Server Handlers...
	grpcUserServer := grpcHandler.NewUserServiceServer(userService)
	grpcAuthServer := grpcHandler.NewAuthServiceServer()
	grpcRegistryServer := grpcHandler.NewRegistryServiceServer(serviceRegistry)
	grpcHealthServer := health.NewServer()

	// --- 2. Setup gRPC Server ---
	grpcListenAddr := fmt.Sprintf(":%d", config.AppConfig.GRPCPort)
	lis, err := net.Listen("tcp", grpcListenAddr)
	if err != nil {
		sugar.Fatalf("Failed to listen for gRPC: %v", err)
	}
	// --- Create gRPC Server with Chained Interceptors ---
	grpcServer := grpc.NewServer(
		// Chain unary interceptors. Order matters: Logging -> Auth
		grpc.ChainUnaryInterceptor(
			// Add logging interceptor first to log all requests
			interceptors.ZapLoggingInterceptor(logger), // Pass the base zap logger

			// Add auth interceptor next
			interceptors.AuthInterceptor(jwtSecretBytes),

			// Add other interceptors like metrics, tracing, recovery later
		),
		// Optionally chain stream interceptors if needed
		// grpc.ChainStreamInterceptor(
		//    interceptors.ZapStreamLoggingInterceptor(logger),
		//    // Add stream auth interceptor if needed
		// ),
	)

	// Register gRPC services (remains the same)
	userpb.RegisterUserServiceServer(grpcServer, grpcUserServer)
	authpb.RegisterAuthServiceServer(grpcServer, grpcAuthServer)
	registrypb.RegisterRegistryServiceServer(grpcServer, grpcRegistryServer) // Still useful for manual/external registration via API
	grpc_health_v1.RegisterHealthServer(grpcServer, grpcHealthServer)        // Register health server
	reflection.Register(grpcServer)
	sugar.Infof("gRPC server listening on %s", grpcListenAddr)

	// --- 3. Setup RESTful (go-restful) Server ---
	restContainer := restful.NewContainer()
	restContainer.EnableContentEncoding(true)
	restContainer.Filter(LogRequestFilter(sugar.Named("REST")))

	// Create and register WebServices (remains the same)
	userWs := new(restful.WebService)
	userController.RegisterRoutes(userWs)
	restContainer.Add(userWs)

	loginWs := new(restful.WebService)
	loginWs.Path("/login").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	loginWs.Route(loginWs.POST("").To(auth.LoginRouteHandler).
		Doc("User login").
		Metadata(restfulspec.KeyOpenAPITags, []string{"auth"}).
		Reads(auth.LoginCredentials{}). // Define this struct if not already done
		Writes(auth.LoginResponse{}))   // Define this struct if not already done
	restContainer.Add(loginWs)

	rootWs := new(restful.WebService)
	rootWs.Route(rootWs.GET("/").To(func(r *restful.Request, w *restful.Response) {
		_, _ = w.Write([]byte("User Center Service OK"))
	}))
	// This /health endpoint is now crucial for Consul HTTP checks
	rootWs.Route(rootWs.GET("/health").To(func(r *restful.Request, w *restful.Response) {
		// TODO: Add detailed health checks (DB ping, etc.)
		// For now, just return 200 OK if the server is running
		_ = w.WriteHeaderAndJson(http.StatusOK, map[string]string{"status": "UP"}, restful.MIME_JSON)
	}))
	restContainer.Add(rootWs)

	// --- 4. Start Servers & Self-Registration with Consul ---
	httpListenAddr := fmt.Sprintf(":%d", config.AppConfig.HTTPPort)
	httpServer := &http.Server{Addr: httpListenAddr, Handler: restContainer}
	sugar.Infof("HTTP server listening on %s", httpListenAddr)

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error, 2)

	go func() {
		grpcHealthServer.SetServingStatus(userpb.UserService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
		grpcHealthServer.SetServingStatus(authpb.AuthService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			sugar.Errorf("gRPC server error: %v", err)
			errChan <- fmt.Errorf("gRPC server error: %w", err)
			grpcHealthServer.Shutdown()
		}
	}()

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Errorf("HTTP server error: %v", err)
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	serviceHost, err := getOutboundIP()
	if err != nil {
		sugar.Warnf("Could not determine outbound IP, using 127.0.0.1 for registration: %v", err)
		serviceHost = "127.0.0.1"
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = fmt.Sprintf("unknown-%d", time.Now().UnixNano())
	}
	baseID := fmt.Sprintf("%s-%s", config.AppConfig.ServiceName, hostname)
	httpServiceID := fmt.Sprintf("%s-http-%d", baseID, config.AppConfig.HTTPPort)
	grpcServiceID := fmt.Sprintf("%s-grpc-%d", baseID, config.AppConfig.GRPCPort)
	httpCheck := registry.CreateHTTPCheck(httpServiceID, serviceHost, config.AppConfig.HTTPPort, "/health", "10s", "1s") // Consider adjusting timings later
	httpTags := []string{"http", "rest", "v1"}
	err = serviceRegistry.Register(httpServiceID, config.AppConfig.ServiceName+"-http", serviceHost, config.AppConfig.HTTPPort, httpTags, httpCheck)
	if err != nil {
		sugar.Errorf("Failed to register HTTP service with Consul: %v", err)
	}
	grpcTarget := fmt.Sprintf("%s:%d", serviceHost, config.AppConfig.GRPCPort)
	grpcCheck := registry.CreateGRPCSCheck(grpcServiceID, grpcTarget, "10s", "1s", false) // Consider adjusting timings later
	grpcTags := []string{"grpc", "v1"}
	err = serviceRegistry.Register(grpcServiceID, config.AppConfig.ServiceName+"-grpc", serviceHost, config.AppConfig.GRPCPort, grpcTags, grpcCheck)
	if err != nil {
		sugar.Errorf("Failed to register gRPC service with Consul: %v", err)
	}

	// --- 5. Graceful Shutdown ---
	select {
	case sig := <-shutdownChan:
		sugar.Infof("Received signal: %v. Shutting down...", sig)
	case err := <-errChan:
		sugar.Errorf("Server error: %v. Shutting down...", err)
	}

	// **Deregister service from Consul**
	sugar.Info("Deregistering service instances from Consul...")
	if err := serviceRegistry.Deregister(httpServiceID); err != nil {
		sugar.Warnf("Failed to deregister HTTP service '%s': %v", httpServiceID, err)
	}
	if err := serviceRegistry.Deregister(grpcServiceID); err != nil {
		sugar.Warnf("Failed to deregister gRPC service '%s': %v", grpcServiceID, err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	sugar.Info("Shutting down gRPC server...")
	grpcHealthServer.Shutdown() // Shutdown health server first
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
