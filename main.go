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
	"strings"
	"syscall"
	"time"

	restfulspec "github.com/emicklei/go-restful-openapi/v2"
	restful "github.com/emicklei/go-restful/v3"
	"github.com/gin-gonic/gin"
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

// Custom error handling middleware
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next() // Execute subsequent processing functions first

		// Handle errors if happened
		if len(c.Errors) > 0 {
			// Check if response was already written
			if c.Writer.Written() {
				return
			}

			err := c.Errors.Last()                               // Get the last error
			fmt.Printf("Error caught by handler: %v\n", err.Err) // Basic logging

			// Send appropriate JSON response (examples)
			if strings.Contains(err.Error(), "Forbidden") { // Simple check
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			} else if strings.Contains(err.Error(), "Unauthorized") {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			} else if strings.Contains(err.Error(), "Not found") {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"message": "Resource not found"})
			} else if strings.Contains(err.Error(), "Invalid request") || strings.Contains(err.Error(), "binding") {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Bad Request: " + err.Err.Error()}) // Include specific binding error
			} else {
				// Default internal server error
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Internal Server Error"})
			}
		}
	}
}

// Custom Logger Middleware
func MyLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		startTime := time.Now()

		// handle requests
		ctx.Next()

		// Log after request processing is completed
		endTime := time.Now()
		latency := endTime.Sub(startTime)

		logger.Info("Request",
			zap.String("client_ip", ctx.ClientIP()),
			zap.String("method", ctx.Request.Method),
			zap.Int("status_code", ctx.Writer.Status()),
			zap.Duration("latency", latency),
			zap.String("user_agent", ctx.Request.UserAgent()),
			zap.String("path", ctx.Request.URL.Path),
			zap.String("errors", ctx.Errors.ByType(gin.ErrorTypePrivate).String()), // Log internal errors
		)
	}
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
	defer logger.Sync() // Flushes buffer, if any
	sugar := logger.Sugar()

	// Setting the JWT Secret
	if config.AppConfig.JwtSecret != "" && config.AppConfig.JwtSecret != "default-very-insecure-secret-key" {
		auth.SetSigningKey([]byte(config.AppConfig.JwtSecret))
		sugar.Info("JWT signing key set from config.")
	} else {
		sugar.Warn("Using default insecure JWT secret key!")
		// You can still use the default mySigningKey
	}

	// Database
	db := database.InitDB() // Assumes InitDB handles seeding etc.

	// Service Registry (simple in-memory)
	serviceRegistry := registry.NewInMemoryRegistry()

	// Repositories & Services
	userRepository := repositories.NewUserRepository(db)
	userService := services.NewUserService(userRepository)
	// Inject dependencies properly (e.g., registry if needed by services)

	// Controllers (for REST API)
	userController := controllers.NewUserController(userService)

	// gRPC Server Handlers
	grpcUserServer := grpcHandler.NewUserServiceServer(userService)
	grpcAuthServer := grpcHandler.NewAuthServiceServer() // Needs DB access for login, consider injecting
	grpcRegistryServer := grpcHandler.NewRegistryServiceServer(serviceRegistry)

	// --- 2. Setup gRPC Server ---
	grpcListenAddr := fmt.Sprintf(":%d", config.AppConfig.GRPCPort)
	lis, err := net.Listen("tcp", grpcListenAddr)
	if err != nil {
		sugar.Fatalf("Failed to listen for gRPC: %v", err)
	}
	grpcServer := grpc.NewServer(
	// Add interceptors here if needed (logging, auth, etc.)
	// grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
	//     // Example: grpc_zap.UnaryServerInterceptor(logger),
	//     //          grpc_auth.UnaryServerInterceptor(yourAuthFunc),
	// )),
	)

	// Register gRPC services
	userpb.RegisterUserServiceServer(grpcServer, grpcUserServer)
	authpb.RegisterAuthServiceServer(grpcServer, grpcAuthServer)
	registrypb.RegisterRegistryServiceServer(grpcServer, grpcRegistryServer)

	// Enable gRPC reflection (useful for tools like grpcurl)
	reflection.Register(grpcServer)
	sugar.Infof("gRPC server listening on %s", grpcListenAddr)

	// --- 3. Setup RESTful (go-restful) Server ---
	restContainer := restful.NewContainer()
	restContainer.EnableContentEncoding(true)
	// Add CORS filter if needed:
	// cors := restful.CrossOriginResourceSharing{ ... }
	// restContainer.Filter(cors.Filter)

	// Add global filters? (e.g., logging)
	// restContainer.Filter(LogRequestFilter(sugar)) // Example custom filter

	// Create and register WebServices
	userWs := new(restful.WebService)
	userController.RegisterRoutes(userWs) // Registers /users routes
	restContainer.Add(userWs)

	// Add login route (doesn't need AuthFilter applied within RegisterRoutes)
	loginWs := new(restful.WebService)
	loginWs.Path("/login").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	loginWs.Route(loginWs.POST("").To(auth.LoginRouteHandler).
		Doc("User login").
		Metadata(restfulspec.KeyOpenAPITags, []string{"auth"}). // Use restfulspec from controller's import
		Reads(auth.LoginCredentials{}).                         // Document input
		Writes(auth.LoginResponse{}))                           // Document output
	restContainer.Add(loginWs)

	// Add root/health check if needed
	rootWs := new(restful.WebService)
	rootWs.Route(rootWs.GET("/").To(func(r *restful.Request, w *restful.Response) {
		_, _ = w.Write([]byte("User Center Service OK"))
	}))
	rootWs.Route(rootWs.GET("/health").To(func(r *restful.Request, w *restful.Response) {
		// Add more detailed health checks (DB connection, etc.)
		_ = w.WriteHeaderAndJson(http.StatusOK, map[string]string{"status": "UP"}, restful.MIME_JSON)
	}))
	restContainer.Add(rootWs)

	// --- 4. Start Servers ---
	httpListenAddr := fmt.Sprintf(":%d", config.AppConfig.HTTPPort)
	httpServer := &http.Server{Addr: httpListenAddr, Handler: restContainer}
	sugar.Infof("HTTP server listening on %s", httpListenAddr)

	// Channel to listen for OS signals
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	// Channel for server errors
	errChan := make(chan error, 2) // Buffer for potential errors from both servers

	// Start gRPC server in a goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			sugar.Errorf("gRPC server error: %v", err)
			errChan <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	// Start HTTP server in a goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Errorf("HTTP server error: %v", err)
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// --- 5. Graceful Shutdown ---
	select {
	case sig := <-shutdownChan:
		sugar.Infof("Received signal: %v. Shutting down...", sig)
	case err := <-errChan:
		sugar.Errorf("Server error: %v. Shutting down...", err)
	}

	// Create a context with timeout for shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Shutdown gRPC server
	sugar.Info("Shutting down gRPC server...")
	grpcServer.GracefulStop() // Doesn't take context

	// Shutdown HTTP server
	sugar.Info("Shutting down HTTP server...")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		sugar.Errorf("HTTP server shutdown error: %v", err)
	}

	sugar.Info("Servers shut down gracefully.")
}

// Example request logging filter for go-restful
func LogRequestFilter(logger *zap.SugaredLogger) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		start := time.Now()
		chain.ProcessFilter(req, resp) // Process the request first
		duration := time.Since(start)
		logger.Infow("Processed request",
			"method", req.Request.Method,
			"path", req.Request.URL.Path,
			"status", resp.StatusCode(),
			"duration_ms", duration.Milliseconds(),
			"remote_addr", req.Request.RemoteAddr,
			"user_agent", req.HeaderParameter("User-Agent"),
		)
	}
}
