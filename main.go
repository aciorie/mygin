package main

import (
	"fmt"
	"mygin/auth"
	"mygin/config"
	"mygin/controllers"
	"mygin/database"
	"mygin/services"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
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

// @title MyGin API
// @version 1.0
// @description This is a sample API built with Gin.

// @host localhost:8080
// @BasePath /

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
	// Initialize configs
	config.InitConfig()

	var logger *zap.Logger
	switch config.AppConfig.LogLevel {
	case "debug":
		logger, _ = zap.NewDevelopment()
	case "info":
		logger, _ = zap.NewProduction()
	default:
		logger, _ = zap.NewProduction()
	}
	defer logger.Sync() // Make sure the buffer is flushed before the program exits

	db := database.InitDB()
	userService := services.NewUserService(db)
	userController := controllers.NewUserController(userService)

	r := gin.New() // Use gin.New() to avoid default middlewares interfering
	r.Use(MyLogger(logger))
	r.Use(gin.Recovery()) // Default recovery middleware AFTER logger

	// --- Public Routes ---
	r.POST("/register", userController.CreateUser) // Changed from /users for clarity

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, World!")
	})
	// Register user related routes
	// r.POST("/users", userController.CreateUser)
	r.POST("/login", auth.LoginHandler) // Use the LoginHandler

	r.GET("/hello", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello Gin!")
	})
	r.GET("/user/:name", func(c *gin.Context) {
		name := c.Param("name")
		c.String(http.StatusOK, "Hello %s", name)
	})
	r.GET("/user/:name/*action", func(c *gin.Context) {
		name := c.Param("name")
		action := c.Param("action")
		message := name + " is " + action
		c.String(http.StatusOK, message)
	})
	r.GET("/welcome", func(c *gin.Context) {
		firstname := c.DefaultQuery("firstname", "Guest") // Get query parameters, use default if not present
		lastname := c.Query("lastname")                   // Get query parameters
		c.String(http.StatusOK, "Hello %s %s", firstname, lastname)
	})
	r.GET("/panic", func(c *gin.Context) {
		// Simulate panic
		panic("Something went wrong!")
	})
	r.POST("/form", func(c *gin.Context) {
		message := c.PostForm("message")               // Get form data
		nick := c.DefaultPostForm("nick", "anonymous") // Get form data, use default if not present

		c.JSON(http.StatusOK, gin.H{
			"status":  "posted",
			"message": message,
			"nick":    nick,
		})
	})

	userRoutes := r.Group("/users")
	userRoutes.Use(auth.AuthMiddleware()) // Apply authentication middleware to routes under /users
	{
		userRoutes.GET("/:id", userController.GetUserByID)
		userRoutes.PUT("/:id", userController.UpdateUser)
		userRoutes.GET("", userController.ListUsers)   // GET /users
		r.POST("/register", userController.CreateUser) // Add register route
		// If there is DeleteUser, also add userRoutes.DELETE("/:id", DeleteUser) here
	}

	r.Use(ErrorHandler()) // Custom error handler *after* other middleware.

	// Use the port number in the configuration
	addr := fmt.Sprintf(":%d", config.AppConfig.Port)
	if err := r.Run(addr); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
