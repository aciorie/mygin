package main

import (
	"fmt"
	"mygin/auth"
	"mygin/config"
	"mygin/controllers"
	"mygin/database"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Define a general error structure
type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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
			err := c.Errors.Last() // Get the last error

			// Handle errors differently depending on their type
			if appErr, ok := err.Err.(*AppError); ok {
				// If it's a customed AppError
				c.AbortWithStatusJSON(appErr.Code, appErr)
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, AppError{
					Code:    http.StatusInternalServerError,
					Message: "Internal Server Error",
				})
				// More detailed error logs are recorded here, such as err.Error()
				fmt.Println("Unhandled Error: ", err.Error())
			}
		}
	}
}

// Define a login requirement structure
type Login struct {
	User     string `json:"user" binding:"required"`
	Password string `json:"password" binding:"required"`
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
			zap.String("path", ctx.Request.URL.Path))
	}
}

// func main() {
// 	// Initialize configs
// 	config.InitConfig()

// 	var logger *zap.Logger
// 	switch config.AppConfig.LogLevel {
// 	case "debug":
// 		logger, _ = zap.NewDevelopment()
// 	case "info":
// 		logger, _ = zap.NewProduction()
// 	default:
// 		logger, _ = zap.NewProduction()
// 	}
// 	defer logger.Sync() // Make sure the buffer is flushed before the program exits

// 	database.InitDB()

// 	r := gin.New()
// 	// r.Use() → global middleware
// 	r.Use(MyLogger(logger))
// 	r.Use(ErrorHandler())

// 	// Register user related routes
// 	r.POST("/users", controllers.CreateUser)

// 	r.GET("/hello", func(c *gin.Context) {
// 		c.String(http.StatusOK, "Hello Gin!")
// 	})
// 	r.GET("/user/:name", func(c *gin.Context) {
// 		name := c.Param("name")
// 		c.String(http.StatusOK, "Hello %s", name)
// 	})
// 	r.GET("/user/:name/*action", func(c *gin.Context) {
// 		name := c.Param("name")
// 		action := c.Param("action")
// 		message := name + " is " + action
// 		c.String(http.StatusOK, message)
// 	})
// 	r.GET("/welcome", func(c *gin.Context) {
// 		firstname := c.DefaultQuery("firstname", "Guest") // 获取查询参数，如果没有则使用默认值
// 		lastname := c.Query("lastname")                   // 获取查询参数
// 		c.String(http.StatusOK, "Hello %s %s", firstname, lastname)
// 	})
// 	r.GET("/panic", func(c *gin.Context) {
// 		//模拟panic
// 		panic("Something went wrong!")
// 	})
// 	r.POST("/form", func(c *gin.Context) {
// 		message := c.PostForm("message")               // 获取表单数据
// 		nick := c.DefaultPostForm("nick", "anonymous") // 获取表单数据，如果没有则使用默认值

// 		c.JSON(http.StatusOK, gin.H{
// 			"status":  "posted",
// 			"message": message,
// 			"nick":    nick,
// 		})
// 	})
// 	r.POST("/login", func(c *gin.Context) {
// 		var login Login
// 		if err := c.ShouldBindJSON(&login); err != nil {
// 			// Use c.Error() to attach error information instead of returning directly
// 			c.Error(&AppError{Code: http.StatusBadRequest, Message: "Invalid request body"})
// 			logger.Error("login error",
// 				zap.String("client_ip", c.ClientIP()),
// 				zap.String("err", err.Error()))
// 			return
// 		}

// 		if login.User == "user" && login.Password == "password" {
// 			c.JSON(http.StatusOK, gin.H{"status": "you are logged in"})
// 		} else {
// 			c.Error(&AppError{Code: http.StatusUnauthorized, Message: "Invalid username or password"})
// 		}
// 	})

//		// Use the port number in the configuration
//		addr := fmt.Sprintf(":%d", config.AppConfig.Port)
//		r.Run(addr)
//	}
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

	database.InitDB()

	r := gin.New() // Use gin.New() to avoid default middlewares interfering
	r.Use(MyLogger(logger))

	// Initialize JWT middleware.
	authMiddleware := auth.AuthMiddleware() // No error check needed as currently implemented

	// Register user related routes
	r.POST("/users", controllers.CreateUser)
	r.POST("/login", auth.LoginHandler) // Use the LoginHandler

	// Create a group for protected routes.
	protected := r.Group("/api")
	protected.Use(authMiddleware) // Apply the JWT middleware to the group.
	{
		protected.GET("/profile", func(c *gin.Context) {
			// Access user information set by the middleware.
			userID := c.GetUint("user_id")
			username := c.GetString("username")

			c.JSON(http.StatusOK, gin.H{
				"user_id":  userID,
				"username": username,
				"message":  "This is a protected route!",
			})
		})
	}

	// Unprotected routes (for demonstration purposes)
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

	r.Use(ErrorHandler()) // Custom error handler *after* other middleware.
	// Use the port number in the configuration
	addr := fmt.Sprintf(":%d", config.AppConfig.Port)
	if err := r.Run(addr); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
