package controllers

import (
	"fmt"
	"mygin/database"
	"mygin/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *AppError) Error() string {
	return fmt.Sprintf("Code: %d, Message: %s", e.Code, e.Message)
}

func CreateUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	// Explicitly verify that the password is empty
	if user.Password == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "Password cannot be empty"})
		return
	}

	// Check if the username already exists
	var existingUser models.User
	result := database.DB.Where("username = ?", user.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"message": "Username already exists"})
		return
	}

	// Encode password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Could not hash password"})
		return
	}
	user.Password = string(hashedPassword)

	// Create users
	result = database.DB.Create(&user)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"message": "Internal Server Error: " + result.Error.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}
