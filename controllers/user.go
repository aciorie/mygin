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
		c.Error(&AppError{Code: http.StatusBadRequest, Message: "Invalid request body"})
		return
	}

	// Check if the username already exists
	var existingUser models.User
	result := database.DB.Where("username = ?", user.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		c.Error(&AppError{Code: http.StatusConflict, Message: "Username already exists"})
		return
	}

	// Encode password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Error(&AppError{http.StatusInternalServerError, "Could not hash password"})
		return
	}
	user.Password = string(hashedPassword)

	// Create users
	result = database.DB.Create(&user)
	if result.Error != nil {
		c.Error(result.Error) // Append gorm errors directly to c.Errors
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}
