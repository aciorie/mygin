package repositories

import "mygin/models"

// UserRepository interface defines User-related database operations
type UserRepository interface{
	Create(user *models.User)	error
	
}