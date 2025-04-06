package repositories

import (
	"mygin/models"

	"gorm.io/gorm"
)

// UserRepository interface defines User-related database operations
type UserRepository interface {
	Create(user *models.User) error
	FindByID(id uint) (*models.User, error)
	FindByUsername(username string) (*models.User, error)
	FindByEmail(email string) (*models.User, error)
	Update(user *models.User) error
	Delete(user *models.User) error
	FindAll(page int, pageSize int) ([]models.User, int64, error)
}

// userRepository implements the UserRepository interface
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new UserRepository instance
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

// Create creates a new User
func (r *userRepository) Create(user *models.User) error {
	result := r.db.Create(user)
	return result.Error
}

// FindByID finds User by ID
func (r *userRepository) FindByID(id uint) (*models.User, error) {
	var user models.User
	result := r.db.First(&user, id)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// FindByUsername finds User by Username
func (r *userRepository) FindByUsername(username string) (*models.User, error) {
	var user models.User
	result := r.db.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// FindByEmail Find User by Email
func (r *userRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	result := r.db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// Update Update User Information
func (r *userRepository) Update(user *models.User) error {
	result := r.db.Save(user)
	return result.Error
}

// Delete deletes User
func (r *userRepository) Delete(user *models.User) error {
	result := r.db.Delete(user)
	return result.Error
}

// FindAll Pagination find all Users
func (r *userRepository) FindAll(page int, pageSize int) ([]models.User, int64, error) {
	offset := (page - 1) * pageSize
	var users []models.User
	var total int64

	if err := r.db.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	result := r.db.Offset(offset).Limit(pageSize).Find(&users)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return users, total, nil
}
