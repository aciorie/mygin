package database

import (
	"fmt"
	"log"
	"mygin/config"
	"mygin/models"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB() {
	databaseSignal := config.AppConfig.DatabaseURL

	// GORM logger configuration
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logger.Info, // Log level (Silent, Error, Warn, Info)
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false,       // Don't include params in the SQL log
			Colorful:                  true,        // Enable color
		},
	)

	db, err := gorm.Open(mysql.Open(databaseSignal), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		panic(fmt.Errorf("Failed to connect database: %s", err))
	}

	// AutoMigrate models including the new ones and join tables
	err = db.AutoMigrate(&models.User{}, &models.Role{}, &models.Permission{})
	if err != nil {
		panic(fmt.Errorf("failed to migrate database: %w", err))
	}

	DB = db
	fmt.Println("Database connection successful and migrations complete.")

	// Seed initial roles and permissions if they don't exist
	SeedInitialData(DB) // Call the seeding function
}

// SeedInitialData seeds the database with initial roles and permissions
func SeedInitialData(DB *gorm.DB) {
	// --- Permissions ---
	permissions := []models.Permission{
		{Name: "users:list", Description: "Ability to list users"},
		{Name: "users:read:self", Description: "Ability to read own user profile"},
		{Name: "users:read:all", Description: "Ability to read any user profile"},
		{Name: "users:update:self", Description: "Ability to update own user profile"},
		{Name: "users:update:all", Description: "Ability to update any user profile"},
		{Name: "users:delete:self", Description: "Ability to delete own user account"},
		{Name: "users:delete:all", Description: "Ability to delete any user account"},
		{Name: "roles:manage", Description: "Ability to manage roles and permissions"},
	}

	for _, p := range permissions {
		var existingPermissiong models.Permission
		if err := DB.Where("name = ?", p.Name).First(&existingPermissiong).Error; err == gorm.ErrRecordNotFound {
			if err := DB.Create(&p).Error; err != nil {
				log.Printf("Failed to seed permission %s: %v\n", p.Name, err)
			} else {
				log.Printf("Seeded permission: %s\n", p.Name)
			}
		}
	}

	// --- Roles ---
	roles := []struct {
		Role        models.Role
		Permissions []string
	}{
		{
			Role:        models.Role{Name: "admin", Description: "Administrator with full access"},
			Permissions: []string{"users:list", "users:read:all", "users:update:all", "users:delete:all", "roles:manage"}, // Admin gets most permissions
		},
		{Role: models.Role{Name: "user", Description: "Standard user"},
			Permissions: []string{"users:read:self", "users:update:self", "users:delete:self"}, // Basic user permissions
		},
	}

	for _, rData := range roles {
		var existingRole models.Role
		if err := DB.Where("name = ?", rData.Role.Name).First(&existingRole).Error; err == gorm.ErrRecordNotFound {
			// Role does not exist, create it
			if err := DB.Create(&rData.Role).Error; err != nil {
				log.Printf("Failed to seed role %s: %v\n", rData.Role.Name, err)
				continue // Skip associating permissions if role creation failed
			}

			log.Printf("Seeded role: %s\n", rData.Role.Name)
			existingRole = rData.Role // Use the newly created role for permission association
		} else if err != nil {
			log.Printf("Error checking for role %s: %v\n", rData.Role.Name, err)
			continue
		}

		// Associate permissions with the role (whether newly created or existing)
		var permissionsToAssociate []models.Permission
		if err := DB.Where("name IN ?", rData.Permissions).Find(&permissionsToAssociate).Error; err != nil {
			log.Printf("Failed to find permissions for role %s: %v\n", existingRole.Name, err)
			continue
		}

		if len(permissionsToAssociate) > 0 {
			// ReplaceAssociations clears existing and adds new ones. Use Append to just add
			if err := DB.Model(&existingRole).Association("Permissions").Replace(permissionsToAssociate); err != nil {
				log.Printf("Failed to associate permissions with role %s: %v\n", existingRole.Name, err)
			} else {
				log.Printf("Associated %d permissions with role %s\n", len(permissionsToAssociate), existingRole.Name)
			}
		}
	}

	// Create an initial admin user if none exists
	var adminUser models.User
	if err := DB.Where("username = ?", "admin").First(&adminUser).Error; err == gorm.ErrRecordNotFound {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("adminpassword"), bcrypt.DefaultCost)
		adminUser = models.User{
			Username: "admin",
			Password: string(hashedPassword),
			Email:    "admin@example.com",
		}
		if err := DB.Create(&adminUser).Error; err != nil {
			log.Printf("Failed to create initial admin user: %v\n", err)
		} else {
			// Assign admin role to the new admin user
			var adminRole models.Role
			if err := DB.Where("name = ?", "admin").First(&adminRole).Error; err == nil {
				DB.Model(&adminUser).Association("Roles").Append(&adminRole)
				log.Println("Created initial admin user and assigned admin role.")
			} else {
				log.Println("Created initial admin user, but failed to find admin role to assign.")
			}
		}
	}
}
