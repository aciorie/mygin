package models

import "gorm.io/gorm"

// Permission represents an action that can be performed (e.g., "user:create", "user:list", "user:update:self", "user:update:all")
type Permission struct {
	gorm.Model
	Name        string `gorm:"unique;not null"` // e.g., "users:list", "users:delete"
	Description string
	Roles       []Role `gorm:"many2many:role_permissions;"` // Many-to-Many relationship back to Role
}
