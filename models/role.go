package models

import "gorm.io/gorm"

type Role struct {
	gorm.Model
	Name        string `gorm:"unique;not null"`
	Description string
	Permissions []Permission `gorm:"many2many:role_permissions;"` // Many-to-Many relationship with Permission
	Users       []User       `gorm:"many2many:user_roles;"`       // Many-to-Many relationship back to User (optional, but good practice)
}
