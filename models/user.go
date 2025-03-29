package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Username string `gorm:"unique;not null"`
	Password string `gorm:"not null" json:"-"` // Don't expose password hash
	Email    string `gorm:"unique"`
	Nickname string
	Roles    []Role `gorm:"many2many:user_roles;"` // Many-to-Many relationship with Role
}
