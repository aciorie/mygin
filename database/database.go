package database

import (
	"fmt"
	"mygin/config"
	"mygin/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	databaseSignal := config.AppConfig.DatabaseURL
	db, err := gorm.Open(mysql.Open(databaseSignal), &gorm.Config{})
	if err != nil {
		panic(fmt.Errorf("Failed to connect database: %s", err))
	}

	db.AutoMigrate(&models.User{})
	DB = db
}
