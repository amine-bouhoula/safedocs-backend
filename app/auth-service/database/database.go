package database

import (
	"auth-service/models"
	"log"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
)

func EnableUUIDExtension() {
	if err := database.DB.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`).Error; err != nil {
		log.Fatalf("Failed to enable uuid-ossp extension: %v", err)
	}
}

func MigrateDB() {
	// Run Migrations
	if err := database.DB.AutoMigrate(&models.User{}); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}
}
