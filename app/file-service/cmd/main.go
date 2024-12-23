package main

import (
	"file-service/internal/api"
	"file-service/internal/models"
	"fmt"
	"log"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"

	"go.uber.org/zap"
)

func main() {
	// Step 1: Load configuration
	cfg, _ := config.LoadConfig()

	fmt.Println(cfg.LogLevel)

	// Step 2: Initialize zap logger
	utils.InitLogger(cfg.LogLevel)

	// Step 3: Initialize database connection
	err := database.ConnectDB(cfg.DatabaseURL)
	if err != nil {
		utils.Logger.Fatal("Failed to connect to the Postgres database", zap.Error(err))
	}

	if err := database.DB.AutoMigrate(&models.FileMetadata{}); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	// Step 4: Start the API server
	utils.Logger.Info("Starting API server...", zap.String("port", cfg.ServerPort))
	api.StartServer(cfg, utils.Logger)
}
