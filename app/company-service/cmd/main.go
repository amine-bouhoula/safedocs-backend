package main

import (
	handlers "company-service/internal/api"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"

	compaynservices "company-service/internal/services"

	"fmt"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {

	utils.InitLogger("production")

	utils.Logger.Info("Starting company-service")

	// Step 1: Load configuration
	cfg, _ := config.LoadConfig()

	// Connect to PostgreSQL
	if err := database.ConnectDB(cfg.DatabaseURL); err != nil {
		utils.Logger.Fatal("Failed to connect to the databse", zap.Error(err))
	}
	utils.Logger.Info("Connected to the database")

	// Connect to Redis
	database.ConnectRedis(cfg.RedisURL)
	utils.Logger.Info("Connected to Redis")

	// Initialize Gin router
	router := gin.Default()

	fmt.Print("PUBLIC KEY PATH = ", cfg.PublicKeyPath)

	utils.Logger.Info("Loading RSA public key", zap.String("public_key_path", cfg.PublicKeyPath))
	publicKey, err := services.LoadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		utils.Logger.Fatal("Error loading RSA public key", zap.Error(err))
	}
	utils.Logger.Info("RSA public key loaded successfully")

	utils.Logger.Info("Applying authentication middleware")
	router.Use(compaynservices.AuthMiddleware(publicKey, utils.Logger))

	// Company Endpoints
	router.POST("/api/v1/companies", handlers.CreateCompany())
	router.GET("/api/v1/companies/:company_id", handlers.GetCompanyByID())

	router.POST("/api/v1/companies/:company_id/users", handlers.AddUserToCompany())

	// Start the server
	if err := router.Run(":8002"); err != nil {
		utils.Logger.Fatal("Server failed to start:", zap.Error(err))
	}

}
