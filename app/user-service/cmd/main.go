package main

import (
	"log"
	"time"

	"user-service/handlers"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"
	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize Logger and Database
	utils.InitLogger("production")
	defer utils.Logger.Sync()

	cfg, _ := config.LoadConfig()

	database.ConnectDB(cfg.DatabaseURL)

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		//AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		ExposeHeaders:    []string{"Content-Length", "Authorization"},
		MaxAge:           12 * time.Hour, // Caching preflight requests
	}))

	// Register Routes
	router.POST("/api/v1/users", handlers.CreateUserHandler())
	router.GET("/api/v1/user/info", handlers.GetUserHandler())
	router.POST("/api/v1/users/check", handlers.GetUserHandlerByEmail())

	// Start the Server
	if err := router.Run(":8003"); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
