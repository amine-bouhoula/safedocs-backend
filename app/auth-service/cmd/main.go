package main

import (
	"auth-service/handlers"

	authdatabase "auth-service/database"

	"github.com/gin-contrib/cors"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"

	"log"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {

	utils.InitLogger("production")

	utils.Logger.Info("Starting auth-service")

	// Step 1: Load configuration
	cfg, _ := config.LoadConfig()

	utils.Logger.Info("Trying to connect to", zap.String("DB Url", cfg.DatabaseURL))

	// Connect to PostgreSQL
	if err := database.ConnectDB(cfg.DatabaseURL); err != nil {
		utils.Logger.Fatal("Failed to connect to the databse", zap.Error(err))
	}
	utils.Logger.Info("Connected to the database")

	authdatabase.EnableUUIDExtension()
	authdatabase.MigrateDB()

	// Connect to Redis
	database.ConnectRedis(cfg.RedisURL)
	utils.Logger.Info("Connected to Redis")

	// Create a new Gin router
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:3039"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Register routes
	router.POST("/api/v1/auth/register", handlers.RegisterHandler())
	router.POST("/api/v1/auth/login", handlers.LoginHandler())
	router.POST("/api/v1/auth/refresh", handlers.RefreshTokenHandler("accessTokenSecret", "refreshTokenSecret"))
	router.POST("/api/v1/auth/logout", handlers.LogoutHandler())
	router.GET("/api/v1/users/:user_id", handlers.GetUserHandler())
	router.GET("/api/v1/usersbyemail/:user_email", handlers.GetUserByEmailHandler())

	// Start the server
	if err := router.Run(":8000"); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
