package api

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"user-service/models"
	userservices "user-service/services"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	database "github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	utils "github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"
	"github.com/gin-contrib/cors"
	"github.com/minio/minio-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type StorageService struct {
	client *minio.Client
	logger *zap.Logger
	bucket string
}

func StartServer(cfg *config.Config, log *zap.Logger) {
	// Ensure logger is not nil
	if log == nil {
		panic("Logger is required but not provided")
	}

	// Validate configuration
	log.Info("Validating server configuration")
	if cfg.ServerPort == "" {
		log.Fatal("Server port must be specified in configuration")
	}
	log.Info("Server configuration validated", zap.String("server_port", cfg.ServerPort))

	// Initialize Gin router
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		//AllowOrigins:     []string{"http://localhost:3039"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		ExposeHeaders:    []string{"Content-Length", "Authorization"},
		MaxAge:           12 * time.Hour, // Caching preflight requests
	}))

	// Initialize services with proper error handling
	log.Info("Initializing storage service")
	storageService, err := userservices.ConnectMinio(cfg.MinIOURL, cfg.MinIOUser, cfg.MinIOPass, log)
	if err != nil {
		log.Fatal("Failed to initialize storage service", zap.Error(err))
	}
	log.Info("Storage service initialized successfully")

	// Load the RSA public key
	log.Info("Loading RSA public key", zap.String("public_key_path", cfg.PublicKeyPath))
	publicKey, err := services.LoadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		//log.Fatal("Error loading RSA public key", zap.Error(err))
	}
	log.Info("RSA public key loaded successfully")

	// Apply middleware
	log.Info("Applying authentication middleware")
	router.Use(userservices.AuthMiddleware(publicKey, log))

	// Define /metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Define routes
	log.Info("Defining routes")
	router.POST("/api/v1/user/uploadprofilepicture", func(c *gin.Context) {
		log.Info("Handling /uploadprofilepicture request", zap.String("method", c.Request.Method))
		UploadUserProfilePicture(c, storageService, log)
	})

	router.GET("/api/v1/user/info", func(c *gin.Context) {
		log.Info("Handling /info get request", zap.String("method", c.Request.Method))
		GetUserHandler(c, log)
	})

	router.PUT("/api/v1/user/info", func(c *gin.Context) {
		log.Info("Handling /info post request", zap.String("method", c.Request.Method))
		UpdateUserInfo(c, log)
	})

	router.GET("/api/v1/user/stats", func(c *gin.Context) {
		log.Info("Handling /stats get request", zap.String("method", c.Request.Method))
		GetUserStatistics(c, log)
	})

	router.GET("/api/v1/users", func(c *gin.Context) {
		log.Info("Handling /users get request", zap.String("method", c.Request.Method))
		GetAllUsersInCompany(c, log)
	})

	// Start the server
	port := cfg.ServerPort
	log.Info("Starting server", zap.String("port", port))
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server", zap.Error(err))
	}
}

// CreateUserHandler - Registers a new user
func CreateUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User

		// Parse the incoming request
		if err := c.ShouldBindJSON(&user); err != nil {
			utils.Logger.Error("Invalid request payload", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Save to the database
		if err := database.DB.Create(&user).Error; err != nil {
			utils.Logger.Error("Failed to create user", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		utils.Logger.Info("User created successfully", zap.String("user_id", user.ID))
		c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "user_id": user.ID})
	}
}

// GetUserHandler - Retrieves a user by ID
func GetUserHandler(c *gin.Context, log *zap.Logger) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		utils.Logger.Error("User not found", zap.String("user_id", userIDStr), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Log the request headers and body
	log.Info("Received upload request",
		zap.String("user id", userIDStr),
		zap.String("method", c.Request.Method),
		zap.String("url", c.Request.RequestURI),
		zap.String("clientIP", c.ClientIP()),
		zap.String("headers", fmt.Sprintf("%v", c.Request.Header)),
	)

	c.JSON(http.StatusOK, gin.H{
		"Email":             user.Email,
		"FirstName":         user.Firstname,
		"LastName":          user.Lastname,
		"Company":           user.Company,
		"Position":          user.Position,
		"ProfilePictureUrl": user.ProfilePictureUrl,
	})
}

func GetUserHandlerByEmail() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Define payload structure
		type EmailRequest struct {
			Email string `json:"email" binding:"required,email"`
		}

		var req EmailRequest

		// Bind JSON payload
		if err := c.ShouldBindJSON(&req); err != nil {
			utils.Logger.Error("Invalid request payload", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error":  "Invalid email format",
				"exists": false,
			})
			return
		}

		// Search for the user by email
		var user models.User
		err := database.DB.Where("email = ?", req.Email).First(&user).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				utils.Logger.Warn("User not found", zap.String("email", req.Email))
				c.JSON(http.StatusOK, gin.H{
					"exists": false,
				})
				return
			}

			// Handle other database errors
			utils.Logger.Error("Database error", zap.String("email", req.Email), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  "Database error",
				"exists": false,
			})
			return
		}

		utils.Logger.Info("User retrieved successfully", zap.String("email", user.Email))
		c.JSON(http.StatusOK, gin.H{
			"exists": true,
		})
	}
}

func UploadUserProfilePicture(c *gin.Context, storage *userservices.StorageService, log *zap.Logger) {

	bodyBytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.Error("Failed to read request body", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Restore the request body so it can be read again by the Gin context
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Log the request headers and body
	log.Info("Received upload request",
		zap.String("user id", userIDStr),
		zap.String("method", c.Request.Method),
		zap.String("url", c.Request.RequestURI),
		zap.String("clientIP", c.ClientIP()),
		zap.String("headers", fmt.Sprintf("%v", c.Request.Header)),
	)

	header, err := c.FormFile("profilepicture") // Use the form key "profilepicture"
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get the file"})
		return
	}

	// Check if the file is empty
	if header.Size == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The uploaded file is empty"})
		return
	}

	fileContent, err := header.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open the file"})
		return
	}
	defer fileContent.Close()

	fileID, publicUrl, err := storage.UploadFile(fileContent, "application/octet-stream")
	if err != nil {
		log.Error("Failed to upload merged file to MinIO", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file to storage"})
		return
	}

	// Query the user from the database
	var user models.User
	err = database.DB.Where("ID = ?", userIDStr).First(&user).Error
	if err != nil {
		utils.Logger.Error("Failed to retrieve user",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.ProfilePictureUrl = publicUrl

	// Save the updated user record to the database
	err = database.DB.Save(&user).Error
	if err != nil {
		utils.Logger.Error("Failed to update user profile picture",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user profile picture"})
		return
	}

	log.Info("Merged file uploaded successfully", zap.String("fileID", fileID), zap.String("profile picutre url", publicUrl))
	c.JSON(http.StatusAccepted, gin.H{"profilepictureurl": publicUrl})
}

type UserInfo struct {
	Firstname string `gorm:"not null"`
	Lastname  string `gorm:"not null"`
	Position  string ``
}

func UpdateUserInfo(c *gin.Context, log *zap.Logger) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Log the request headers and body
	log.Info("Received request to change user information",
		zap.String("user id", userIDStr),
		zap.String("method", c.Request.Method),
		zap.String("url", c.Request.RequestURI),
		zap.String("clientIP", c.ClientIP()),
		zap.String("headers", fmt.Sprintf("%v", c.Request.Header)),
	)

	// Bind request payload
	var req UserInfo
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Logger.Error("Invalid request payload", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		utils.Logger.Error("User not found", zap.String("user_id", userIDStr), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	if req.Firstname != "" {
		user.Firstname = req.Firstname
	}
	if req.Lastname != "" {
		user.Lastname = req.Lastname
	}
	if req.Position != "" {
		user.Position = req.Position
	}

	// Save the updated user record to the database
	err := database.DB.Save(&user).Error
	if err != nil {
		utils.Logger.Error("Failed to update user profile picture",
			zap.String("user_id", userIDStr),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user profile picture"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"message": "User information updated successfully"})
}

func GetUserStatistics(c *gin.Context, log *zap.Logger) {

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Log the request headers and body
	log.Info("Received request to get user statistics",
		zap.String("user id", userIDStr),
		zap.String("method", c.Request.Method),
		zap.String("url", c.Request.RequestURI),
		zap.String("clientIP", c.ClientIP()),
		zap.String("headers", fmt.Sprintf("%v", c.Request.Header)),
	)

}

func GetAllUsersInCompany(c *gin.Context, log *zap.Logger) {

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Log the request headers and body
	log.Info("Received request to get user statistics",
		zap.String("user id", userIDStr),
		zap.String("method", c.Request.Method),
		zap.String("url", c.Request.RequestURI),
		zap.String("clientIP", c.ClientIP()),
		zap.String("headers", fmt.Sprintf("%v", c.Request.Header)),
	)

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		utils.Logger.Error("User not found", zap.String("user_id", userIDStr), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var users []models.User
	err := database.DB.Where("company = ?", user.Company).Find(&users).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			utils.Logger.Warn("Users in company not found", zap.String("company", user.Company))
			c.JSON(http.StatusOK, gin.H{
				"users": nil,
			})
			return
		}

		// Handle other database errors
		utils.Logger.Warn("Users in company not found", zap.String("company", user.Company))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Database error",
		})
		return
	}

	utils.Logger.Info("Users in company found successfully", zap.String("company", user.Company))
	c.JSON(http.StatusOK, models.ConvertUsersToDTO(users))

}
