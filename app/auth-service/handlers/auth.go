package handlers

import (
	"auth-service/models"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"

	authservices "auth-service/utils"

	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func RegisterHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log incoming request
		utils.Logger.Info("Received a register request",
			zap.String("method", c.Request.Method),
			zap.String("url", c.Request.URL.Path),
		)

		// Bind request payload
		var req models.RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			utils.Logger.Error("Invalid request payload", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Hash the password
		hashedPassword, err := utils.HashPassword(req.Password)
		if err != nil {
			utils.Logger.Error("Error hashing password", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
			return
		}

		// Create user model
		user := models.User{
			Username: req.Username,
			Email:    req.Email,
			Password: hashedPassword,
		}

		// Save user to database
		if err := database.DB.Create(&user).Error; err != nil {
			utils.Logger.Error("Failed to register user", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
			return
		}

		utils.Logger.Info("User registered successfully", zap.String("username", user.Username))

		// Load the private key for JWT generation
		privateKeyPEM, err := authservices.LoadPrivateKey("../keys/private_key.pem")
		if err != nil {
			utils.Logger.Fatal("Failed to load private key", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load private key"})
			return
		}

		// Generate JWT token
		token, err := authservices.GenerateInternalJWT(user, []string{"admin"}, privateKeyPEM)
		if err != nil {
			utils.Logger.Error("Failed to generate token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// Respond with token
		c.JSON(http.StatusCreated, gin.H{
			"user_uuid": user.ID,
			"token":     token,
		})

	}
}

func LoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log incoming request
		utils.Logger.Info("Received a login request",
			zap.String("method", c.Request.Method),
			zap.String("url", c.Request.URL.Path),
		)

		// Parse the request payload
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			utils.Logger.Error("Invalid request payload", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Check if user exists in the database
		var user models.User
		err := database.DB.Where("email = ?", req.Email).First(&user).Error
		if err != nil {
			utils.Logger.Error("Invalid credentials", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Validate password
		if !utils.CheckPasswordHash(req.Password, user.Password) {
			utils.Logger.Error("Invalid credentials - wrong password")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Load the private key for JWT generation
		privateKeyPEM, err := authservices.LoadPrivateKey("../keys/private_key.pem")
		if err != nil {
			utils.Logger.Fatal("Failed to load private key", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load private key"})
			return
		}

		// Generate JWT token
		token, err := authservices.GenerateInternalJWT(user, []string{"admin"}, privateKeyPEM)
		if err != nil {
			utils.Logger.Error("Failed to generate token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// Respond with token
		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	}
}

func RefreshTokenHandler(accessTokenSecret, refreshTokenSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshTokenRequest

		// Validate request payload
		if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Parse the refresh token
		token, err := jwt.ParseWithClaims(req.RefreshToken, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte(refreshTokenSecret), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok || claims.ExpiresAt.Time.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token claims are invalid"})
			return
		}

		// Verify token from Redis
		storedToken, err := authservices.GetToken(database.RedisClient, claims.UserID)
		if err != nil || storedToken != req.RefreshToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found or already used"})
			return
		}

		// Generate a new access token
		newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
			UserID: claims.UserID,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			},
		})

		accessToken, err := newAccessToken.SignedString([]byte(accessTokenSecret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		// Respond with new token
		c.JSON(http.StatusOK, gin.H{
			"access_token": accessToken,
		})
	}
}

func LogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LogoutRequest

		// Validate request payload
		if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Delete the token from Redis
		if err := authservices.DeleteToken(database.RedisClient, req.RefreshToken); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found"})
			return
		}

		// Success response
		c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
	}
}

func GetUserHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")

		// Log the incoming request
		utils.Logger.Info("Received request to get user",
			zap.String("user_id", userID),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
		)

		// Query the user from the database
		var user models.User
		err := database.DB.Where("ID = ?", userID).First(&user).Error
		if err != nil {
			utils.Logger.Error("Failed to retrieve user",
				zap.String("user_id", userID),
				zap.Error(err),
			)
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Successful response log
		utils.Logger.Info("User retrieved successfully",
			zap.String("user_id", string(user.ID)),
		)

		// Respond with the found user
		c.JSON(http.StatusOK, gin.H{
			"user_id":  user.ID,
			"email":    user.Email,
			"username": user.Username,
		})
	}
}

func GetUserByEmailHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		userEmail := c.Param("user_email")

		// Log the incoming request
		utils.Logger.Info("Received request to get user",
			zap.String("user_email", userEmail),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
		)

		// Query the user from the database
		var user models.User
		err := database.DB.Where("Email = ?", userEmail).First(&user).Error
		if err != nil {
			utils.Logger.Error("Failed to retrieve user",
				zap.String("user_email", userEmail),
				zap.Error(err),
			)
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Successful response log
		utils.Logger.Info("User retrieved successfully",
			zap.String("user_email", string(user.ID)),
		)

		// Respond with the found user
		c.JSON(http.StatusOK, gin.H{
			"user_id":  user.ID,
			"email":    user.Email,
			"username": user.Username,
		})
	}
}
