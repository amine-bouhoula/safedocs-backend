package services

import (
	"crypto/rsa"
	"strings"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Middleware to validate token and process requests
func AuthMiddleware(publicKey *rsa.PublicKey, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/metrics" {
			c.Next() // Skip authentication for /metrics
			return
		}

		// Extract basic request info for logging
		requestID := c.GetHeader("uploadSessionId") // Assume clients send a unique request ID
		logger = logger.With(zap.String("request_id", requestID), zap.String("path", c.Request.URL.Path))

		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Warn("Authorization header missing",
				zap.String("client_ip", c.ClientIP()),
			)
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header missing"})
			return
		}

		// Extract the token from "Bearer <token>" format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			logger.Warn("Invalid Authorization header format",
				zap.String("client_ip", c.ClientIP()),
				zap.String("auth_header", authHeader),
			)
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid Authorization header format"})
			return
		}
		tokenString := parts[1]

		// Validate the token
		claims, err := services.ValidateToken(tokenString, publicKey)
		if err != nil {
			logger.Error("Token validation failed",
				zap.String("client_ip", c.ClientIP()),
				zap.String("token", tokenString),
				zap.Error(err),
			)
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized", "message": err.Error()})
			return
		}

		// // Log successful validation
		// logger.Info("Token validated successfully",
		// 	zap.String("client_ip", c.ClientIP()),
		// 	zap.Any("claims", claims),
		// )

		// Store the claims in the context for use in handlers
		c.Set("claims", claims)

		// Proceed to the next handler
		c.Next()
	}
}
