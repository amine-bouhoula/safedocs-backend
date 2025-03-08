package services

import (
	"crypto/rsa"
	"strings"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
)

// Middleware to validate token and process requests
// AuthMiddleware to validate token and process requests
func AuthMiddleware(publicKey *rsa.PublicKey, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for /metrics and WebSocket connections (identified by the "Upgrade" header)
		if c.Request.URL.Path == "/metrics" || c.Request.Header.Get("Upgrade") == "websocket" {
			c.Next() // Skip authentication for these endpoints
			return
		}

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
		token, err := services.ValidateToken(tokenString, publicKey)
		if err != nil {
			logger.Error("Token validation failed",
				zap.String("client_ip", c.ClientIP()),
				zap.String("token", tokenString),
				zap.Error(err),
			)
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized", "message": err.Error()})
			return
		}

		// Extract claims from the token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			logger.Error("Failed to extract claims from token",
				zap.String("token", tokenString),
			)
			c.AbortWithStatusJSON(401, gin.H{"error": "Failed to extract claims from token"})
			return
		}

		// Extract userID from claims
		userID, ok := claims["userID"].(string)
		if !ok {
			logger.Error("UserID not found in token claims",
				zap.Any("claims", claims),
			)
			c.AbortWithStatusJSON(401, gin.H{"error": "UserID not found in token"})
			return
		}

		// Store the userID in the context for use in handlers
		c.Set("userID", userID)

		// Proceed to the next handler
		c.Next()
	}
}
