package handlers

import (
	"net/http"

	"company-service/internal/services"

	"github.com/gin-gonic/gin"
)

type AddUserRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"omitempty,oneof=admin user"`
}

// AddUserToCompany - Adds a user to a company
func AddUserToCompany() gin.HandlerFunc {
	return func(c *gin.Context) {
		companyID := c.Param("company_id")

		var req AddUserRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Call the service layer
		if err := services.AddUserToCompany(companyID, req.UserID, req.Role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "User added to the company successfully"})
	}
}
