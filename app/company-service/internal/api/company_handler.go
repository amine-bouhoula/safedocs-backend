package handlers

import (
	"company-service/internal/models"
	"company-service/internal/services"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func CreateCompany() gin.HandlerFunc {
	return func(c *gin.Context) {
		var org models.Company

		// Bind request payload to the model
		if err := c.ShouldBindJSON(&org); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Call the service layer to create the company
		if err := services.CreateCompany(&org); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Return success response
		c.JSON(http.StatusCreated, org)
	}
}

func GetCompanyByID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract and parse company ID
		id, err := strconv.Atoi(c.Param("company_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
			return
		}

		// Call the service layer to retrieve the company
		org, err := services.GetCompanyByID(uint(id))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Company not found"})
			return
		}

		// Return the found company
		c.JSON(http.StatusOK, org)
	}
}
