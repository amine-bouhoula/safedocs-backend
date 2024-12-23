package services

import (
	"company-service/internal/models"
	"errors"
	"fmt"
	"net/http"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
)

func UserExists(userID string) (bool, error) {
	userServiceURL := fmt.Sprintf("http://auth-service:8000/api/v1/users/%s", userID)

	resp, err := http.Get(userServiceURL)
	if err != nil {
		return false, errors.New("failed to contact user-service")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("user not found")
	}

	return true, nil
}

func AddUserToCompany(companyID, userID, role string) error {
	// Check if the user exists
	exists, err := UserExists(userID)
	if err != nil || !exists {
		return errors.New("user not found in user-service")
	}

	// Add user to the company
	companyUser := models.CompanyUser{
		CompanyID: companyID,
		UserID:    userID,
		Role:      role,
	}

	if err := database.DB.Create(&companyUser).Error; err != nil {
		return errors.New("failed to add user to company")
	}
	return nil
}

// RemoveUserFromCompany - Removes a user from a company
func RemoveUserFromCompany(companyID, userID string) error {
	if err := database.DB.Where("company_id = ? AND user_id = ?", companyID, userID).
		Delete(&models.CompanyUser{}).Error; err != nil {
		return errors.New("user not found in the company")
	}
	return nil
}
