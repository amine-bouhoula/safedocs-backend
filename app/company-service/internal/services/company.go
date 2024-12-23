package services

import (
	"company-service/internal/models"
	"errors"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
)

func CreateCompany(company *models.Company) error {

	if err := database.DB.Create(company).Error; err != nil {
		return errors.New("failed to create company")
	}
	return nil
}

func GetCompanyByID(id uint) (*models.Company, error) {

	var org models.Company
	if err := database.DB.First(&org, id).Error; err != nil {
		return nil, errors.New("company not found")
	}
	return &org, nil
}
