package services

import (
	"errors"
	"file-service/internal/models"
	"time"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type PermissionsService struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewPermissionsService(db *gorm.DB, log *zap.Logger) *PermissionsService {
	return &PermissionsService{db: db, logger: log}
}

func (ps *PermissionsService) GetFilePermissionsByID(fileID string) (models.FilePermission, error) {
	var permission models.FilePermission
	err := ps.db.Where("file_id = ?", fileID).First(&permission).Error
	return permission, err

}

func (ps *PermissionsService) IsActionAllowed(fileID string, userID string, action models.PermissionType) (bool, error) {
	var filePermission models.FilePermission
	var fileShare models.FileShare

	// Check file permissions
	err := ps.db.Where("file_id = ? AND user_id = ? and permission_type = ?", fileID, userID, action).First(&filePermission)
	if err == nil {
		return true, nil
	}

	// Check file share table
	err = ps.db.Where("file_id = ? AND shared_with = ? and permission_type = ?", fileID, userID, action).First(&fileShare)
	if err == nil {
		return true, nil
	}

	return false, errors.New("permission denied")
}

func (ps *PermissionsService) AddNewPermission(fileID string, sharedByID string, sharedWithEmail string, permissionType models.PermissionType) error {

	expiresAt := time.Now().Add(24 * time.Hour)

	var user models.User
	err := database.DB.Where("Email = ?", sharedWithEmail).First(&user).Error
	if err != nil {
		utils.Logger.Error("Failed to retrieve user",
			zap.String("user_email", sharedWithEmail),
			zap.Error(err),
		)
		return err
	}

	sharedfile := models.FileShare{
		ID:             uuid.New().String(),
		FileID:         fileID,
		SharedWith:     user.ID,
		SharedBy:       sharedByID,
		PermissionType: permissionType.String(),
		ExpiresAt:      &expiresAt,
	}

	// Successful response log
	utils.Logger.Info("User retrieved successfully",
		zap.String("user_email", string(user.ID)),
	)

	ps.logger.Info("File share logged",
		zap.String("FileShareID", sharedfile.ID),
		zap.String("FileID", sharedfile.FileID),
		zap.String("SharedBy", sharedfile.SharedBy),
		zap.String("SharedWith", sharedfile.SharedWith),
	)

	if err := ps.db.Create(&sharedfile).Error; err != nil {
		ps.logger.Error("Failed to save metadata", zap.Error(err))
		return err
	}
	return nil
}

func (ps *PermissionsService) GetSharedFilesByUserEmail(sharedWithEmail string, permissionType models.PermissionType) ([]string, error) {

	// Query the user from the database
	var user models.User
	err := database.DB.Where("Email = ?", sharedWithEmail).First(&user).Error
	if err != nil {
		utils.Logger.Error("Failed to retrieve user",
			zap.String("user_email", sharedWithEmail),
			zap.Error(err),
		)
		return nil, err
	}

	// Successful response log
	utils.Logger.Info("User retrieved successfully",
		zap.String("user_email", string(user.ID)),
	)

	var files []models.FileShare
	err = ps.db.Where("shared_with = ? AND permission_type = ?", user.ID, permissionType).Find(&files).Error
	if err != nil {
		return nil, err
	}

	var filesID []string
	for _, file := range files {
		filesID = append(filesID, file.FileID)
	}
	return filesID, nil
}

func (ps *PermissionsService) GetSharedFilesByUserID(sharedWithID string, permissionType models.PermissionType) ([]string, error) {
	var files []models.FileShare
	err := ps.db.Where("shared_with = ? AND permission_type = ?", sharedWithID, permissionType).Find(&files).Error
	if err != nil {
		return nil, err
	}

	var filesID []string
	for _, file := range files {
		filesID = append(filesID, file.FileID)
	}
	return filesID, nil
}
