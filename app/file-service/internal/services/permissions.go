package services

import (
	"errors"
	"file-service/internal/models"
	"time"

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

func (ps *PermissionsService) AddNewPermission(fileID string, sharedByID string, sharedWithID string, permissionType models.PermissionType) error {

	expiresAt := time.Now().Add(24 * time.Hour)

	sharedfile := models.FileShare{
		ID:             uuid.New().String(),
		FileID:         fileID,
		SharedWith:     sharedWithID,
		SharedBy:       sharedByID,
		PermissionType: permissionType.String(),
		ExpiresAt:      &expiresAt,
	}

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
