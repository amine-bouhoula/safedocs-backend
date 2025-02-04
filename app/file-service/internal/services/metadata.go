package services

import (
	"file-service/internal/models"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type MetadataService struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewMetadataService(db *gorm.DB, log *zap.Logger) *MetadataService {
	return &MetadataService{db: db, logger: log}
}

// SaveFileMetadata saves the file metadata using GORM
func (m *MetadataService) SaveFileMetadata(userID string, fileID string, fileName string, fileVersion string, comment string, size int64) error {
	metadata := models.FileMetadata{
		UserID:      userID,
		FileID:      fileID,
		VersionID:   fileVersion,
		FileName:    fileName,
		Comment:     comment,
		Size:        size,
		ContentType: "application/octet-stream",
		CreatedBy:   userID,
	}

	m.logger.Info("File metadata logged",
		zap.String("FileID", metadata.FileID),
		zap.String("UserID", metadata.UserID),
		zap.String("VersionID", metadata.VersionID),
		zap.String("FileName", metadata.FileName),
		zap.Int64("Size", metadata.Size),
		zap.String("ContentType", metadata.ContentType),
	)

	if err := m.db.Create(&metadata).Error; err != nil {
		m.logger.Error("Failed to save metadata", zap.Error(err))
		return err
	}
	return nil
}

func (ms *MetadataService) GetFilesByUserID(userID string, offset int, size int, order_by string, sort string) ([]models.FileMetadata, int64, error) {
	var files []models.FileMetadata
	var totalpages int64

	if order_by == "" {
		order_by = "created_at"
	}

	if sort == "" {
		sort = "DESC"
	}

	// Count total files for the user
	if err := ms.db.Model(&models.FileMetadata{}).
		Where("user_id = ?", userID).
		Count(&totalpages).Error; err != nil {
		return nil, 0, err
	}

	if offset != -1 && size != 0 {
		err := ms.db.Where("user_id = ?", userID).
			Order(fmt.Sprintf("%s %s", order_by, sort)).
			Offset(offset).
			Limit(size).
			Find(&files).Error

		if err != nil {
			return nil, 0, err
		}

	} else {
		err := ms.db.Where("user_id = ?", userID).
			Order(fmt.Sprintf("%s %s", order_by, sort)). // Fix here
			Find(&files).Error
		if err != nil {
			return nil, 0, err
		}

	}
	return files, totalpages, nil
}

func (m *MetadataService) DeleteFileMetadata(userID string, fileID string, fileVersion string) error {
	// Query the existing file metadata from the database
	var metadata models.FileMetadata
	//if err := m.db.Where("user_id = ? AND file_id = ? AND version_id = ?", userID, fileID, fileVersion).First(&metadata).Error; err != nil {
	if err := m.db.Where("user_id = ? AND file_id = ?", userID, fileID).First(&metadata).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			m.logger.Warn("Metadata not found for file",
				zap.String("FileID", fileID),
				zap.String("UserID", userID),
				zap.String("VersionID", fileVersion),
			)
			return nil // Return nil if the record doesn't exist
		}
		m.logger.Error("Failed to retrieve metadata", zap.Error(err))
		return err
	}

	// Log the metadata before deleting
	m.logger.Info("Deleting file metadata",
		zap.String("FileID", metadata.FileID),
		zap.String("UserID", metadata.UserID),
		zap.String("VersionID", metadata.VersionID),
		zap.String("FileName", metadata.FileName),
		zap.Int64("Size", metadata.Size),
		zap.String("ContentType", metadata.ContentType),
	)

	m.logger.Info("Moving file metadata to bin")

	binEntry := models.FilesBin{
		FileMetadata: metadata,
		DeletedBy:    userID,
		DeletedAt:    time.Now(),
	}

	if err := m.db.Create(&binEntry).Error; err != nil {
		m.logger.Error("Failed to save metadata to bin", zap.Error(err))
		return err
	}

	// Delete the file metadata
	if err := m.db.Delete(&metadata).Error; err != nil {
		m.logger.Error("Failed to delete metadata", zap.Error(err))
		return err
	}
	return nil
}

func (ms *MetadataService) GetFilesByID(filseID []string) ([]models.FileMetadata, error) {
	var files []models.FileMetadata
	err := ms.db.Where("file_id IN ?", filseID).Find(&files).Error
	return files, err
}

func (ms *MetadataService) GetFileByVersionID(versionID string) (models.FileMetadata, error) {
	var file models.FileMetadata
	err := ms.db.Where("version_id = ?", versionID).Find(&file).Error
	return file, err
}

func (ms *MetadataService) GetBinContents(userID string) ([]models.FilesBin, error) {
	var binContents []models.FilesBin
	err := ms.db.Where("user_id = ?", userID).Find(&binContents).Error
	return binContents, err
}

func (ms *MetadataService) RestoreFile(fileID string, userID string) error {
	var binEntry models.FilesBin
	if err := ms.db.Where("file_id = ? AND user_id = ?", fileID, userID).First(&binEntry).Error; err != nil {
		return err
	}

	// Restore the file to Metadata table
	restoredFile := binEntry.FileMetadata
	if err := ms.db.Create(&restoredFile).Error; err != nil {
		ms.logger.Error("failed to restore file metadata", zap.Error(err))
		return err
	}

	// Delete the deleted file record from FilesBin
	if err := ms.db.Delete(&binEntry).Error; err != nil {
		ms.logger.Error("Failed to delete metadata from filesbin", zap.Error(err))
		return err
	}

	ms.logger.Info("file restored correctly")
	return nil
}
