package services

import (
	"file-service/internal/models"

	"github.com/google/uuid"
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
func (m *MetadataService) SaveFileMetadata(userID string, fileID string, fileName string, fileVersion string, size int64) error {
	metadata := models.FileMetadata{
		UserID:       userID,
		FileID:       fileID,
		ParentFileID: uuid.NewString(),
		VersionID:    fileVersion,
		FileName:     fileName,
		Size:         size,
		ContentType:  "application/octet-stream",
	}

	m.logger.Info("File metadata logged",
		zap.String("FileID", metadata.FileID),
		zap.String("UserID", metadata.UserID),
		zap.String("ParentFileID", metadata.ParentFileID),
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

func (ms *MetadataService) GetFilesByUserID(userID string) ([]models.FileMetadata, error) {
	var files []models.FileMetadata
	err := ms.db.Where("user_id = ?", userID).Find(&files).Error
	return files, err
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
		zap.String("ParentFileID", metadata.ParentFileID),
		zap.String("VersionID", metadata.VersionID),
		zap.String("FileName", metadata.FileName),
		zap.Int64("Size", metadata.Size),
		zap.String("ContentType", metadata.ContentType),
	)

	// Delete the file metadata
	if err := m.db.Delete(&metadata).Error; err != nil {
		m.logger.Error("Failed to delete metadata", zap.Error(err))
		return err
	}
	return nil
}
