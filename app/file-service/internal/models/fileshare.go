package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type FileShare struct {
	ID             string     `gorm:"type:uuid;primaryKey"`       // Unique identifier
	FileID         string     `gorm:"type:uuid;not null"`         // Foreign key to files table
	SharedWith     string     `gorm:"type:uuid;not null"`         // Email of the person the file is shared with
	SharedBy       string     `gorm:"type:uuid;not null"`         // Foreign key to users table (sharer)
	PermissionType string     `gorm:"type:varchar(10);not null;"` // e.g., "read", "write"
	ExpiresAt      *time.Time `gorm:"type:timestamp"`             // Optional expiration time for the share
	CreatedAt      time.Time  `gorm:"autoCreateTime"`             // Creation timestamp
}

// BeforeCreate hook to auto-generate UUID for the primary key
func (fs *FileShare) BeforeCreate(tx *gorm.DB) (err error) {
	fs.ID = uuid.New().String()
	return
}
