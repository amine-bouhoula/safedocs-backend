package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PermissionType string

const (
	PermissionRead  PermissionType = "read"
	PermissionWrite PermissionType = "write"
	PermissionShare PermissionType = "share"
)

func (p PermissionType) String() string {
	return string(p)
}

type FilePermission struct {
	ID             string    `gorm:"type:uuid;primaryKey"`       // Unique identifier
	FileID         string    `gorm:"type:uuid;not null"`         // Foreign key to files table
	UserID         string    `gorm:"type:uuid;not null"`         // Foreign key to users table
	PermissionType string    `gorm:"type:varchar(10);not null;"` // e.g., "read", "write"
	CreatedAt      time.Time `gorm:"autoCreateTime"`             // Creation timestamp
}

// BeforeCreate hook to auto-generate UUID for the primary key
func (fp *FilePermission) BeforeCreate(tx *gorm.DB) (err error) {
	fp.ID = uuid.New().String()
	return
}
