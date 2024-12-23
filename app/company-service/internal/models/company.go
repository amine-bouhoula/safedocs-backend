package models

import (
	"time"

	"gorm.io/gorm"
)

type Company struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"unique;not null"`
	Description string
	OwnerID     uint `gorm:"not null"` // User ID of the owner
	CreatedAt   string
	UpdatedAt   string
}

type CompanyUser struct {
	ID        uint           `gorm:"primaryKey;autoIncrement"`
	CompanyID string         `gorm:"type:uuid;not null;index"`
	UserID    string         `gorm:"type:uuid;not null;index"`
	Role      string         `gorm:"type:varchar(50);default:'user'"` // Optional: For role-based permissions
	CreatedAt time.Time      `gorm:"autoCreateTime"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"` // Soft delete support
}
