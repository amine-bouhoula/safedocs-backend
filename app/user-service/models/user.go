package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID          string         `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Username    string         `gorm:"unique;not null"`
	Email       string         `gorm:"unique;not null"`
	Password    string         `gorm:"not null"`
	ProfileLink string         `gorm:"type:text"` // Added profile link field
	CreatedAt   time.Time      `gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}
