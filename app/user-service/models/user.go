package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID                string `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Firstname         string `gorm:"not null"`
	Lastname          string `gorm:"not null"`
	Email             string `gorm:"unique;not null"`
	Password          string `gorm:"not null"`
	Company           string
	Role              string
	CreatedAt         time.Time      `gorm:"autoCreateTime"`
	UpdatedAt         time.Time      `gorm:"autoUpdateTime"`
	DeletedAt         gorm.DeletedAt `gorm:"index"`
	ProfilePictureUrl string         `gorm:"type:text"` // URL of the profile picture
	Position          string         ``
}
