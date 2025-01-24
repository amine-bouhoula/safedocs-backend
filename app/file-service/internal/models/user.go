package models

import (
	"time"

	"gorm.io/gorm"
)

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

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    string    `gorm:"not null;index"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}
