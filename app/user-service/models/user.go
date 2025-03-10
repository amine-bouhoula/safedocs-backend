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

// UserDTO is a slim version used for data transfer.
type UserDTO struct {
	ID        string `json:"id"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Email     string `json:"email"`
}

// ToDTO converts a full User model to the UserDTO.
func (u *User) ToDTO() UserDTO {
	return UserDTO{
		ID:        u.ID,
		Firstname: u.Firstname,
		Lastname:  u.Lastname,
		Email:     u.Email,
	}
}

// ConvertUsersToDTO converts a slice of User into a slice of UserDTO.
func ConvertUsersToDTO(users []User) []UserDTO {
	dtos := make([]UserDTO, len(users))
	for i, user := range users {
		dtos[i] = user.ToDTO()
	}
	return dtos
}
