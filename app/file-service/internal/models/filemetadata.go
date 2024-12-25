package models

import "time"

type FileMetadata struct {
	FileID        string `gorm:"primaryKey"` // Unique identifier for the file
	UserID        string `gorm:"not null"`   // User ID
	ParentFileID  string
	FileName      string `gorm:"not null"`  // File name
	Size          int64  `gorm:"not null"`  // File size in bytes
	ContentType   string `gorm:"not null"`  // MIME type of the file
	Version       int    `gorm:"default:1"` // Human-readable version number
	VersionID     string
	CreatedAt     time.Time `gorm:"autoCreateTime"` // Automatically set when a record is created
	CreatedBy     string    `gorm:"not null"`       // User who created the file
	SharedWith    []string  `gorm:"-"`              // List of users the file is shared with (not stored in DB)
	WriteAccess   []string  `gorm:"-"`
	ReadAccess    []string  `gorm:"-"`
	SharedWithRaw string    `gorm:"type:text"` // JSON-encoded version of SharedWith (stored in DB)
}
