package models

import "time"

type FileMetadata struct {
	ID            int    `gorm:"autoIncrement"`       // Optional auto-increment column
	FileID        string `gorm:"primaryKey;not null"` // Part of the composite primary key
	VersionID     string `gorm:"primaryKey;not null"` // Part of the composite primary key
	UserID        string `gorm:"not null"`            // User ID
	ParentFileID  string
	FileName      string `gorm:"not null"` // File name
	Comment       string
	Size          int64     `gorm:"not null"`       // File size in bytes
	ContentType   string    `gorm:"not null"`       // MIME type of the file
	Version       int       `gorm:"default:1"`      // Human-readable version number
	CreatedAt     time.Time `gorm:"autoCreateTime"` // Automatically set when a record is created
	CreatedBy     string    `gorm:"not null"`       // User who created the file
	SharedWith    []string  `gorm:"-"`              // List of users the file is shared with (not stored in DB)
	WriteAccess   []string  `gorm:"-"`
	ReadAccess    []string  `gorm:"-"`
	SharedWithRaw string    `gorm:"type:text"` // JSON-encoded version of SharedWith (stored in DB)
}
