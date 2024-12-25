package models

import "time"

type FilesBin struct {
	FileMetadata
	DeletedBy  string
	DeletedAt  time.Time
	RestoredAt time.Time
}
