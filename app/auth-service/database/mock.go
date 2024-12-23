package database

import (
	"database/sql"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// OpenMockDB - Initializes a GORM mock database using sql.DB
func OpenMockDB(db *sql.DB) (*gorm.DB, error) {
	mockDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db, // Use the mock SQL database connection
	}), &gorm.Config{})

	if err != nil {
		return nil, err
	}
	database.DB = mockDB
	return mockDB, nil
}
