package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TaskType string

const (
	TypeTask TaskType = "task"
	TypeBug  TaskType = "bug"
)

// Task represents a task entity in the DMS
// It can be related to documents, approvals, or general project tasks.
type Task struct {
	ID          uuid.UUID      `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	Title       string         `gorm:"type:varchar(255);not null" json:"title"`
	Description string         `gorm:"type:text" json:"description"`
	CompanyID   uuid.UUID      `gorm:"type:uuid;index;not null" json:"company_id"`
	Type        TaskType       `gorm:"type:varchar(50);default:'task'" json:"type"`
	AssignedTo  *uuid.UUID     `gorm:"type:uuid;index;default:null" json:"assigned_to,omitempty"`
	DueDate     *time.Time     `json:"due_date,omitempty"`
	Status      TaskStatus     `gorm:"type:varchar(50);default:'pending'" json:"status"`
	Priority    TaskPriority   `gorm:"type:varchar(50);default:'medium'" json:"priority"`
	DocumentID  *uuid.UUID     `gorm:"type:uuid;index;default:null" json:"document_id,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type CreateTaskDTO struct {
	Title       string    `json:"title" binding:"required"`
	Description string    `json:"description" binding:"required"`
	CompanyID   uuid.UUID `json:"company_id" binding:"required"`
	Type        TaskType  `json:"type" binding:"required,oneof=task bug"`
}

// TaskStatus represents possible statuses of a Task
type TaskStatus string

const (
	StatusPending    TaskStatus = "pending"
	StatusInProgress TaskStatus = "in_progress"
	StatusCompleted  TaskStatus = "completed"
	StatusArchived   TaskStatus = "archived"
)

// TaskPriority represents the priority of the Task
type TaskPriority string

const (
	PriorityLow    TaskPriority = "low"
	PriorityMedium TaskPriority = "medium"
	PriorityHigh   TaskPriority = "high"
)

// TaskQueryDTO represents parameters to query tasks.
type TaskQueryDTO struct {
	ID        *uuid.UUID    `form:"id"`
	UserID    *uuid.UUID    `form:"user_id"`
	Priority  *TaskPriority `form:"priority"`
	Status    *TaskStatus   `form:"status"`
	CompanyID *uuid.UUID    `form:"company_id"`
}

// TaskRepository defines methods for interacting with tasks in the database.
type TaskRepository interface {
	CreateTask(task *Task) error
	GetTaskByID(id uuid.UUID) (*Task, error)
	GetTasksByUserID(userID uuid.UUID, limit, offset int) ([]Task, error)
	GetTasksByType(taskType TaskType, limit, offset int) ([]Task, error)
	GetTasksByPriority(priority TaskPriority, limit, offset int) ([]Task, error)
	GetTasksByStatus(status TaskStatus, limit, offset int) ([]Task, error)
	GetTasksByCompanyID(companyID uuid.UUID, limit, offset int) ([]Task, error)
}
