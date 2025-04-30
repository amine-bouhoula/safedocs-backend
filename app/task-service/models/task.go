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
	ProjectID   uuid.UUID      `gorm:"type:uuid" json:"project_id"`
	Type        TaskType       `gorm:"type:varchar(50);default:'task'" json:"type"`
	AssignedTo  *uuid.UUID     `gorm:"type:uuid;index;default:null" json:"assigned_to,omitempty"`
	DueDate     *time.Time     `json:"due_date,omitempty"`
	Status      TaskStatus     `gorm:"type:varchar(50);default:'pending'" json:"status"`
	Priority    TaskPriority   `gorm:"type:varchar(50);default:'medium'" json:"priority"`
	DocumentID  *uuid.UUID     `gorm:"type:uuid;index;default:null" json:"document_id,omitempty"`
	Attachments []Attachment   `gorm:"foreignKey:TaskID;constraint:OnDelete:CASCADE;" json:"attachments,omitempty"`
	Comments    []Comment      `gorm:"foreignKey:TaskID;constraint:OnDelete:CASCADE;" json:"comments,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// Attachment represents a file attached to a task.
type Attachment struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	TaskID    uuid.UUID `gorm:"type:uuid;index;not null" json:"task_id"`
	FileName  string    `gorm:"type:varchar(255);not null" json:"file_name"`
	FileURL   string    `gorm:"type:text;not null" json:"file_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateTaskDTO represents the data required to create a new task.
type CreateTaskDTO struct {
	Title       string          `json:"title" binding:"required"`
	Description string          `json:"description" binding:"required"`
	ProjectID   uuid.UUID       `json:"project_id" binding:"required"`
	Type        TaskType        `json:"type" binding:"required,oneof=task bug"`
	Attachments []AttachmentDTO `json:"attachments,omitempty"`
}

// AttachmentDTO represents the data required to attach a file to a task.
type AttachmentDTO struct {
	FileName string `json:"file_name" binding:"required"`
	FileURL  string `json:"file_url" binding:"required"`
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
	ProjectID *uuid.UUID    `form:"project_id"`
}

type TaskSummary struct {
	OpenTasksCount   int64  `json:"open_tasks_count"`
	ClosedTasksCount int64  `json:"closed_tasks_count"`
	OpenBugsCount    int64  `json:"open_bugs_count"`
	ClosedBugsCount  int64  `json:"closed_bugs_count"`
	TopTasks         []Task `json:"top_tasks"`
	TopBugs          []Task `json:"top_bugs"`
}

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

type UserPublicInfo struct {
	ID                string `json:"id"`
	Firstname         string `json:"firstname"`
	Lastname          string `json:"lastname"`
	ProfilePictureUrl string `json:"profile_picture_url"`
}

type Comment struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	TaskID    uuid.UUID      `json:"task_id" gorm:"type:uuid;index"`
	Content   string         `json:"content"`
	CreatedAt time.Time      `json:"created_at"`
	UserID    uuid.UUID      `gorm:"type:uuid;index" json:"user_id"`
	User      UserPublicInfo `gorm:"foreignKey:UserID" json:"user"`
}

// TaskRepository defines methods for interacting with tasks in the database.
type TaskRepository interface {
	CreateTask(task *Task) error
	GetAllTasks(limit, offset int) ([]Task, error)
	GetTaskByID(id uuid.UUID) (*Task, error)
	GetTasksByUserID(userID uuid.UUID, limit, offset int) ([]Task, error)
	GetTasksByType(taskType TaskType, userID *uuid.UUID, limit, offset int) ([]Task, error)
	GetTasksByPriority(priority TaskPriority, userID *uuid.UUID, limit, offset int) ([]Task, error)
	GetTasksByStatus(status TaskStatus, userID *uuid.UUID, limit, offset int) ([]Task, error)
	GetTasksByProjectID(projectID uuid.UUID, userID *uuid.UUID, limit, offset int) ([]Task, error)
	GetTasksSummaryForUser(userID *uuid.UUID) (*TaskSummary, error)
	EditTask(task *Task) error
	CreateComment(comment *Comment) error
	GetCommentsByTaskID(taskID uuid.UUID, limit, offset int) ([]Comment, error)
}
