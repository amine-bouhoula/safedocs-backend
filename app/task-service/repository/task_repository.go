package repository

import (
	"task-service/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type taskRepository struct {
	db *gorm.DB
}

func NewTaskRepository(db *gorm.DB) models.TaskRepository {
	return &taskRepository{db}
}

func (r *taskRepository) CreateTask(task *models.Task) error {
	return r.db.Create(task).Error
}

func (r *taskRepository) GetTaskByID(id uuid.UUID) (*models.Task, error) {
	var task models.Task
	if err := r.db.First(&task, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *taskRepository) GetTasksByUserID(userID uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task
	if err := r.db.Where("assigned_to = ?", userID).Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

func (r *taskRepository) GetTasksByType(taskType models.TaskType, userID *uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task

	query := r.db.Model(&models.Task{}).Where("type = ?", taskType)

	if userID != nil {
		query = query.Where("assigned_to = ?", *userID)
	}

	if err := query.Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return tasks, nil
}

func (r *taskRepository) GetTasksByPriority(priority models.TaskPriority, userID *uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task

	query := r.db.Model(&models.Task{}).Where("priority = ?", priority)

	if userID != nil {
		query = query.Where("assigned_to = ?", *userID)
	}

	if err := query.Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return tasks, nil
}

func (r *taskRepository) GetTasksByStatus(status models.TaskStatus, userID *uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task
	query := r.db.Model(&models.Task{}).Where("status = ?", status)

	if userID != nil {
		query = query.Where("assigned_to = ?", *userID)
	}

	if err := query.Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return tasks, nil
}

func (r *taskRepository) GetTasksByCompanyID(companyID uuid.UUID, userID *uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task
	query := r.db.Model(&models.Task{}).Where("company_id = ?", companyID)

	if userID != nil {
		query = query.Where("assigned_to = ?", *userID)
	}

	if err := query.Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return tasks, nil
}
