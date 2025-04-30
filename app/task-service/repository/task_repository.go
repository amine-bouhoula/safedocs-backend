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

func (r *taskRepository) GetAllTasks(limit, offset int) ([]models.Task, error) {
	var tasks []models.Task
	if err := r.db.Preload("Attachments").
		Limit(limit).
		Offset(offset).
		Order("created_at DESC").
		Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

func (r *taskRepository) GetTaskByID(id uuid.UUID) (*models.Task, error) {
	var task models.Task
	if err := r.db.
		Preload("Attachments").
		Preload("Comments", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at DESC")
		}).
		First(&task, "id = ?", id).Error; err != nil {
		return nil, err
	}

	// Now manually load UserPublicInfo for each Comment
	for i := range task.Comments {
		var user models.User
		if err := r.db.
			Select("id", "firstname", "lastname", "profile_picture_url").
			First(&user, "id = ?", task.Comments[i].UserID).Error; err == nil {
			task.Comments[i].User = models.UserPublicInfo{
				ID:                user.ID,
				Firstname:         user.Firstname,
				Lastname:          user.Lastname,
				ProfilePictureUrl: user.ProfilePictureUrl,
			}
		}
	}

	return &task, nil
}

func (r *taskRepository) GetTasksByUserID(userID uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task
	if err := r.db.Preload("Attachments").Where("assigned_to = ?", userID).Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

func (r *taskRepository) GetTasksByType(taskType models.TaskType, userID *uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task

	query := r.db.Preload("Attachments").Model(&models.Task{}).Where("type = ?", taskType)

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

	query := r.db.Preload("Attachments").Model(&models.Task{}).Where("priority = ?", priority)

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
	query := r.db.Preload("Attachments").Model(&models.Task{}).Where("status = ?", status)

	if userID != nil {
		query = query.Where("assigned_to = ?", *userID)
	}

	if err := query.Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return tasks, nil
}

func (r *taskRepository) GetTasksByProjectID(projectID uuid.UUID, userID *uuid.UUID, limit, offset int) ([]models.Task, error) {
	var tasks []models.Task
	query := r.db.Preload("Attachments").Model(&models.Task{}).Where("project_id = ?", projectID)

	if userID != nil {
		query = query.Where("assigned_to = ?", *userID)
	}

	if err := query.Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return tasks, nil
}

func (r *taskRepository) GetTasksSummaryForUser(userID *uuid.UUID) (*models.TaskSummary, error) {
	summary := &models.TaskSummary{}

	// Count opened tasks
	if err := r.db.Preload("Attachments").Model(&models.Task{}).
		Where("assigned_to = ? AND type = ? AND status IN ?", userID, models.TypeTask, []string{string(models.StatusPending), string(models.StatusInProgress)}).
		Count(&summary.OpenTasksCount).Error; err != nil {
		return nil, err
	}

	// Count closed tasks
	if err := r.db.Preload("Attachments").Model(&models.Task{}).
		Where("assigned_to = ? AND type = ? AND status IN ?", userID, models.TypeTask, []string{string(models.StatusCompleted), string(models.StatusArchived)}).
		Count(&summary.ClosedTasksCount).Error; err != nil {
		return nil, err
	}

	// Count opened bugs
	if err := r.db.Preload("Attachments").Model(&models.Task{}).
		Where("assigned_to = ? AND type = ? AND status IN ?", userID, models.TypeBug, []string{string(models.StatusPending), string(models.StatusInProgress)}).
		Count(&summary.OpenBugsCount).Error; err != nil {
		return nil, err
	}

	// Count closed bugs
	if err := r.db.Preload("Attachments").Model(&models.Task{}).
		Where("assigned_to = ? AND type = ? AND status IN ?", userID, models.TypeBug, []string{string(models.StatusCompleted), string(models.StatusArchived)}).
		Count(&summary.ClosedBugsCount).Error; err != nil {
		return nil, err
	}

	// Top 5 tasks ordered by priority
	if err := r.db.Preload("Attachments").Where("assigned_to = ? AND type = ?", userID, models.TypeTask).
		Order("priority DESC").
		Limit(5).
		Find(&summary.TopTasks).Error; err != nil {
		return nil, err
	}

	// Top 5 bugs ordered by priority
	if err := r.db.Preload("Attachments").Where("assigned_to = ? AND type = ?", userID, models.TypeBug).
		Order("priority DESC").
		Limit(5).
		Find(&summary.TopBugs).Error; err != nil {
		return nil, err
	}

	return summary, nil
}

func (r *taskRepository) EditTask(task *models.Task) error {
	var existingTask models.Task
	if err := r.db.First(&existingTask, "id = ?", task.ID).Error; err != nil {
		return err // Task not found or database error
	}

	// Update only provided fields
	updates := map[string]interface{}{}

	if task.Title != "" {
		updates["title"] = task.Title
	}
	if task.Description != "" {
		updates["description"] = task.Description
	}
	if task.Type != "" {
		updates["type"] = task.Type
	}
	if task.Status != "" {
		updates["status"] = task.Status
	}
	if task.Priority != "" {
		updates["priority"] = task.Priority
	}
	if task.DueDate != nil {
		updates["due_date"] = task.DueDate
	}
	if task.AssignedTo != nil {
		updates["assigned_to"] = task.AssignedTo
	}
	if task.DocumentID != nil {
		updates["document_id"] = task.DocumentID
	}
	if task.ProjectID != uuid.Nil {
		updates["project_id"] = task.ProjectID
	}
	if task.Comments != nil {
		updates["comments"] = task.Comments
	}

	if len(updates) == 0 {
		// nothing to update
		return nil
	}

	// Perform the update with only provided fields
	if err := r.db.Model(&existingTask).Updates(updates).Error; err != nil {
		return err
	}

	return nil
}

func (r *taskRepository) CreateComment(comment *models.Comment) error {
	// Fetch the user from the users table
	var user models.User
	if err := r.db.
		Select("id", "firstname", "lastname", "profile_picture_url").
		First(&user, "id = ?", comment.UserID).Error; err != nil {
		return err
	}

	// Fill the small public user struct
	comment.User = models.UserPublicInfo{
		ID:                user.ID,
		Firstname:         user.Firstname,
		Lastname:          user.Lastname,
		ProfilePictureUrl: user.ProfilePictureUrl,
	}

	// Now save the comment
	return r.db.Create(comment).Error
}

// GetCommentsByTaskID fetches comments for a specific task.
func (r *taskRepository) GetCommentsByTaskID(taskID uuid.UUID, limit, offset int) ([]models.Comment, error) {
	var comments []models.Comment
	err := r.db.
		Where("task_id = ?", taskID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&comments).Error
	return comments, err
}
