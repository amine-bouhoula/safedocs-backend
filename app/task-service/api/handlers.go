package api

import (
	"net/http"
	"strconv"
	"time"

	"task-service/models"
	"task-service/repository"
	taskservices "task-service/services"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	"github.com/gin-contrib/cors"
	"github.com/google/uuid"
	"github.com/minio/minio-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	database "github.com/amine-bouhoula/safedocs-mvp/sdlib/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type StorageService struct {
	client *minio.Client
	logger *zap.Logger
	bucket string
}

func StartServer(cfg *config.Config, log *zap.Logger) {
	// Ensure logger is not nil
	if log == nil {
		panic("Logger is required but not provided")
	}

	// Validate configuration
	log.Info("Validating server configuration")
	if cfg.ServerPort == "" {
		log.Fatal("Server port must be specified in configuration")
	}
	log.Info("Server configuration validated", zap.String("server_port", cfg.ServerPort))

	// Initialize Gin router
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		//AllowOrigins:     []string{"http://localhost:3039"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		ExposeHeaders:    []string{"Content-Length", "Authorization"},
		MaxAge:           12 * time.Hour, // Caching preflight requests
	}))

	// Initialize services with proper error handling
	log.Info("Initializing storage service")
	_, err := taskservices.ConnectMinio(cfg.MinIOURL, cfg.MinIOUser, cfg.MinIOPass, log)
	if err != nil {
		log.Fatal("Failed to initialize storage service", zap.Error(err))
	}
	log.Info("Storage service initialized successfully")

	// Load the RSA public key
	log.Info("Loading RSA public key", zap.String("public_key_path", cfg.PublicKeyPath))
	publicKey, err := services.LoadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		//log.Fatal("Error loading RSA public key", zap.Error(err))
	}
	log.Info("RSA public key loaded successfully")

	// Apply middleware
	log.Info("Applying authentication middleware")
	router.Use(taskservices.AuthMiddleware(publicKey, log))

	// Define /metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	repo := repository.NewTaskRepository(database.DB)

	taskHandler := NewTaskHandler(repo)

	// Define routes
	log.Info("Defining routes")
	router.POST("/api/v1/tasks", taskHandler.CreateTask)
	router.GET("/api/v1/tasks", taskHandler.GetAllTasks)
	router.GET("/api/v1/tasks/", taskHandler.GetAllTasks)
	router.GET("/api/v1/tasks/:task_id", taskHandler.GetTaskByID)
	router.PUT("/api/v1/tasks/:task_id", taskHandler.EditTask)
	router.GET("/api/v1/tasks/user/:user_id", taskHandler.GetTasksByUserID)
	router.GET("/api/v1/tasks/summary/:user_id", taskHandler.GetTasksSummaryForUser)
	router.GET("/api/v1/tasks/type/:type", taskHandler.GetTasksByType) // New route added
	router.GET("/api/v1/tasks/priority/:priority", taskHandler.GetTasksByPriority)
	router.GET("/api/v1/tasks/status/:status", taskHandler.GetTasksByStatus)
	router.GET("/api/v1/tasks/project/:project_id", taskHandler.GetTasksByProjectID)
	router.POST("/api/v1/tasks/:task_id/comments", taskHandler.CreateComment)
	router.GET("/api/v1/tasks/:task_id/comments", taskHandler.GetCommentsByTaskID)

	// Start the server
	port := cfg.ServerPort
	log.Info("Starting server", zap.String("port", port))
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server", zap.Error(err))
	}
}

type TaskHandler struct {
	repo models.TaskRepository
}

func NewTaskHandler(repo models.TaskRepository) *TaskHandler {
	return &TaskHandler{repo: repo}
}

func (h *TaskHandler) CreateTask(c *gin.Context) {
	var taskDTO models.CreateTaskDTO
	if err := c.ShouldBindJSON(&taskDTO); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
		return
	}

	parsedUserID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Create task entity
	task := &models.Task{
		ID:          uuid.New(),
		Title:       taskDTO.Title,
		Description: taskDTO.Description,
		ProjectID:   taskDTO.ProjectID,
		Type:        taskDTO.Type,
		Status:      models.StatusPending,
		AssignedTo:  &parsedUserID,
	}

	// Process pre-uploaded attachments
	var attachments []models.Attachment
	for _, att := range taskDTO.Attachments {
		attachment := models.Attachment{
			ID:       uuid.New(),
			TaskID:   task.ID,
			FileName: att.FileName,
			FileURL:  att.FileURL,
		}
		attachments = append(attachments, attachment)
	}

	// Assign attachments to the task
	task.Attachments = attachments

	// Save task and attachments in the database
	if err := h.repo.CreateTask(task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, task)
}

func (h *TaskHandler) GetAllTasks(c *gin.Context) {
	limit, offset := getPaginationParams(c)
	tasks, err := h.repo.GetAllTasks(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTaskByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("task_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid task ID"})
		return
	}
	task, err := h.repo.GetTaskByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, task)
}

func (h *TaskHandler) GetTasksByUserID(c *gin.Context) {
	var userID uuid.UUID
	userIDParam := c.Param("user_id")

	if userIDParam == "0" {
		userIDFromCtx, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
			return
		}

		userIDStr, ok := userIDFromCtx.(string)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}

		parsedUserID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}

		userID = parsedUserID
	} else {
		parsedUserID, err := uuid.Parse(userIDParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}
		userID = parsedUserID
	}

	limit, offset := getPaginationParams(c)
	tasks, err := h.repo.GetTasksByUserID(userID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByType(c *gin.Context) {
	typeParam := models.TaskType(c.Param("type"))
	limit, offset := getPaginationParams(c)

	tasks, err := h.repo.GetTasksByType(typeParam, nil, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByPriority(c *gin.Context) {
	priority := models.TaskPriority(c.Param("priority"))
	limit, offset := getPaginationParams(c)

	tasks, err := h.repo.GetTasksByPriority(priority, nil, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByStatus(c *gin.Context) {
	status := models.TaskStatus(c.Param("status"))
	limit, offset := getPaginationParams(c)

	tasks, err := h.repo.GetTasksByStatus(status, nil, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByProjectID(c *gin.Context) {
	projectID, err := uuid.Parse(c.Param("project_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
		return
	}
	limit, offset := getPaginationParams(c)

	tasks, err := h.repo.GetTasksByProjectID(projectID, nil, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksSummaryForUser(c *gin.Context) {

	userIDParam := c.Param("userID")
	var userID uuid.UUID
	var err error

	if userIDParam != "" {
		userID, err = uuid.Parse(userIDParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}
	}

	tasks, err := h.repo.GetTasksSummaryForUser(&userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)

}

func (h *TaskHandler) EditTask(c *gin.Context) {
	id, err := uuid.Parse(c.Param("task_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid task ID"})
		return
	}

	var task models.Task
	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task.ID = id
	if err := h.repo.EditTask(&task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "task updated successfully"})
}

func getPaginationParams(c *gin.Context) (limit, offset int) {
	limitStr := c.DefaultQuery("size", "10")
	offsetStr := c.DefaultQuery("page", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 10
	}

	offset, err = strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	return limit, offset
}

func (h *TaskHandler) CreateComment(c *gin.Context) {
	var comment models.Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	taskIDParam := c.Param("task_id")
	taskID, err := uuid.Parse(taskIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid task ID"})
		return
	}
	comment.TaskID = taskID
	comment.CreatedAt = time.Now()

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
		return
	}

	comment.UserID, _ = uuid.Parse(userIDStr)

	if err := h.repo.CreateComment(&comment); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create comment"})
		return
	}

	c.JSON(http.StatusCreated, comment)
}

func (h *TaskHandler) GetCommentsByTaskID(c *gin.Context) {
	taskIDParam := c.Param("task_id")
	taskID, err := uuid.Parse(taskIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid task ID"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	comments, err := h.repo.GetCommentsByTaskID(taskID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch comments"})
		return
	}

	c.JSON(http.StatusOK, comments)
}
