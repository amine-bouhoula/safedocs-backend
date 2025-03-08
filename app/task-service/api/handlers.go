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
	router.GET("/api/v1/tasks/:taskid", taskHandler.GetTaskByID)
	router.GET("/api/v1/tasks/user/:user_id", taskHandler.GetTasksByUserID)
	router.GET("/api/v1/tasks/type/:type", taskHandler.GetTasksByType) // New route added
	router.GET("/api/v1/tasks/priority/:priority", taskHandler.GetTasksByPriority)
	router.GET("/api/v1/tasks/status/:status", taskHandler.GetTasksByStatus)
	router.GET("/api/v1/tasks/company/:company_id", taskHandler.GetTasksByCompanyID)

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

	task := &models.Task{
		ID:          uuid.New(),
		Title:       taskDTO.Title,
		Description: taskDTO.Description,
		CompanyID:   taskDTO.CompanyID,
		Type:        taskDTO.Type,
	}

	if err := h.repo.CreateTask(task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, task)
}

func (h *TaskHandler) GetTaskByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
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
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
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
	tasks, err := h.repo.GetTasksByType(typeParam, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByPriority(c *gin.Context) {
	priority := models.TaskPriority(c.Param("priority"))
	limit, offset := getPaginationParams(c)
	tasks, err := h.repo.GetTasksByPriority(priority, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByStatus(c *gin.Context) {
	status := models.TaskStatus(c.Param("status"))
	limit, offset := getPaginationParams(c)
	tasks, err := h.repo.GetTasksByStatus(status, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func (h *TaskHandler) GetTasksByCompanyID(c *gin.Context) {
	companyID, err := uuid.Parse(c.Param("company_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid company ID"})
		return
	}
	limit, offset := getPaginationParams(c)
	tasks, err := h.repo.GetTasksByCompanyID(companyID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tasks)
}

func getPaginationParams(c *gin.Context) (limit, offset int) {
	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

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
