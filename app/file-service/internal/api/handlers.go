package api

import (
	"bytes"
	"errors"
	"file-service/internal/models"
	fileservices "file-service/internal/services"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/utils"
	"github.com/gin-contrib/cors"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

type UploadSession struct {
	FileName       string
	FileSize       int64
	ChunkSize      int64
	UploadedChunks map[int]bool // Track received chunks
	TotalChunks    int
	TempDir        string    // Directory for storing temporary chunks
	CreatedAt      time.Time // Timestamp for session creation
}

type ChunkMetadata struct {
	FileName       string
	FileSize       int64
	ChunkSize      int64
	UploadedChunks map[int]bool // Track received chunks
	TotalChunks    int
	TempDir        string
}

var uploadSessions = struct {
	sync.Mutex
	Sessions map[string]*UploadSession
}{
	Sessions: make(map[string]*UploadSession),
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
		AllowOrigins:     []string{"http://localhost:3039"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		ExposeHeaders:    []string{"Content-Length", "Authorization"},
		MaxAge:           12 * time.Hour, // Caching preflight requests
	}))

	// Initialize services with proper error handling
	log.Info("Initializing storage service")
	storageService, err := fileservices.ConnectMinio(cfg.MinIOURL, cfg.MinIOUser, cfg.MinIOPass, log)
	if err != nil {
		log.Fatal("Failed to initialize storage service", zap.Error(err))
	}
	log.Info("Storage service initialized successfully")

	log.Info("Initializing metadata service")
	metadataService := fileservices.NewMetadataService(database.DB, log)
	if metadataService == nil {
		log.Fatal("Failed to initialize metadata service")
	}
	log.Info("Metadata service initialized successfully")

	log.Info("Initialzing permissions service")
	permissionsService := fileservices.NewPermissionsService(database.DB, log)
	if permissionsService == nil {
		log.Fatal("Failed to initialize permissions service")
	}
	log.Info("Permissions service initialized successfully")

	// Load the RSA public key
	log.Info("Loading RSA public key", zap.String("public_key_path", cfg.PublicKeyPath))
	publicKey, err := services.LoadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		//log.Fatal("Error loading RSA public key", zap.Error(err))
	}
	log.Info("RSA public key loaded successfully")

	// Apply middleware
	log.Info("Applying authentication middleware")
	router.Use(fileservices.AuthMiddleware(publicKey, log))

	// Define /metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Define routes
	log.Info("Defining routes")
	router.POST("/api/v1/files/upload", func(c *gin.Context) {
		log.Info("Handling /upload request", zap.String("method", c.Request.Method))
		singleFileUploadHandler(c, storageService, metadataService, log)
	})

	router.GET("/api/v1/files/list", func(c *gin.Context) {
		log.Info("Handling /list request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		fileslisterHandler(c, metadataService, log)
	})

	router.GET("/api/v1/files/listshared", func(c *gin.Context) {
		log.Info("Handling /list request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		sharedfileslisterHandler(c, metadataService, permissionsService, log)
	})

	router.DELETE("/api/v1/files/:fileID", func(c *gin.Context) {
		log.Info("Handling /delete request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		singleFileDeleteHandler(c, metadataService, log)
	})

	router.PUT("/api/v1/files/restore/:fileID", func(c *gin.Context) {
		log.Info("Handling /restore request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		restoreFileHandler(c, metadataService, log)
	})

	var ws = fileservices.NewWebSocketServer(log)

	router.GET("/api/v1/files/ws-connection", func(c *gin.Context) {
		ws.HandleConnection(c, publicKey)
	})

	router.GET("/api/v1/files/download/:fileID", func(c *gin.Context) {
		log.Info("Handling /download request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		downloadFileHandler(c, metadataService, permissionsService, storageService)
	})

	router.POST("/api/v1/files/share", func(c *gin.Context) {
		log.Info("Handler /share request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		shareFileHandler(c, metadataService, permissionsService, log)

	})

	// Start the server
	port := cfg.ServerPort
	log.Info("Starting server", zap.String("port", port))
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server", zap.Error(err))
	}
}

func downloadFileHandler(c *gin.Context, metadata *fileservices.MetadataService, permissions *fileservices.PermissionsService, storageService *fileservices.StorageService) {
	bucketName := "files" // c.Param("bucket")
	fileID := c.Param("fileID")

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}
	isAllowed, err := permissions.IsActionAllowed(fileID, userIDStr, models.PermissionRead)
	if err != nil || !isAllowed {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	file, err := metadata.GetFilesByID([]string{fileID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download file: " + err.Error()})
		return
	}

	// Get the file and its content type
	object, contentType, err := storageService.GetFileObject(bucketName, fileID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download file: " + err.Error()})
		return
	}
	defer object.Close()

	// Set appropriate headers for binary file download
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(fileID))
	c.Header("Content-Type", contentType)
	c.Header("Content-Transfer-Encoding", "binary") // Ensures the content is treated as binary

	c.JSON(http.StatusFound, gin.H{
		"Name":       file[0].FileName,
		"Size":       file[0].Size,
		"CreatedBy":  file[0].CreatedBy,
		"CreatedAt":  file[0].CreatedAt,
		"Version":    file[0].VersionID,
		"Permission": "Read",
	})
}

func listFileVersionsHandler(c *gin.Context, storage *fileservices.StorageService) {
	bucketName := c.Param("bucket")
	fileName := c.Param("file")

	versions, err := storage.ListFileVersions(bucketName, fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list file versions: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, versions)
}

func singleFileUploadHandler(c *gin.Context, storage *fileservices.StorageService, metadata *fileservices.MetadataService, log *zap.Logger) {
	startTime := time.Now()

	bodyBytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.Error("Failed to read request body", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Restore the request body so it can be read again by the Gin context
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Log the request headers and body
	log.Info("Received upload request",
		zap.String("user id", userIDStr),
		zap.String("method", c.Request.Method),
		zap.String("url", c.Request.RequestURI),
		zap.String("clientIP", c.ClientIP()),
		zap.String("headers", fmt.Sprintf("%v", c.Request.Header)),
	)
	const maxFileSize = 100 * 1024 * 1024 // 10MB in bytes
	// Parse multipart form data
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	// Get files from the form data
	files := form.File["files"] // "files" is the name attribute in the React file input
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No files uploaded"})
		return
	}

	type uploadedFile struct {
		Size int64
		Name string
		ID   string
	}

	var uploadedFiles []uploadedFile

	for _, file := range files {
		// Check file size
		if file.Size > maxFileSize {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("File %s is too large. Max allowed size is 10MB", file.Filename),
			})
			return
		}

		// Open the file
		fileContent, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to open file"})
			return
		}
		defer fileContent.Close()

		fileID := uuid.New().String()

		// Upload file to MinIO
		objectName := fmt.Sprintf("%d_%s", time.Now().UnixNano(), file.Filename)
		fileID, fileVersion, err := storage.UploadFile(fileContent, fileID, file.Filename, "application/octet-stream")
		if err != nil {
			log.Error("Failed to upload merged file to MinIO", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file to storage"})
			return
		}

		log.Info("Merged file uploaded successfully", zap.String("fileID", fileID), zap.String("file version", fileVersion))

		// Save metadata
		err = metadata.SaveFileMetadata(userIDStr, fileID, file.Filename, fileVersion, file.Size)
		if err != nil {
			log.Error("Failed to save file metadata", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file metadata"})
			return
		}

		uploadedFiles = append(uploadedFiles, uploadedFile{file.Size, objectName, fileID})

		// Log and respond
		duration := time.Since(startTime)
		log.Info("File upload in MINIO and assembly process completed ",
			zap.String("file name", file.Filename),
			zap.String("file ID", fileID),
			zap.String("file version", fileVersion),
			zap.Duration("duration", duration),
		)
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"message":       "Files uploaded successfully",
		"uploadedFiles": uploadedFiles,
	})
}

func fileslisterHandler(c *gin.Context, metadata *fileservices.MetadataService, log *zap.Logger) {
	// Step 1: Extract the token from the Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Error("Authorization header is missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
		return
	}

	// The token is usually in the format "Bearer <token>"
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader { // "Bearer " was not in the header
		log.Error("Authorization header format is invalid")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format is invalid"})
		return
	}

	// Extract the userID from the token claims
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Step 3: Fetch files for the user from the database
	files, err := metadata.GetFilesByUserID(userIDStr)
	if err != nil {
		log.Error("Failed to fetch files", zap.String("userID", userIDStr), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve files"})
		return
	}

	// Step 4: Return the list of files in the response
	log.Info("Files retrieved successfully", zap.String("userID", userIDStr), zap.Int("fileCount", len(files)))
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func sharedfileslisterHandler(c *gin.Context, metadata *fileservices.MetadataService, permissions *fileservices.PermissionsService, log *zap.Logger) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Error("Authorization header is missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
		return
	}

	// The token is usually in the format "Bearer <token>"
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader { // "Bearer " was not in the header
		log.Error("Authorization header format is invalid")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format is invalid"})
		return
	}

	// Extract the userID from the token claims
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Step 3: Fetch files for the user from the database
	filesIDs, err := permissions.GetSharedFilesByUserID(userIDStr, models.PermissionRead)
	if err != nil {
		log.Error("Failed to fetch files", zap.String("userID", userIDStr), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve files"})
		return
	}

	files, err := metadata.GetFilesByID(filesIDs)
	if err != nil {
		log.Error("Failed to fetch files", zap.String("userID", userIDStr), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve files"})
		return
	}

	// Step 4: Return the list of files in the response
	log.Info("Files retrieved successfully", zap.String("userID", userIDStr), zap.Int("fileCount", len(files)))
	c.JSON(http.StatusOK, gin.H{"files": files})

}

func singleFileDeleteHandler(c *gin.Context, metadata *fileservices.MetadataService, log *zap.Logger) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Error("Authorization header is missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
		return
	}

	// The token is usually in the format "Bearer <token>"
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader { // "Bearer " was not in the header
		log.Error("Authorization header format is invalid")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format is invalid"})
		return
	}

	// Extract the userID from the token claims
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	fileID := c.Param("fileID") // Get fileID from URL parameter

	// Step 3: Fetch files for the user from the database
	err := metadata.DeleteFileMetadata(userIDStr, fileID, "fileVersion")
	if err != nil {
		log.Error("Failed to fetch files", zap.String("userID", userIDStr), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve files"})
		return
	}

}

func shareFileHandler(c *gin.Context, metadata *fileservices.MetadataService, permissions *fileservices.PermissionsService, log *zap.Logger) {

	type ShareFile struct {
		FileID          string `json:"file_id"`
		SharedWithEmail string `json:"shared_with_email"`
	}

	var req ShareFile
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Logger.Error("Invalid request payload", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return

	}

	fileID := req.FileID
	sharedWithEmail := req.SharedWithEmail

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	// Lets first check if the userid is the creator of the file through the metadata
	files, err := metadata.GetFilesByID([]string{fileID})
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Error("Authorization header is missing")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}
	}

	if len(files) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Permission denied for selected file"})
		return
	}

	if files[0].CreatedBy == userID {
		err := permissions.AddNewPermission(fileID, userIDStr, sharedWithEmail, models.PermissionRead)
		if err == nil {
			c.JSON(http.StatusAccepted, gin.H{"msg": "File shared successfully"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error" + err.Error()})
		}
		return
	}

	// anyone with write permission can also share the file, so check the permission = write for userid/fileid
	isAllowed, err := permissions.IsActionAllowed(fileID, userIDStr, models.PermissionRead)
	if err != nil || !isAllowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "You dont have permission to download the file"})
		return
	}

	// if all okay, lets add a new line to permissions table
	if files[0].CreatedBy == userIDStr || isAllowed || files[0].CreatedBy == userID {
		err := permissions.AddNewPermission(fileID, userIDStr, sharedWithEmail, models.PermissionRead)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error" + err.Error()})
		}
	} else {
		c.JSON(http.StatusForbidden, gin.H{"error": "You dont have the permission to share this folder"})
	}

}

func restoreFileHandler(c *gin.Context, metadata *fileservices.MetadataService, log *zap.Logger) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Error("Authorization header is missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
		return
	}

	// The token is usually in the format "Bearer <token>"
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader { // "Bearer " was not in the header
		log.Error("Authorization header format is invalid")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format is invalid"})
		return
	}

	// Extract the userID from the token claims
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID not found in context"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "UserID is not of type string"})
		return
	}

	fileID := c.Param("fileID") // Get fileID from URL parameter

	// Step 3: Fetch files for the user from the database
	err := metadata.RestoreFile(fileID, userIDStr)
	if err != nil {
		log.Error("Failed to fetch files", zap.String("userID", userIDStr), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve files"})
		return
	}
}
