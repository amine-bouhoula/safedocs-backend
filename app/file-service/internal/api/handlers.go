package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	fileservices "file-service/internal/services"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/config"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/database"
	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	"github.com/gin-contrib/cors"
	"github.com/google/uuid"

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

	router.POST("/api/v1/files/start-upload", func(c *gin.Context) {
		startUpload(c, log)
	})

	// Define routes
	log.Info("Defining routes")
	router.POST("/api/v1/files/upload", func(c *gin.Context) {
		log.Info("Handling /upload request", zap.String("method", c.Request.Method))
		singleFileUploadHandler(c, storageService, metadataService, log)
	})

	router.GET("/api/v1/files/list", func(c *gin.Context) {
		log.Info("Handling /download request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		fileslisterHandler(c, metadataService, log)
	})

	router.DELETE("/api/v1/files/:fileID", func(c *gin.Context) {
		log.Info("Handling /delete request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		singleFileDeleteHandler(c, metadataService, log)
	})

	var ws = fileservices.NewWebSocketServer(log)

	router.GET("/api/v1/files/ws-connection", func(c *gin.Context) {
		ws.HandleConnection(c, publicKey)
	})

	router.GET("/api/v1/files/download/:bucket/:file", func(c *gin.Context) {
		log.Info("Handling /download request", zap.String("method", c.Request.Method), zap.String("path", c.Request.URL.Path))
		downloadFileHandler(c, storageService)
	})

	// Start the server
	port := cfg.ServerPort
	log.Info("Starting server", zap.String("port", port))
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server", zap.Error(err))
	}
}

func downloadFileHandler(c *gin.Context, storageService *fileservices.StorageService) {
	bucketName := c.Param("bucket")
	fileName := c.Param("file")

	// Get the file and its content type
	object, contentType, err := storageService.GetFile(bucketName, fileName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to download file: " + err.Error()})
		return
	}
	defer object.Close()

	// Set appropriate headers
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(fileName))
	c.Header("Content-Type", contentType)

	// Stream the object directly to the response
	_, err = io.Copy(c.Writer, object)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stream file: " + err.Error()})
		return
	}
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

// StartUpload initializes an upload session
func startUpload(c *gin.Context, log *zap.Logger) {
	var request []struct {
		FileName  string `json:"fileName"`
		FileSize  int64  `json:"fileSize"`
		ChunkSize int64  `json:"chunkSize"`
	}

	log.Info("Received request to start multiple upload sessions", zap.String("clientIP", c.ClientIP()))

	// Parse request body
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Error("Failed to parse request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Initialize response
	uploadResponses := []map[string]interface{}{}

	for _, file := range request {
		// Validate fileName and fileSize
		if file.FileName == "" || file.FileSize <= 0 {
			log.Error("Invalid fileName or fileSize",
				zap.String("fileName", file.FileName),
				zap.Int64("fileSize", file.FileSize))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid fileName or fileSize"})
			return
		}

		// Default chunk size to 5MB if not provided
		if file.ChunkSize <= 0 {
			file.ChunkSize = 5 * 1024 * 1024 // 5MB
			log.Info("Default chunk size applied", zap.Int64("chunkSize", file.ChunkSize))
		}

		// Generate a unique upload session ID
		uploadSessionId := generateSessionID()
		log.Info("Generated unique upload session ID", zap.String("uploadSessionId", uploadSessionId))

		// Create a new upload session
		uploadSession := &UploadSession{
			FileName:       file.FileName,
			FileSize:       file.FileSize,
			ChunkSize:      file.ChunkSize,
			UploadedChunks: make(map[int]bool),
			CreatedAt:      time.Now(),
		}

		// Store the session in memory
		uploadSessions.Lock()
		uploadSessions.Sessions[uploadSessionId] = uploadSession
		uploadSessions.Unlock()
		log.Info("Upload session created successfully",
			zap.String("uploadSessionId", uploadSessionId),
			zap.String("fileName", file.FileName),
			zap.Int64("fileSize", file.FileSize),
			zap.Int64("chunkSize", file.ChunkSize),
		)

		// Add the session details to the response
		uploadResponses = append(uploadResponses, map[string]interface{}{
			"uploadSessionId": uploadSessionId,
			"fileName":        file.FileName,
			"chunkSize":       file.ChunkSize,
		})
	}

	// Respond with all session IDs and chunk sizes
	c.JSON(http.StatusOK, gin.H{
		"uploadSessions": uploadResponses,
	})
	log.Info("Response sent successfully", zap.Int("uploadSessionCount", len(uploadResponses)))
}

// Helper function to generate a random session ID
func generateSessionID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
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

	var uploadedFiles []string

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
		fileSizeStr := c.PostForm("fileSize")

		var multiplier int64
		if strings.HasSuffix(fileSizeStr, "MB") {
			multiplier = 1 // File size is already in MB
			fileSizeStr = strings.TrimSuffix(fileSizeStr, "MB")
		} else if strings.HasSuffix(fileSizeStr, "GB") {
			multiplier = 1024 // 1 GB = 1024 MB
			fileSizeStr = strings.TrimSuffix(fileSizeStr, "GB")
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid file size. Must end with 'MB' or 'GB'.",
			})
			return
		}

		// Parse the numeric part of the file size
		fileSizeNumber, err := strconv.ParseFloat(fileSizeStr, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid file size. Must be a valid number.",
			})
			return
		}

		// Convert megabytes to bytes
		fileSizeBytes := int64(fileSizeNumber*1024*1024) * multiplier

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
		err = metadata.SaveFileMetadata(userIDStr, fileID, file.Filename, fileVersion, fileSizeBytes)
		if err != nil {
			log.Error("Failed to save file metadata", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file metadata"})
			return
		}

		uploadedFiles = append(uploadedFiles, objectName)

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
