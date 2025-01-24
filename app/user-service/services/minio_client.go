package services

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

type StorageService struct {
	client *minio.Client
	logger *zap.Logger
	bucket string
}

func EnableVersioning(client *minio.Client, bucketName string) error {
	ctx := context.Background()
	return client.EnableVersioning(ctx, bucketName)
}

func InitBucketHandler(client *minio.Client, bucketName string) error {

	ctx := context.Background()

	// Check if the bucket exists
	exists, err := client.BucketExists(ctx, bucketName)
	if err != nil {
		return fmt.Errorf("error checking if bucket exists: %w", err)
	}

	// Create the bucket if it doesn't exist
	if !exists {
		err = client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
		if err != nil {
			return fmt.Errorf("error creating bucket: %w", err)
		}
		log.Printf("Bucket %s created successfully", bucketName)
	} else {
		log.Printf("Bucket %s already exists", bucketName)
	}

	return nil
}

func ConnectMinio(endpoint, accessKey, secretKey string, log *zap.Logger) (*StorageService, error) {

	// Initialize MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false, // Use true if using HTTPS
	})
	if err != nil {
		log.Fatal("Failed to initialize MinIO client", zap.Error(err))
		return nil, err
	}

	log.Info("MinIO client initialized", zap.String("endpoint", endpoint))

	err = InitBucketHandler(client, "files")
	if err != nil {
		log.Fatal("Failed to create/access bucket name", zap.Error(err))
		return nil, err
	}

	err = EnableVersioning(client, "files")
	if err != nil {
		log.Fatal("Failed to enable versioning in Minio")
		return nil, err
	}

	return &StorageService{client: client, logger: log, bucket: "userprofilepictures"}, nil
}

func (s *StorageService) UploadFile(file io.Reader, contentType string) (string, string, error) {

	imageID := uuid.New().String() + ".jpg"

	// Upload the file using the provided or generated fileID
	_, err := s.client.PutObject(context.Background(), s.bucket, imageID, file, -1, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		s.logger.Error("Failed to upload profile picture", zap.String("fileID", imageID), zap.Error(err))
		return "", "", err
	}

	publicURL := fmt.Sprintf("http://192.168.1.19:9000/%s/%s", s.bucket, imageID)
	// Log success with the version ID
	s.logger.Info("File uploaded successfully",
		zap.String("imageID", imageID),
		zap.String("Image shareable link", publicURL),
	)

	return imageID, publicURL, nil
}

func (s *StorageService) GetFileObject(bucketName, objectName string) (*minio.Object, string, error) {
	ctx := context.Background()

	// Retrieve the object
	object, err := s.client.GetObject(ctx, bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, "", err
	}

	// Retrieve metadata for content type
	statInfo, err := s.client.StatObject(ctx, bucketName, objectName, minio.StatObjectOptions{})
	if err != nil {
		return nil, "", err
	}

	// Return the object and its content type
	return object, statInfo.ContentType, nil
}

func (s *StorageService) GetFileVersion(bucketName, objectName, versionID string) (*minio.Object, error) {
	opts := minio.GetObjectOptions{}
	opts.VersionID = versionID

	return s.client.GetObject(context.Background(), bucketName, objectName, opts)
}

func (s *StorageService) ListFileVersions(bucketName, objectName string) ([]minio.ObjectInfo, error) {
	var versions []minio.ObjectInfo
	ctx := context.Background()

	// List all versions of the object
	opts := minio.ListObjectsOptions{
		Prefix:       objectName,
		Recursive:    true,
		WithVersions: true,
	}
	for object := range s.client.ListObjects(ctx, bucketName, opts) {
		if object.Err != nil {
			return nil, object.Err
		}
		versions = append(versions, object)
	}
	return versions, nil
}
