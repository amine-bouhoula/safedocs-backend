package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SaveToken - Saves the refresh token to Redis
func SaveToken(rdb *redis.Client, userID, token string, ttl time.Duration) error {
	ctx := context.Background()
	err := rdb.Set(ctx, userID, token, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	return nil
}

// GetToken - Retrieves the refresh token from Redis
func GetToken(rdb *redis.Client, userID string) (string, error) {
	ctx := context.Background()
	token, err := rdb.Get(ctx, userID).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("token not found")
	} else if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return token, nil
}

// DeleteToken - Deletes the token from Redis
func DeleteToken(rdb *redis.Client, userID string) error {
	ctx := context.Background()
	err := rdb.Del(ctx, userID).Err()
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	return nil
}
