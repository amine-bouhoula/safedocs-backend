package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	ServerPort    string
	DatabaseURL   string
	RedisURL      string
	MinIOURL      string
	MinIOUser     string
	MinIOPass     string
	LogLevel      string
	PublicKeyPath string
}

func LoadConfig() (*Config, error) {

	fmt.Println("Reading config file .env")

	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	cfg := &Config{
		ServerPort:    viper.GetString("SERVER_PORT"),
		DatabaseURL:   viper.GetString("DATABASE_URL"),
		RedisURL:      viper.GetString("REDIS_URL"),
		MinIOURL:      viper.GetString("MINIO_URL"),
		MinIOUser:     viper.GetString("MINIO_USER"),
		MinIOPass:     viper.GetString("MINIO_PASS"),
		LogLevel:      viper.GetString("LOG_LEVEL"),
		PublicKeyPath: viper.GetString("PUBLIC_KEY_PATH"),
	}
	return cfg, nil
}
