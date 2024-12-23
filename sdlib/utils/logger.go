package utils

import (
	"go.uber.org/zap"
)

var Logger *zap.Logger

func InitLogger(level string) {

	var err error
	if level == "production" {
		Logger, err = zap.NewProduction()
	} else {
		Logger, err = zap.NewDevelopment()
	}

	if err != nil {
		panic("Failed to initialize zap logger: " + err.Error())
	}
}
