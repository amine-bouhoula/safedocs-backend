package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
)

// LoadPublicKey loads an RSA public key from a PEM-encoded file.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	// Read the PEM file
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key PEM format")
	}

	// Parse the key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Assert the key is an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPubKey, nil
}

// Function to validate the JWT
func ValidateToken(tokenString string, publicKey *rsa.PublicKey) (*jwt.Token, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
