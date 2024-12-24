package utils

import (
	"auth-service/models"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("your_secret_key")

func GenerateToken(username string) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
}

func GenerateInternalJWT(user models.User, roles []string, privateKeyPEM []byte) (string, error) {
	log.Println("Starting GenerateInternalJWT...")
	log.Printf("Received userID: %s", user.ID)
	log.Printf("Roles: %v", roles)

	// Attempt to parse the private key
	log.Println("Parsing private key...")
	privateKey, err := ParsePrivateKey(privateKeyPEM)
	if err != nil {
		log.Printf("Failed to parse private key: %v", err)
		return "", err
	}
	log.Println("Private key successfully parsed.")

	// Log token claims
	claims := jwt.MapClaims{
		"userID": user.ID,
		"name":   user.Username,
		"email":  user.Email,
		"roles":  roles,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
		"iss":    "auth-service",
		"aud":    "file-service",
	}
	log.Printf("Generated claims: %+v", claims)

	// Create a new token
	log.Println("Creating new JWT...")
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if token == nil {
		log.Println("Failed to create JWT token.")
		return "", jwt.NewValidationError("token creation failed", jwt.ValidationErrorClaimsInvalid)
	}
	log.Println("JWT token created successfully.")

	// Sign the token with the private key
	log.Println("Signing the token...")
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Printf("Failed to sign the token: %v", err)
		return "", err
	}
	log.Println("Token signed successfully.")

	// Return the signed token
	log.Println("Returning the signed token.")
	return signedToken, nil
}

// LoadPrivateKey loads an RSA private key from a PEM file.
func LoadPrivateKey(privateKeyPath string) ([]byte, error) {
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	return privateKeyPEM, nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key.
func ParsePrivateKey(pemKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}

	// PKCS#1 (Traditional RSA)
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// PKCS#8 (Modern format)
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return rsaKey, nil
	}

	return nil, errors.New("unsupported key type")
}

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
