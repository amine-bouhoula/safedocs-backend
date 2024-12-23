package services

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/amine-bouhoula/safedocs-mvp/sdlib/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins for now (can be restricted for security)
		return true
	},
}

type WebSocketConnection struct {
	conn      *websocket.Conn
	mutex     sync.Mutex
	userID    string
	lastPing  time.Time
	closeChan chan struct{}
}

type WebSocketServer struct {
	connections map[string]*WebSocketConnection
	mutex       sync.Mutex
	logger      *zap.Logger
}

func NewWebSocketServer(logger *zap.Logger) *WebSocketServer {
	return &WebSocketServer{
		connections: make(map[string]*WebSocketConnection),
		logger:      logger,
	}
}

// Token validation function
func validateToken(tokenString string) (*jwt.Token, error) {
	// Replace with your token validation logic
	// For example, using a HMAC secret key
	secretKey := []byte("your_secret_key")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token method conforms to expected signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Additional validation can be added here (e.g., token expiration)

	return token, nil
}

// Handle new WebSocket connection
func (ws *WebSocketServer) HandleConnection(c *gin.Context, publicKey *rsa.PublicKey) {
	// Extract the token from the query parameters
	tokenString := c.Query("token")
	if tokenString == "" {
		ws.logger.Error("Token is missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is required"})
		return
	}

	// Validate the token
	token, err := services.ValidateToken(tokenString, publicKey)
	if err != nil {
		ws.logger.Error("Token validation failed",
			zap.String("client_ip", c.ClientIP()),
			zap.String("token", tokenString),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized", "message": err.Error()})
		return
	}

	// Extract userID from token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		ws.logger.Error("Failed to extract claims from token")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to extract claims from token"})
		return
	}

	userID, ok := claims["userID"].(string)
	if !ok {
		ws.logger.Error("userID not found in token claims")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "userID not found in token"})
		return
	}

	// Upgrade the HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		ws.logger.Error("Failed to upgrade HTTP connection to WebSocket", zap.Error(err))
		return
	}

	ws.logger.Info("New WebSocket connection", zap.String("userID", userID))

	// Create a new WebSocketConnection object
	connection := &WebSocketConnection{
		conn:      conn,
		userID:    userID,
		lastPing:  time.Now(),
		closeChan: make(chan struct{}),
	}

	// Register connection
	ws.mutex.Lock()
	ws.connections[userID] = connection
	ws.mutex.Unlock()

	// Start a goroutine to handle incoming messages from this connection
	go ws.handleMessages(connection)

	// Start pinging the connection every 30 seconds to keep it alive
	go ws.keepConnectionAlive(connection)
}

// Handle incoming messages from WebSocket connection
func (ws *WebSocketServer) handleMessages(connection *WebSocketConnection) {
	defer func() {
		// Cleanup when the connection is closed
		ws.mutex.Lock()
		delete(ws.connections, connection.userID)
		ws.mutex.Unlock()
		connection.conn.Close()
	}()

	for {
		// Read messages from the connection
		_, message, err := connection.conn.ReadMessage()
		if err != nil {
			if err != websocket.ErrCloseSent {
				ws.logger.Error("Failed to read message", zap.Error(err))
			}
			return
		}

		// Log and process the message (custom logic can go here)
		ws.logger.Info("Received WebSocket message", zap.String("userID", connection.userID), zap.String("message", string(message)))
	}
}

// Keep the WebSocket connection alive by periodically sending ping messages
func (ws *WebSocketServer) keepConnectionAlive(connection *WebSocketConnection) {
	for {
		select {
		case <-time.After(30 * time.Second):
			// Send a ping message to keep the connection alive
			if err := connection.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				ws.logger.Error("Failed to send ping", zap.Error(err))
				return
			}
		case <-connection.closeChan:
			// If the connection is closed, stop pinging
			return
		}
	}
}

// Close the WebSocket connection
func (ws *WebSocketServer) CloseConnection(userID string) {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()

	if connection, exists := ws.connections[userID]; exists {
		connection.conn.Close()
		close(connection.closeChan)
		delete(ws.connections, userID)
		ws.logger.Info("WebSocket connection closed", zap.String("userID", userID))
	}
}
