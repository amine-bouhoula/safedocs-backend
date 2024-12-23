#!/bin/bash

# Configuration
LOGIN_URL="http://localhost:8000/login"     # Endpoint for login
INIT_UPLOAD_URL="http://localhost:8001/start-upload" # Endpoint for start-upload
START_UPLOAD_URL="http://localhost:8001/upload" # Endpoint for start-upload
USERNAME="user"                   # Replace with your username
PASSWORD="password"                   # Replace with your password
CHUNK_SIZE=$((1024 * 1024 * 100))                         # Chunk size in bytes (5MB)

# Ensure a file path is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <file_path>"
  exit 1
fi

FILE_PATH="$1"

# Ensure the file exists
if [ ! -f "$FILE_PATH" ]; then
  echo "File not found: $FILE_PATH"
  exit 1
fi

# Get the file name and size
FILE_NAME=$(basename "$FILE_PATH")
FILE_SIZE=$(stat -c%s "$FILE_PATH") # For Linux. Use `stat -f%z "$FILE_PATH"` on macOS.

echo "File details:"
echo "  File Name: $FILE_NAME"
echo "  File Size: $FILE_SIZE bytes"

# Login and retrieve the token
echo "Sending login request..."
LOGIN_RESPONSE=$(curl -s -X POST "$LOGIN_URL" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME\", \"password\": \"$PASSWORD\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "Failed to retrieve token. Debugging information:"
  echo "  Login Response: $LOGIN_RESPONSE"
  echo "  Expected field 'token' was missing or null."
  exit 1
fi

echo "Token retrieved: $TOKEN"

# Call the /start-upload endpoint
echo "Starting upload session..."
UPLOAD_RESPONSE=$(curl -s -X POST "$INIT_UPLOAD_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
        \"fileName\": \"$FILE_NAME\",
        \"fileSize\": $FILE_SIZE,
        \"chunkSize\": $CHUNK_SIZE
      }")

echo "Response from /start-upload:"
# Extract and output the session ID
SESSION_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.uploadSessionId')

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" == "null" ]; then
  echo "Failed to retrieve session ID. Response: $UPLOAD_RESPONSE"
  exit 1
fi

echo "Session ID: $SESSION_ID"

# Ensure the file exists
if [ ! -f "$FILE_PATH" ]; then
  echo "File not found: $FILE_PATH"
  exit 1
fi

# Get file size and name
FILE_NAME=$(basename "$FILE_PATH")
FILE_SIZE=$(stat -c%s "$FILE_PATH") # For Linux. Use `stat -f%z "$FILE_PATH"` on macOS.

# Calculate total chunks
TOTAL_CHUNKS=$(( (FILE_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE )) # Ceiling division

echo "Uploading file: $FILE_NAME"
echo "File size: $FILE_SIZE bytes"
echo "Chunk size: $CHUNK_SIZE bytes"
echo "Total chunks: $TOTAL_CHUNKS"

# Split the file into chunks
echo "Splitting file into chunks..."
split -b "$CHUNK_SIZE" "$FILE_PATH" chunk_

#FILE_ID="6c399110-8964-4117-8773-b97a8f5ad899"

# Upload each chunk
INDEX=0
for CHUNK in chunk_*; do
  echo "Uploading chunk $INDEX of $TOTAL_CHUNKS (${CHUNK})..."

  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$START_UPLOAD_URL" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@${CHUNK}" \
    -F "uploadSessionId=${SESSION_ID}" \
    -F "chunkIndex=${INDEX}" \
    -F "totalChunks=${TOTAL_CHUNKS}" \
    -F "fileName=${FILE_NAME}" \
    -F "fileID=${FILE_ID}")

  if [ "$RESPONSE" -ne 200 ]; then
    echo "Error uploading chunk $INDEX. Server responded with HTTP $RESPONSE."
    exit 1
  fi

  echo "Chunk $INDEX uploaded successfully."
  INDEX=$((INDEX + 1))
done

# Cleanup: Remove temporary chunks
echo "Cleaning up temporary chunks..."
rm -f chunk_*

echo "File upload completed successfully!"