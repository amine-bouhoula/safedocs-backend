#!/bin/bash

# Configuration
FILE="$1"                                # Input file (passed as the first argument)
JWT_TOKEN="$2"                           # JWT token (passed as the second argument)
SERVER_URL="http://localhost:8001/upload" # Backend URL for uploads
CHUNK_SIZE="5M"                          # Chunk size (e.g., 5M for 5 MB)

# Ensure file and token are provided
if [ -z "$FILE" ] || [ -z "$JWT_TOKEN" ]; then
  echo "Usage: $0 <file> <jwt_token>"
  exit 1
fi

# Ensure the file exists
if [ ! -f "$FILE" ]; then
  echo "File not found: $FILE"
  exit 1
fi

# Split the file into chunks
echo "Splitting file into chunks of size $CHUNK_SIZE..."
split -b "$CHUNK_SIZE" "$FILE" chunk_

# Count total chunks
TOTAL_CHUNKS=$(ls chunk_* | wc -l)
echo "Total chunks created: $TOTAL_CHUNKS"

# Upload each chunk
INDEX=0
for CHUNK in chunk_*; do
  echo "Uploading chunk $INDEX of $TOTAL_CHUNKS (${CHUNK})..."

  # Send the chunk using curl
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SERVER_URL" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -F "file=@${CHUNK}" \
    -F "chunkIndex=${INDEX}" \
    -F "totalChunks=${TOTAL_CHUNKS}" \
    -F "fileName=$(basename "$FILE")")

  # Check response
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

echo "Upload completed successfully!"

