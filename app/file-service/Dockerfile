# Step 1: Use an official Golang image as a builder
FROM golang:1.22 as builder
# Set the working directory inside the container
WORKDIR /app
# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./
# Download and cache dependencies
RUN go mod download
# Copy the source code
COPY . .
# Build the Go application
#RUN go build -o file-service ./cmd/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o file-service ./cmd/main.go


# Step 2: Use a smaller base image for the runtime
FROM alpine:latest
# Install certificates for HTTPS (required for MinIO and PostgreSQL)
RUN apk --no-cache add ca-certificates
# Set the working directory inside the container
WORKDIR /app
# Copy the binary from the builder stage
COPY --from=builder /app/file-service .
COPY --from=builder /app/cmd/.env .

RUN mkdir -p /keys
COPY ./keys/public_key.pem /keys/public_key.pem
RUN chmod 600 /keys/public_key.pem

# Add OpenSSL and copy the key generation script
#RUN apk add --no-cache openssl
#COPY scripts/generate_keys.sh /scripts/generate_keys.sh
# Make the script executable
#RUN chmod +x /scripts/generate_keys.sh

# Run the script during container startup
#CMD ["/scripts/generate_keys.sh"]

# Expose the application's port
EXPOSE 8080
# Run the binary
ENTRYPOINT ["./file-service"]
