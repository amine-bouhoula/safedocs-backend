# Build stage
FROM golang:1.22 AS builder
WORKDIR /app
COPY . . 

# Run Tests Before Build
#RUN go test ./tests/... -v


RUN go mod tidy                 # Install dependencies
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o auth-service ./cmd/main.go

#RUN go build -o main .          # Build the Go binary named 'main'

# Run stage
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/auth-service .
COPY --from=builder /app/cmd/.env .

RUN mkdir -p /keys
COPY ./keys/private_key.pem /keys/private_key.pem
RUN chmod 600 /keys/private_key.pem

RUN chmod +x auth-service
EXPOSE 8002
CMD ["./auth-service"]
