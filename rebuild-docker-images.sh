#!/bin/bash

# Services to manage
SERVICES="loki nginx_exporter rabbitmq postgres_db auth-service \
          file-service nginx postgres_exporter promtail minio prometheus redis grafana"

# Docker Compose files
COMPOSE_FILES="-f docker-compose.yml \
               -f db/docker-compose.db.yml \
               -f cache/docker-compose.cache.yml \
               -f app/docker-compose.backend.yml"
#               -f gateway/docker-compose.nginx.yml \
#               -f monitoring/docker-compose.monitoring.yml"


# Determine if sudo is needed
SUDO=""
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
fi

# Function to stop containers
stop_containers() {
    echo "Stopping containers..."
    $SUDO docker compose $COMPOSE_FILES stop
}

# Function to bring down Docker Compose
docker_down() {
    echo "Bringing down Docker Compose..."
    $SUDO docker compose $COMPOSE_FILES down
}

# Function to rebuild containers
docker_build() {
    echo "Rebuilding containers..."
    $SUDO docker compose $COMPOSE_FILES build --no-cache
}

# Function to bring up Docker Compose
docker_up() {
    echo "Generating RSA keys..."
    ./keys/generate_keys.sh

    echo "Bringing up Docker Compose..."
    $SUDO docker compose $COMPOSE_FILES up -d
}

# Function to perform all actions sequentially
all() {
    docker_down
    docker_build
    docker_up
}

# Menu for user to select an action
case $1 in
    stop)
        stop_containers
        ;;
    down)
        docker_down
        ;;
    build)
        docker_build
        ;;
    up)
        docker_up
        ;;
    all)
        all
        ;;
    help)
        echo "Usage: $0 {stop|down|build|up|all|help}"
        echo "Commands:"
        echo "  stop   - Stop containers"
        echo "  down   - Bring down Docker Compose"
        echo "  build  - Rebuild images"
        echo "  up     - Bring up Docker Compose"
        echo "  all    - Perform down, build, and up"
        echo "  help   - Show this help message"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information."
        exit 1
        ;;
esac
