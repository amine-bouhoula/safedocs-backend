#!/bin/sh

# Ensure all required directories exist and are writable
REQUIRED_DIRS="/tmp/data/index /tmp/data/boltdb-cache /tmp/data/chunks /tmp/data/wal"

for DIR in $REQUIRED_DIRS; do
    if [ ! -d "$DIR" ]; then
        echo "Creating missing directory: $DIR"
        mkdir -p "$DIR"
    fi
    chmod -R 755 "$DIR"
done

echo "Directory setup complete. Starting Loki..."

# Start Loki with the provided configuration file
exec /usr/bin/loki -config.file=/etc/loki/local-config.yml
