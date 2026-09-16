#!/bin/bash
set -e

# Build the development containers
docker-compose build

# Start the containers in development mode
docker-compose up -d

# Follow the API logs
docker-compose logs -f api