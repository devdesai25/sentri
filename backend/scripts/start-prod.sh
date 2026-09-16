#!/bin/bash
set -e

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
  echo "Error: .env file not found."
  echo "Please create a .env file based on .env.example"
  exit 1
fi

# Build and start the production containers
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

echo "Sentri API is now running in production mode"
echo "To check logs: docker-compose -f docker-compose.prod.yml logs -f api"