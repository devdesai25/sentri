#!/bin/bash

if [ ! -z "$DEBUG" ]; then
  set -x
fi

# Configuration
API_URL="http://localhost:8000/api/v1/commands/explain"
MAX_RETRIES=5
TIMEOUT=15  # seconds
RETRY_DELAY=1  # seconds between retries

# Cache configuration
CACHE_DIR="$HOME/.sentri/cache"
CACHE_FILE="$CACHE_DIR/command_explanations.json"
MAX_CACHE_ENTRIES=100  # Maximum number of cached entries
CACHE_EXPIRY_DAYS=7    # Cache expires after 7 days

# PID for the spinner animation
SPINNER_PID=""

# Function to display a spinner animation
spinner() {
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local delay=0.1
  local msg="$1"
  
  # Hide cursor
  tput civis
  
  # Display spinner with message
  while true; do
    for frame in "${frames[@]}"; do
      printf "\r\033[K%s %s" "$frame" "$msg"
      sleep "$delay"
    done
  done
  
  # Show cursor again (this line won't be reached normally as function is killed)
  tput cnorm
}

# Function to start the spinner
start_spinner() {
  local msg="$1"
  if [ -z "$msg" ]; then
    msg="Fetching command explanation..."
  fi
  
  # Start the spinner in the background
  spinner "$msg" &
  SPINNER_PID=$!
  disown
}

# Function to stop the spinner
stop_spinner() {
  # Kill the spinner process if it exists
  if [ ! -z "$SPINNER_PID" ] && ps -p $SPINNER_PID > /dev/null; then
    kill $SPINNER_PID > /dev/null 2>&1
    SPINNER_PID=""
    
    # Show cursor again
    tput cnorm
    
    # Clear the line
    printf "\r\033[K"
  fi
}

# Create cache directory if it doesn't exist
mkdir -p "$CACHE_DIR"

# Function to check and manage cache expiration
manage_cache_expiration() {
  # Initialize cache file if it doesn't exist
  if [ ! -f "$CACHE_FILE" ]; then
    echo "{}" > "$CACHE_FILE"  # Empty JSON object
    if [ ! -z "$DEBUG" ]; then
      printf "Debug: Created new cache file\n"
    fi
    return 0
  fi
  
  # Check cache file age
  local current_time=$(date +%s)
  local file_modified_time=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || stat -f %m "$CACHE_FILE" 2>/dev/null)
  
  if [ -z "$file_modified_time" ]; then
    # If we can't get file time, reset cache to be safe
    printf "Warning: Unable to determine cache age, resetting cache\n"
    echo "{}" > "$CACHE_FILE"
    return 0
  fi
  
  local age_seconds=$((current_time - file_modified_time))
  local expiry_seconds=$((CACHE_EXPIRY_DAYS * 86400))  # Convert days to seconds
  
  if [ "$age_seconds" -gt "$expiry_seconds" ]; then
    # Cache is older than expiry period, reset it
    if [ ! -z "$DEBUG" ]; then
      printf "Debug: Cache is %d days old, resetting\n" $((age_seconds / 86400))
    fi
    echo "{}" > "$CACHE_FILE"
    printf "Notice: Command cache has been reset (older than %d days)\n" $CACHE_EXPIRY_DAYS
    return 0
  fi
  
  if [ ! -z "$DEBUG" ]; then
    printf "Debug: Cache age is %d days\n" $((age_seconds / 86400))
  fi
  return 0
}

# Function to clean up temporary files and stop spinner
cleanup() {
  # Stop the spinner if it's running
  stop_spinner
  
  # Remove temporary files
  rm -f "$TEMP_JSON" "$TEMP_RESPONSE" 2>/dev/null
  
  # Show cursor in case it was hidden
  tput cnorm 2>/dev/null
}

# Set trap to ensure cleanup on script exit
trap cleanup EXIT INT TERM

# Check and manage cache expiration
manage_cache_expiration

# Get the command to explain (everything after sentri)
COMMAND="$@"

# Extract the actual command and arguments
COMMAND_PARTS=($COMMAND)
CMD=${COMMAND_PARTS[0]}
ARGS="${COMMAND#$CMD}"
ARGS="${ARGS## }"  # Trim leading space

# Create cache key (command + arguments, normalized)
CACHE_KEY=$(echo "${CMD}${ARGS}" | tr -s '[:space:]' ' ' | xargs)

# Get current username and working directory
USERNAME=$(whoami)
WORKING_DIR=$(pwd)

# Create a temporary file for the JSON payload
TEMP_JSON=$(mktemp)
TEMP_RESPONSE=$(mktemp)

# Function to check if command explanation is in cache
check_cache() {
  local cmd_key="$1"
  
  # Use jq to check if the key exists in the cache
  if jq -e ".[\"$cmd_key\"]" "$CACHE_FILE" > /dev/null 2>&1; then
    if [ ! -z "$DEBUG" ]; then
      printf "Debug: Found in cache: %s\n" "$cmd_key"
    fi
    return 0  # Command found in cache
  else
    if [ ! -z "$DEBUG" ]; then
      printf "Debug: Not in cache: %s\n" "$cmd_key"
    fi
    return 1  # Command not in cache
  fi
}

# Function to get explanation from cache
get_from_cache() {
  local cmd_key="$1"
  jq ".[\"$cmd_key\"]" "$CACHE_FILE" > "$TEMP_RESPONSE"
  
  # Update cache file's modification time (touch the file)
  # This ensures frequently used cache doesn't expire
  touch "$CACHE_FILE"
}

# Function to add explanation to cache
add_to_cache() {
  local cmd_key="$1"
  local tmp_cache_file=$(mktemp)
  
  # Read the current cache content
  if [ ! -z "$DEBUG" ]; then
    printf "Debug: Adding to cache: %s\n" "$cmd_key"
  fi
  
  # Update cache with new entry, including timestamp
  jq --arg key "$cmd_key" --slurpfile content "$TEMP_RESPONSE" \
    '.[$key] = $content[0]' "$CACHE_FILE" > "$tmp_cache_file"
    
  # Handle cache size limits (remove oldest entries if needed)
  CACHE_SIZE=$(jq 'length' "$tmp_cache_file")
  if [ "$CACHE_SIZE" -gt "$MAX_CACHE_ENTRIES" ]; then
    # Remove oldest entries to maintain cache size
    jq 'to_entries | sort_by(.key) | .[1:] | from_entries' "$tmp_cache_file" > "$CACHE_FILE"
  else
    # Replace cache with updated version
    mv "$tmp_cache_file" "$CACHE_FILE"
  fi
  
  # Remove the temporary cache file if it still exists
  [ -f "$tmp_cache_file" ] && rm -f "$tmp_cache_file"
}

# Check if command is already in cache
if check_cache "$CACHE_KEY"; then
  start_spinner "Retrieving explanation from cache..."
  get_from_cache "$CACHE_KEY"
  stop_spinner
  SUCCESS=true
  CACHE_HIT=true
else
  CACHE_HIT=false
  # Prepare the JSON payload for API request
  cat > "$TEMP_JSON" << EOF
{
  "command": "$CMD",
  "arguments": "$ARGS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "username": "$USERNAME",
  "working_directory": "$WORKING_DIR"
}
EOF

  # Print debug info if enabled
  if [ ! -z "$DEBUG" ]; then
    printf "Debug: API URL = %s\n" "$API_URL"
    printf "Debug: JSON payload:\n"
    cat "$TEMP_JSON"
  fi

  # Initialize retry counter
  RETRY_COUNT=0
  SUCCESS=false

  # Retry loop
  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ $RETRY_COUNT -gt 0 ]; then
      stop_spinner
      printf "Retry attempt %d of %d...\n" $RETRY_COUNT $MAX_RETRIES
      sleep $RETRY_DELAY
      # Increase delay for subsequent retries (exponential backoff)
      RETRY_DELAY=$((RETRY_DELAY * 2))
    fi
    
    # Start the spinner with appropriate message
    if [ $RETRY_COUNT -eq 0 ]; then
      start_spinner "Sentri is analyzing your command..."
    else
      start_spinner "Retrying command analysis..."
    fi
    
    # Make the API request
    if [ ! -z "$DEBUG" ]; then
      stop_spinner
      printf "Calling API...\n"
      curl -v -s -m "$TIMEOUT" -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d @"$TEMP_JSON" > "$TEMP_RESPONSE" 2>&1
      CURL_STATUS=$?
      printf "Curl status: %d\n" $CURL_STATUS
      start_spinner "Continuing analysis..."
    else
      curl -s -m "$TIMEOUT" -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d @"$TEMP_JSON" > "$TEMP_RESPONSE" 2>&1
      CURL_STATUS=$?
    fi
    
    # Stop the spinner
    stop_spinner
    
    # Check if curl command succeeded
    if [ $CURL_STATUS -ne 0 ]; then
      printf "🐕 Error: API request failed (curl error %d)\n" $CURL_STATUS
      
      if [ $CURL_STATUS -eq 7 ]; then
        printf "Could not connect to server. Is the API running?\n"
      elif [ $CURL_STATUS -eq 28 ]; then
        printf "Connection timed out. Server might be overloaded.\n"
      fi
      
      RETRY_COUNT=$((RETRY_COUNT + 1))
      continue  # Try again
    fi
    
    # Check response size
    RESPONSE_SIZE=$(wc -c < "$TEMP_RESPONSE")
    if [ $RESPONSE_SIZE -eq 0 ]; then
      printf "🐕 Error: Received empty response from API\n"
      RETRY_COUNT=$((RETRY_COUNT + 1))
      continue  # Try again
    fi
    
    # Check if the response is valid JSON
    if ! jq . "$TEMP_RESPONSE" > /dev/null 2>&1; then
      printf "🐕 Error: Invalid JSON response\n"
      if [ ! -z "$DEBUG" ]; then
        printf "Response content:\n"
        cat "$TEMP_RESPONSE"
      fi
      RETRY_COUNT=$((RETRY_COUNT + 1))
      continue  # Try again
    fi
    
    # Check for API error response
    if jq -e 'has("detail")' "$TEMP_RESPONSE" > /dev/null 2>&1; then
      ERROR_MSG=$(jq -r '.detail' "$TEMP_RESPONSE")
      printf "🐕 Error from API: %s\n" "$ERROR_MSG"
      RETRY_COUNT=$((RETRY_COUNT + 1))
      continue  # Try again
    fi
    
    # Check if we have all required fields
    if ! jq -e 'has("command") and has("summary") and has("sections") and has("risk_level")' "$TEMP_RESPONSE" > /dev/null 2>&1; then
      printf "🐕 Error: Incomplete response missing required fields\n"
      RETRY_COUNT=$((RETRY_COUNT + 1))
      continue  # Try again
    fi
    
    # Add response to cache
    start_spinner "Caching explanation for future use..."
    add_to_cache "$CACHE_KEY"
    stop_spinner
    
    # If we got here, the API call was successful
    SUCCESS=true
    break
  done
fi

# Check if we succeeded after retries
if [ "$SUCCESS" = false ]; then
  printf "🐕 Error: Failed to get command explanation after %d attempts\n" $MAX_RETRIES
  printf "Would you like to execute the command anyway? [y/N] "
  read -r CONFIRM
  if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
    eval "$COMMAND"
  fi
  exit 1
fi

# Parse and display the command explanation
SUMMARY=$(jq -r '.summary' "$TEMP_RESPONSE")
RISK_LEVEL=$(jq -r '.risk_level' "$TEMP_RESPONSE")

# Display header with formatting
printf "\n🛡️ \033[1mSENTRI COMMAND EXPLANATION\033[0m\n"
if [ "$CACHE_HIT" = true ]; then
  printf "Command: \033[1m%s\033[0m \033[2m[cached]\033[0m\n" "$COMMAND"
else
  printf "Command: \033[1m%s\033[0m\n" "$COMMAND"
fi
printf "\n\033[1mSummary:\033[0m %s\n" "$SUMMARY"

# Display risk level with appropriate color
case "$RISK_LEVEL" in
  "critical")
    printf "\n\033[1;37;41mRISK LEVEL: CRITICAL\033[0m\n"
    ;;
  "high")
    printf "\n\033[1;31mRISK LEVEL: HIGH\033[0m\n"
    ;;
  "medium")
    printf "\n\033[1;33mRISK LEVEL: MEDIUM\033[0m\n"
    ;;
  "low")
    printf "\n\033[1;32mRISK LEVEL: LOW\033[0m\n"
    ;;
  "minimal")
    printf "\n\033[1;36mRISK LEVEL: MINIMAL\033[0m\n"
    ;;
  *)
    printf "\n\033[1;34mRISK LEVEL: UNKNOWN\033[0m\n"
    ;;
esac

# Display sections
SECTIONS_COUNT=$(jq '.sections | length' "$TEMP_RESPONSE")
for i in $(seq 0 $((SECTIONS_COUNT-1))); do
  TITLE=$(jq -r ".sections[$i].title" "$TEMP_RESPONSE")
  CONTENT=$(jq -r ".sections[$i].content" "$TEMP_RESPONSE")
  printf "\n\033[1m%s:\033[0m\n%s\n" "$TITLE" "$CONTENT"
done

# Ask for confirmation
printf "\nWould you like to execute this command? [Y/n] "
read -r CONFIRM

# Execute if confirmed (default is yes)
if [[ ! "$CONFIRM" =~ ^[nN]$ ]]; then
  printf "\nExecuting command...\n\n"
  eval "$COMMAND"
fi

# Exit with success
exit 0