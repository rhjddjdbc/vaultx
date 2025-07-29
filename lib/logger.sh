# lib/logger.sh

#################
# logger function 
#################
# Default values
LOGGING_ENABLED="${LOGGING_ENABLED:-false}"
LOG_FILE="${LOG_FILE:-$HOME/.vaultx.log}"

# Create the log file if it doesn't exist (but only if logging is enabled)
if [[ "$LOGGING_ENABLED" == "true" && ! -f "$LOG_FILE" ]]; then
  touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
fi

# Function: log_action "message"
log_action() {
  if [[ "$LOGGING_ENABLED" != "true" ]]; then
    return 0
  fi

  local ts user msg
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  user="${USER:-unknown}"
  msg="$1"

  echo "[$ts] [user:$user] $msg" >> "$LOG_FILE"
}
