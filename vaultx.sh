#!/bin/bash
set -euo pipefail
umask 077

##############################################
# Securely unset sensitive variables
# Clears and unsets sensitive values in memory
##############################################
secure_unset() {
  local var val len
  local whitelist=(MASTER pw pw2 username)

  for var in "${whitelist[@]}"; do
    [[ "$var" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || continue
    val="${!var:-}"
    if [[ -n "$val" ]]; then
      len="${#val}"
      printf -v "$var" '%*s' "$len" ''
      unset "$var"
    fi
  done

  unset HASHED STORED_HASH
}

##################
# Argument Parsing
##################
CLI_MODE=false
VAULT_CLI=""
ACTION_CLI=""
ENTRY_CLI=""
USERNAME_CLI=""
METHOD_CLI=""
ALL_CLI=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cli) CLI_MODE=true ;;
    -v|--vault) VAULT_CLI="$2"; shift ;;
    -a|--action) ACTION_CLI="$2"; shift ;;
    -e|--entry) ENTRY_CLI="$2"; shift ;;
    -u|--username) USERNAME_CLI="$2"; shift ;;
    -m|--method) METHOD_CLI="$2"; shift ;;
    --all) ALL_CLI=true ;;
    -h|--help) 
      if [[ -f "help.txt" ]]; then
        cat help.txt
      else
        echo "help.txt not found."
      fi
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
  shift
done

#####################################
# Configuration and Environment Setup
#####################################

# Determine home directory
HOME="${HOME:-$(getent passwd "$(id -u -n)" | cut -d: -f6)}"
CONFIG_FILE="$HOME/.config/vaultx/config.env"

# Load config file if present
if [[ -f "$CONFIG_FILE" ]]; then
  perms=$(stat -c "%a" "$CONFIG_FILE")
  if [[ "$perms" != "600" ]]; then
    echo "WARNING: $CONFIG_FILE has permissions $perms. Fixing to 600." >&2
    chmod 600 "$CONFIG_FILE"
  fi
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
else
  echo "No config found at $CONFIG_FILE. Using defaults." >&2
fi

# Default configuration values
VAULT="${VAULT_DIR:-vault}"
PASSWORD_LENGTH="${PASSWORD_LENGTH:-24}"
PASSWORD_COST="${PASSWORD_COST:-16}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-5}"
LOCKOUT_DURATION="${LOCKOUT_DURATION:-600}"

##################################
# Script Setup and Library Loading
##################################
SCRIPT_DIR=$(dirname "$(realpath "$0")")

source "$SCRIPT_DIR/lib/option.sh"
source "$SCRIPT_DIR/lib/pass.sh"
source "$SCRIPT_DIR/lib/tools.sh"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/vault.sh"
source "$SCRIPT_DIR/lib/logger.sh"

####################
# CLI Mode Execution
####################
if [[ "$CLI_MODE" == true ]]; then
  run_cli_mode
  exit 0
fi

NEW_VAULT_CREATED=false

#####################################
# Privilege Escalation Tool Detection
#####################################
if command -v doas &>/dev/null; then
  ESC_CMD="doas"
elif command -v sudo &>/dev/null; then
  ESC_CMD="sudo"
else
  ESC_CMD=""
fi

####################################
# Protect /proc/self/fd from leakage
####################################
protect_fd() {
  perms=$(stat -Lc '%a' /proc/self/fd)
  other=${perms: -1}
  if (( other != 0 )); then
    echo "WARNING: /proc/self/fd has permissions $perms – descriptors might leak to other users." >&2
    if [[ -n $ESC_CMD ]]; then
      echo "Attempting to remount /proc with hidepid=2 using $ESC_CMD..." >&2
      if $ESC_CMD mount -o remount,hidepid=2 /proc; then
        echo "SUCCESS: /proc was remounted with hidepid=2." >&2
      else
        echo "ERROR: Failed to remount. Please check $ESC_CMD configuration." >&2
      fi
    else
      echo "No privilege escalation tool found. Cannot remount /proc automatically." >&2
    fi
  fi
}
protect_fd

#########################################
# Pre-declare all variables (strict mode)
#########################################
MASTER="" HASHED="" STORED_HASH=""
pw="" pw2="" username="" 
name="" selected="" action=""

#######################################
# Vault Selection and Metadata Creation
#######################################
select_vault

cat > "$VAULT/.backup.meta" << EOF
Algorithm: aes-256-cbc
PBKDF2 iterations: 200000
Salted: yes
Base64 encoded: yes
Extension: .bin

OpenSSL command to decrypt manually:

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -in github.bin -out github.txt
EOF

chmod 600 "$VAULT/.backup.meta"

#####################################
# Secure Temporary Directory Creation
#####################################
TMP_DIR=$(mktemp -d -p "$VAULT" vaultx-tmp.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

##############################
# Main Menu – Interactive Mode
##############################
main_menu() {
  local vault="${VAULT:-unknown}"
  local entry="${ENTRY_CLI:-none}"

  # Aktion auswählen
  action=$(printf "%s\n" \
    "Save new entry" \
    "Decrypt entry" \
    "Edit existing entry" \
    "Delete entry" \
    "Backup vault" \
    "List vault" \
    "Exit" \
  | fzf --prompt="Select action: ")

  if [[ -z "$action" ]]; then
    echo "No action selected." >&2
    exit 1
  fi
  case "$action" in
    "Save new entry")
      save_new_entry
      log_action "Interactive: Selected action: '$action', vault: '$vault_choice' entry: '$selected'" 
      ;;
    "Decrypt entry")
      decrypt_entry
      log_action "Interactive: Selected action: '$action', vault: '$vault_choice' entry: '$selected'" 
      ;;
    "Edit existing entry")
      edit_entry
      log_action "Interactive: Selected action: '$action', vault: '$vault_choice' entry: '$selected'" 
      ;;
    "Delete entry")
      delete_entry
      log_action "Interactive: Selected action: '$action', vault: '$vault_choice' entry: '$selected'" 
      ;;
    "Backup vault")
      backup_vault
      log_action "Interactive: Selected action: '$action', vault: '$vault_choice'."
      ;;
    "List vault")
      list_vault
      log_action "Interactive: Selected action: '$action', vault: '$vault_choice'."
      ;;
    "Exit")
      echo "Exiting."
      exit 0
      ;;
    *)
      echo "Unknown action." >&2
      exit 1
      ;;
  esac
}

main_menu
