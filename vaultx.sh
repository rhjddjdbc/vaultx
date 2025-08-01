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


###############
# source config
###############
CONFIG_FILE="$HOME/.config/vaultx/config.env"

# Check and fix file permissions and ownership if necessary
check_and_fix_permissions() {
  # Get the current permissions, owner, and group of the file
  perms=$(stat -c "%a" "$CONFIG_FILE")
  owner=$(stat -c "%U" "$CONFIG_FILE")
  group=$(stat -c "%G" "$CONFIG_FILE")

  # Check if permissions are correct (644)
  if [[ "$perms" != "644" ]]; then
    echo "WARNING: The permissions for the config file are not correct. Setting them to 644." >&2
    chmod 644 "$CONFIG_FILE"
  fi

  # Check if the owner is root:root
  if [[ "$owner" != "root" || "$group" != "root" ]]; then
    echo "WARNING: The owner of the file is not correct. Setting the owner to root:root." >&2
    if [[ -n "$ESC_CMD" ]]; then
      $ESC_CMD chown root:root "$CONFIG_FILE"
    else
      echo "ERROR: No privilege escalation tool (sudo or doas) found to change ownership." >&2
      exit 1
    fi
  fi
}

# Determine which privilege escalation tool to use (sudo or doas)
if command -v doas &>/dev/null; then
  ESC_CMD="doas"
elif command -v sudo &>/dev/null; then
  ESC_CMD="sudo"
else
  ESC_CMD=""
fi

# Check and fix the file permissions and ownership
check_and_fix_permissions

# Source the config file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
  source "$CONFIG_FILE"
else
  echo "ERROR: Config file not found!" >&2
  exit 1
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

# NEW_VAULT_CREATED=false

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
if [[ "$NEW_VAULT_CREATED" == true ]]; then
  echo "New vault '$vault_choice' created. Proceeding to save first entry..."
  save_new_entry
  log_action "Auto-prompted Save new entry for newly created vault: '$vault_choice'"
  echo "Entry saved. Exiting."
  exit 0
fi

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
