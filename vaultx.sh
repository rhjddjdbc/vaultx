#!/bin/bash
set -euo pipefail
umask 077

# Secure variable unset with whitelist
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

# Argument-Parsing
CLI_MODE=false
VAULT_CLI=""
ACTION_CLI=""
ENTRY_CLI=""
USERNAME_CLI=""
METHOD_CLI=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cli) CLI_MODE=true ;;
    -v|--vault) VAULT_CLI="$2"; shift ;;
    -a|--action) ACTION_CLI="$2"; shift ;;
    -e|--entry) ENTRY_CLI="$2"; shift ;;
    -u|--username) USERNAME_CLI="$2"; shift ;;
    -m|--method) METHOD_CLI="$2"; shift ;;   
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done
HOME="${HOME:-$(getent passwd "$(id -u -n)" | cut -d: -f6)}"
CONFIG_FILE="$HOME/.config/vaultx/config.env"

# Load config
if [[ -f "$CONFIG_FILE" ]]; then
  perms=$(stat -c "%a" "$CONFIG_FILE")
  if [[ "$perms" != "600" ]]; then
    echo "WARNING: $CONFIG_FILE has permissions $perms. Setting to 600." >&2
    chmod 600 "$CONFIG_FILE"
  fi
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
else
  echo "No config file found at $CONFIG_FILE. Using defaults." >&2
fi
# Script-Setup
SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Source libraries
source "$SCRIPT_DIR/lib/option.sh"
source "$SCRIPT_DIR/lib/pass.sh"
source "$SCRIPT_DIR/lib/tools.sh"
source "$SCRIPT_DIR/lib/cli.sh"

# CLI-Mode start
if [[ "$CLI_MODE" == true ]]; then
  run_cli_mode
  exit 0
fi

NEW_VAULT_CREATED=false

VAULT="${VAULT_DIR:-vault}"
PASSWORD_LENGTH="${PASSWORD_LENGTH:-24}"
PASSWORD_COST="${PASSWORD_COST:-16}" 

# Escalation tool detection
if command -v doas &>/dev/null; then ESC_CMD="doas"
elif command -v sudo &>/dev/null; then ESC_CMD="sudo"
else ESC_CMD=""
fi

# Ensure /proc/self/fd is properly protected
protect_fd() {
  perms=$(stat -Lc '%a' /proc/self/fd)
  other=${perms: -1}
  if (( other != 0 )); then
    echo "WARNING: /proc/self/fd has permissions $perms – file descriptors may leak to other users." >&2
    if [[ -n $ESC_CMD ]]; then
      echo "Attempting to remount /proc with hidepid=2 using $ESC_CMD…" >&2
      if $ESC_CMD mount -o remount,hidepid=2 /proc; then
        echo "SUCCESS: /proc has been remounted with hidepid=2." >&2
      else
        echo "ERROR: Failed to remount. Check your $ESC_CMD configuration." >&2
      fi
    else
      echo "No privilege tool found. Cannot remount /proc automatically." >&2
    fi
  fi
}


# Predeclare variables for strict mode
MASTER="" HASHED="" STORED_HASH=""
pw="" pw2="" username="" note=""
name="" selected="" action=""

select_vault() {
  mkdir -p "$VAULT_DIR"
  cd "$VAULT_DIR" || exit 1

  # List all existing vaults
  vaults=$(find . -maxdepth 1 -mindepth 1 -type d | sed 's|^\./||' | sort)

  # If no vaults exist, create 'default' automatically and select it
  if [[ -z "$vaults" ]]; then
    echo "No vault found. Creating 'default'..."
    mkdir -p "$VAULT_DIR/default"
    chmod 700 "$VAULT_DIR/default"
    vault_choice="default"
    NEW_VAULT_CREATED=true
  else
    # If vaults exist, present the selection menu
    vault_choice=$(printf "%s\n" $vaults "Create new vault" | fzf --prompt="Select vault: ")

    if [[ -z "$vault_choice" ]]; then
      echo "No selection made." >&2
      exit 1
    fi

    if [[ "$vault_choice" == "Create new vault" ]]; then
      read -r -p "Enter name for new vault (letters, numbers, _ or -): " new_vault
      if [[ -z "$new_vault" || ! "$new_vault" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "Invalid vault name." >&2
        exit 1
      fi
      vault_choice="$new_vault"
      mkdir -p "$VAULT_DIR/$vault_choice"
      chmod 700 "$VAULT_DIR/$vault_choice"
      echo "Vault '$vault_choice' created successfully."
      NEW_VAULT_CREATED=true
    fi
  fi

  # Set vault paths for the selected or created vault
  VAULT_DIR="$VAULT_DIR/$vault_choice"
  MASTER_HASH_FILE="$VAULT_DIR/.master_hash"
  FAIL_COUNT_FILE="$VAULT_DIR/.fail_count"
  LAST_FAIL_FILE="$VAULT_DIR/.last_fail"
}

select_vault
cat > "$VAULT_DIR/.backup.meta" << EOF
Algorithm: aes-256-cbc
PBKDF2 iterations: 200000
Salted: yes
Base64 encoded: yes
Extension: .bin

OpenSSL command to decrypt manually:

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -in github.bin -out github.txt
EOF
chmod 600 "$VAULT_DIR/.backup.meta"

# Secure temp dir
TMP_DIR=$(mktemp -d -p "$VAULT" vaultx-tmp.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# Lockout policy
MAX_ATTEMPTS=5
LOCKOUT_DURATION=600

# Main menu
main_menu() {
  if [[ "$NEW_VAULT_CREATED" == true ]]; then
    echo "New vault created. Please add your first entry."
    save_new_entry
    echo "First entry saved. Exiting now."
    exit 0
  fi

  action=$(printf "%s\n" \
    "Save new entry" \
    "Decrypt entry" \
    "Edit existing entry" \
    "Delete entry" \
    "Backup vault" \
    "Audit vault" \
    "Exit" \
  | fzf --prompt="Select action: ")
  
  [[ -z "$action" ]] && echo "No action selected." >&2 && exit 1

  case "$action" in
    "Save new entry")
      save_new_entry
      ;;
    "Decrypt entry")
      decrypt_entry
      ;;
    "Edit existing entry")
      edit_entry
      ;;
    "Delete entry")
      delete_entry
      ;;
    "Backup vault")
      backup_vault
      ;;
    "Audit vault")
      audit_vault
      ;;
    "Exit")
      echo "Exiting."
      exit 0
      ;;
  esac
}

main_menu
