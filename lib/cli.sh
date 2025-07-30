# lib/cli_mode.sh

#########################################
# Entry point for CLI mode
# Handles CLI args and dispatches actions
#########################################
run_cli_mode() {
  vault_choice="$VAULT_CLI"
  if [[ "$ACTION_CLI" == "backup" && "$ALL_CLI" == true ]]; then
    cli_backup_all_vaults
    log_action "CLI: Action: '$ACTION_CLI' all"
    return
 fi

  VAULT_DIR="${VAULT_DIR:-vault}/$vault_choice"
  MASTER_HASH_FILE="$VAULT_DIR/.master_hash"
  FAIL_COUNT_FILE="$VAULT_DIR/.fail_count"
  LAST_FAIL_FILE="$VAULT_DIR/.last_fail"

  # Ensure the vault directory exists
  if [[ ! -d "$VAULT_DIR" ]]; then
    echo "Vault '$vault_choice' not found. Creating it now..."
    log_action "Create new Vault: '$vault_choice'"
    mkdir -p "$VAULT_DIR" || { echo "Failed to create vault directory." >&2; exit 1; }
    chmod 700 "$VAULT_DIR"
  fi

  # Now we can safely create the TMP_DIR inside it
  TMP_DIR=$(mktemp -d -p "$VAULT_DIR" vaultx-tmp.XXXXXX) || {
    echo "Failed to create temporary directory." >&2
    exit 1
  }
  trap 'rm -rf "$TMP_DIR"' EXIT
  case "$ACTION_CLI" in
    add|get|delete)
      [[ -z "$ENTRY_CLI" ]] && { echo "Missing entry name (--entry/-e)." >&2; exit 1; }
      ;;
  esac

  case "$ACTION_CLI" in
    add)
      cli_add_entry
      log_action "CLI: Action: '$ACTION_CLI', Vault: '$vault_choice', Entry: '$ENTRY_CLI'"
      ;;
    get)
      cli_get_entry
      log_action "CLI: Action: '$ACTION_CLI', Vault: '$vault_choice', Entry: '$ENTRY_CLI'"
      ;;
    delete)
      cli_delete_entry
      log_action "CLI: Action: '$ACTION_CLI', Vault: '$vault_choice', Entry: '$ENTRY_CLI'"
      ;;
    backup)
      cli_backup_vault
      log_action "CLI: Action: '$ACTION_CLI', Vault: '$vault_choice'"
      ;;
    list)
      cli_list_vault
      log_action "CLI: Action: '$ACTION_CLI', Vault: '$vault_choice'"
      ;;
    *)
      echo "Invalid CLI action. Use: add, get, delete, backup, backup-all, list" >&2
      exit 1
      ;;
  esac

}

#########################################
# Adds a new encrypted entry to the vault
#########################################
cli_add_entry() {
  if ! prompt_and_verify_password; then
    log_action "CLI: FAILED AUTHENTICATION by saving new password." 
    exit 1
  fi

  file="$VAULT_DIR/$ENTRY_CLI.bin"
  [[ -f "$file" ]] && { echo "Entry already exists." >&2; exit 1; }

  pw=$(cli_password_input "${METHOD_CLI:-manual}") || exit 1

  {
    echo "# AES-256-CBC, PBKDF2, 200000 iterations"
    [[ -n "$USERNAME_CLI" ]] && echo "Username: $USERNAME_CLI"
    echo "Password: $pw"
  } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
      -out "$file" -pass fd:3 3<<<"$MASTER"

  hmac=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  echo "$hmac  $(basename "$file")" > "$VAULT_DIR/$ENTRY_CLI.hmac"

  echo "Entry '$ENTRY_CLI' added."
  secure_unset
}

#####################################
# Decrypts and displays a vault entry
#####################################
cli_get_entry() {
  file="$VAULT_DIR/$ENTRY_CLI.bin"
  [[ ! -f "$file" ]] && { echo "Entry '$ENTRY_CLI' not found." >&2; exit 1; }

  if ! prompt_and_verify_password; then
    log_action "CLI: FAILED AUTHENTICATION by decrypting '$ENTRY_CLI'." 
    exit 1
  fi

  hmac_file="${file%.bin}.hmac"
  [[ ! -f "$hmac_file" ]] && { echo "HMAC file missing." >&2; return 1; }

  expected=$(awk '{print $1}' "$hmac_file")
  actual=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  ! hash_equals "$expected" "$actual" && { echo "HMAC mismatch."; secure_unset; return 1; }

  decrypted=$(grep -v '^#' "$file" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -pass fd:3 3<<<"$MASTER") || {
    echo "Decryption failed." >&2
    secure_unset
    return 1
  }

  user=$(echo "$decrypted" | awk -F': ' '/^Username:/ { print $2 }')
  pass=$(echo "$decrypted" | awk -F': ' '/^Password:/ { print $2 }')

  [[ -n "$user" ]] && echo "Username: $user"
  echo "Password: $pass"

  if [[ "$HIBP_CHECK_CLI" == "true" ]]; then
     check_pwned_password "$pass"; 
  fi

  secure_unset
}

##############################################
# Deletes an entry and related metadata files
#############################################
cli_delete_entry() {
    entry_name="$ENTRY_CLI"

    # Define file paths
    file_path="$VAULT_DIR/$entry_name.bin"
    hmac_path="$VAULT_DIR/$entry_name.hmac"

    # Check if entry exists  
    if [ ! -f "$file_path" ]; then  
        echo "Entry '$entry_name' not found." >&2  
        exit 1  
    fi  

    # Prompt for confirmation  
    printf "Are you sure you want to delete entry '%s'? [y/N]: " "$entry_name"  
    read confirm  
    if ! echo "$confirm" | grep -qi '^y$'; then  
        echo "Deletion cancelled."  
        return 0  
    fi  

    rm -f "$file_path" "$hmac_path"  
    echo "Entry '$entry_name' deleted."  
    secure_unset  
}

#####################################################
# Handles password input for CLI (manual or generated)
######################################################
cli_password_input() {
  local method="$1"
  local pw copy_choice custom_len

  case "$method" in
    manual)
      # Prompt to stderr, read silently with 60s timeout
      echo -n "Password (timeout 60s): " >&2
      read -s -r -t 60 pw
      echo >&2

      # Validate non-empty
      if [[ -z "$pw" ]]; then
        echo "Password cannot be empty." >&2
        return 1
      fi
      if [[ "$HIBP_CHECK_CLI" == "true" ]]; then
        if ! check_pwned_password "$pw"; then
	    return 1
        fi
      fi

      # Output only the password to stdout
      printf '%s' "$pw"
      ;;

    generate)
      custom_len="${PASSWORD_LENGTH:-24}"
      pw=$(LC_ALL=C tr -dc 'A-Za-z0-9@#%&+=_' </dev/urandom | head -c "$custom_len")
      echo "Generated password: $pw" >&2
      read -r -p "Copy to clipboard? [y/N]: " copy_choice
      if [[ "$copy_choice" =~ ^[Yy]$ ]]; then
        copy_to_clipboard "$pw"
      fi
      printf '%s' "$pw"
      ;;

    *)
      echo "Unknown method: $method" >&2
      return 1
      ;;
  esac
}

############################################
# CLI version of vault backup functionality
############################################
cli_backup_vault() {
  ts=$(date +"%Y-%m-%dT_%H:%M:%S")
  dest="${BACKUP_DIR:-$HOME}"
  backup_path="$dest/$vault_choice-$ts.zip"

  if ! command -v zip >/dev/null 2>&1; then
    echo "Error: 'zip' command not found. Please install it." >&2
    exit 1
  fi

  # Ensure backup directory exists
  if [[ ! -d "$dest" ]]; then
    echo "Backup directory '$dest' does not exist. Creating it..."
    mkdir -p "$dest" || {
      echo "Failed to create backup directory: $dest" >&2
      exit 1
    }
  fi

  zip -rq "$backup_path" "$VAULT_DIR" || {
    echo "Backup failed." >&2
    exit 1
  }

  chmod 600 "$backup_path"
  echo "Backup for vault '$vault_choice' saved at: $backup_path"
}

# all vaults backup
cli_backup_all_vaults() {
  base_dir="${VAULT_DIR:-vault}"
  dest="${BACKUP_DIR:-$HOME}"
  ts=$(date +"%Y-%m-%dT_%H:%M:%S")
  backup_file="$dest/all-vaults-$ts.zip"

  if ! command -v zip >/dev/null; then
    echo "Error: 'zip' not found. Please install zip utility." >&2
    exit 1
  fi

  if [[ ! -d "$base_dir" ]]; then
    echo "Vault base directory '$base_dir' not found." >&2
    exit 1
  fi

  mkdir -p "$dest"
  zip -rq "$backup_file" "$base_dir"
  chmod 600 "$backup_file"
  echo "Backup complete: $backup_file"
}

#####################################
# CLI: list entries with dates
#####################################
cli_list_vault() {
  echo "Vault list for '$vault_choice':"
  echo

  if [[ ! -d "$VAULT_DIR" ]]; then
    echo "Vault directory '$VAULT_DIR' not found." >&2
    exit 1
  fi

  find "$VAULT_DIR" -maxdepth 1 -type f -name "*.bin" | sort | while read -r entry; do
    label=$(basename "$entry" .bin)
    modified=$(stat -c '%y' "$entry" 2>/dev/null || date -r "$entry")
    echo "- $label (last modified: $modified)"
  done
}
