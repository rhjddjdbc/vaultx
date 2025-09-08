
#########################################
# Entry point for CLI mode
# Handles CLI args and dispatches actions
#########################################
run_cli_mode() {
  # Vault choice must be explicitly provided by CLI argument or env var VAULT_CLI
  vault_choice="${VAULT_CLI}"

  if [[ -z "$vault_choice" ]]; then
    echo "Error: Vault choice must be specified with --vault or VAULT_CLI environment variable." >&2
    exit 1
  fi

  VAULT_BASE="${VAULT_BASE:-$HOME/.vault}"
  VAULT_DIR="$VAULT_BASE/$vault_choice"

  if [[ "$ACTION_CLI" == "backup" && "$ALL_CLI" == true ]]; then
    cli_backup_all_vaults
    log_action "CLI: Action: '$ACTION_CLI' all"
    return
  fi

  # Vault-specific files
  MASTER_HASH_FILE="$VAULT_DIR/.master_hash"
  FAIL_COUNT_FILE="$VAULT_DIR/.fail_count"
  LAST_FAIL_FILE="$VAULT_DIR/.last_fail"
  LOCKOUT_SECRET_FILE="$VAULT_DIR/.lockout_secret"
  LOCKOUT_STATE_FILE="$VAULT_DIR/.lockout_state"

  # Ensure vault directory exists or create it
  if [[ ! -d "$VAULT_DIR" ]]; then
    echo "Vault '$vault_choice' not found. Creating it now..."
    log_action "Create new Vault: '$vault_choice'"
    mkdir -p "$VAULT_DIR" || { echo "Failed to create vault directory." >&2; exit 1; }
    chmod 700 "$VAULT_DIR"
  fi

  # Initialize lockout logic after VAULT_DIR is set
  init_lockout_secret
  load_lockout_secret

  # Create temporary working directory inside the vault
  TMP_DIR=$(mktemp -d -p "$VAULT_DIR" vaultx-tmp.XXXXXX) || {
    echo "Failed to create temporary directory." >&2
    exit 1
  }
  trap 'rm -rf "$TMP_DIR"' EXIT

  # Validate entry parameter for add/get/delete
  case "$ACTION_CLI" in
    add|get|delete)
      if [[ -z "$ENTRY_CLI" ]]; then
        echo "Missing entry name (--entry/-e)." >&2
        exit 1
      fi
      ;;
  esac

  # Dispatch CLI actions
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
    log_action "CLI: FAILED AUTHENTICATION while saving new password." 
    exit 1
  fi

  file="$VAULT_DIR/$ENTRY_CLI.bin"
  if [[ -f "$file" ]]; then
    echo "Entry already exists." >&2
    exit 1
  fi

  rsa_pubkey="$VAULT_RSA/id_rsa_vault.pub.pem"
  if [[ "$TWO_FA_ENABLED" == true && ! -f "$rsa_pubkey" ]]; then
    echo "RSA public key not found at $rsa_pubkey" >&2
    exit 1
  fi

  pw=$(cli_password_input "${METHOD_CLI:-manual}") || exit 1
  tmpfile="$VAULT_DIR/$ENTRY_CLI.aes"

  {
    echo "# AES-256-CBC, PBKDF2, 200000 iterations"
    [[ -n "$USERNAME_CLI" ]] && echo "Username: $USERNAME_CLI"
    echo "Password: $pw"
  } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
      -out "$tmpfile" -pass fd:3 3<<<"$MASTER"

  if [[ "$TWO_FA_ENABLED" == true ]]; then
     openssl pkeyutl -encrypt -pubin -inkey "$rsa_pubkey" \
       -in "$tmpfile" -out "$file" || {
        echo "RSA encryption failed." >&2
        rm -f "$tmpfile"
        exit 1
    }
    rm -f "$tmpfile"
    echo "2FA enabled – entry encrypted with AES + RSA."
  else
    mv "$tmpfile" "$file"
    echo "2FA disabled – entry encrypted with AES only."
  fi

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
  if [[ ! -f "$file" ]]; then
    echo "Entry '$ENTRY_CLI' not found." >&2
    exit 1
  fi

  rsa_privkey="$VAULT_RSA/id_rsa_vault.pem"
  if [[ "$TWO_FA_ENABLED" == true && ! -f "$rsa_privkey" ]]; then
    echo "RSA private key not found at $rsa_privkey" >&2
    exit 1
  fi

  hmac_file="${file%.bin}.hmac"
  if [[ ! -f "$hmac_file" ]]; then
    echo "HMAC file missing." >&2
    return 1
  fi

  if ! prompt_and_verify_password; then
    log_action "CLI: FAILED AUTHENTICATION while decrypting '$ENTRY_CLI'." 
    exit 1
  fi

  expected=$(awk '{print $1}' "$hmac_file")
  actual=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  if ! hash_equals "$expected" "$actual"; then
    echo "HMAC mismatch." >&2
    secure_unset
    return 1
  fi

  tmpfile="/tmp/vault_cli_$$.aes"

  if [[ "$TWO_FA_ENABLED" == true ]]; then
    openssl pkeyutl -decrypt -inkey "$rsa_privkey" \
      -in "$file" -out "$tmpfile" || {
        echo "RSA decryption failed." >&2
        rm -f "$tmpfile"
        secure_unset
        return 1
    }
  else
    cp "$file" "$tmpfile"
  fi

  decrypted=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
    -in "$tmpfile" -pass fd:3 3<<<"$MASTER") || {
      echo "AES decryption failed." >&2
      rm -f "$tmpfile"
      secure_unset
      return 1
  }

  rm -f "$tmpfile"

  user=$(echo "$decrypted" | awk -F': ' '/^Username:/ { print $2 }')
  pass=$(echo "$decrypted" | awk -F': ' '/^Password:/ { print $2 }')

  [[ -n "$user" ]] && echo "Username: $user"
  echo "Password: $pass"

  if [[ "$HIBP_CHECK_CLI" == "true" ]]; then
    check_pwned_password "$pass"
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

######################################################
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
