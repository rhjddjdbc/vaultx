# lib/cli_mode.sh

run_cli_mode() {
  TMP_DIR=$(mktemp -d -p "${VAULT_DIR:-/tmp}" vaultx-tmp.XXXXXX)
  trap 'rm -rf "$TMP_DIR"' EXIT
  vault_choice="$VAULT_CLI"
  VAULT_DIR="${VAULT_DIR:-vault}/$vault_choice"
  MASTER_HASH_FILE="$VAULT_DIR/.master_hash"
  FAIL_COUNT_FILE="$VAULT_DIR/.fail_count"
  LAST_FAIL_FILE="$VAULT_DIR/.last_fail"

  [[ ! -d "$VAULT_DIR" ]] && { echo "Vault '$vault_choice' not found."; exit 1; }
  [[ -z "$ENTRY_CLI" ]] && { echo "Missing entry name (--entry/-e)." >&2; exit 1; }
  case "$ACTION_CLI" in
    add)
      cli_add_entry
      ;;
    get)
      cli_get_entry
      ;;
    delete)
      cli_delete_entry
      ;;
    *)
      echo "Invalid CLI action. Use: add, get, delete" >&2
      exit 1
      ;;
  esac
}


cli_add_entry() {
  if ! prompt_and_verify_password; then
    echo "Master password verification failed." >&2
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


cli_get_entry() {
  file="$VAULT_DIR/$ENTRY_CLI.bin"
  [[ ! -f "$file" ]] && { echo "Entry '$ENTRY_CLI' not found." >&2; exit 1; }

  if ! prompt_and_verify_password; then
    echo "Master password verification failed." >&2
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


cli_delete_entry() {
  file="$VAULT_DIR/$ENTRY_CLI.bin"
  hmac="$VAULT_DIR/$ENTRY_CLI.hmac"
  meta="$VAULT_DIR/.${ENTRY_CLI}.meta"

  [[ ! -f "$file" ]] && { echo "Entry '$ENTRY_CLI' not found." >&2; exit 1; }

  if ! prompt_and_verify_password; then
    echo "Master password verification failed." >&2
    exit 1
  fi

  rm -f "$file" "$hmac" "$meta"
  echo "Entry '$ENTRY_CLI' deleted."
  secure_unset
}

cli_password_input() {
  local method="$1"
  local pw copy_choice custom_len

  case "$method" in
    manual)
      # Prompt to stderr, read silently with 60s timeout
      echo -n "Password [timeout 60s]: " >&2
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
