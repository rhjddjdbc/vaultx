# lib/option.sh

############################################################
# Save new entry to vault (with optional username)
# Ensures unique name, encrypts, generates HMAC and metadata
############################################################
save_new_entry() {
  if ! prompt_and_verify_password; then
    echo "Master password verification failed. Exiting..." >&2
    exit 1
  fi

  read -t 30 -r -p "Entry name for '$vault_choice' vault (e.g. github) [timeout 30s]: " name || { echo -e "\nTimeout reached." >&2; exit 1; }
  [[ -z "$name" || ! "$name" =~ ^[A-Za-z0-9._-]+$ ]] && { echo "Invalid entry name." >&2; exit 1; }

  vault_file="$VAULT_DIR/$name.bin"
  counter=2
  while [[ -f "$vault_file" ]]; do
    vault_file="$VAULT_DIR/$name-$counter.bin"
    name="$name-$counter"
    ((counter++))
  done

  vault_root=$(realpath -m "$VAULT_DIR")
  [[ "$(realpath -m "$vault_file")" != "$vault_root/"* ]] && { echo "Invalid path." >&2; exit 1; }

  read -t 30 -r -p "Username (optional) [timeout 30s]: " username || username=""

  pw=$(generate_password_prompt) || exit 1

  {
    echo "# Vault encrypted with OpenSSL AES-256-CBC, PBKDF2, 200000 iterations"
    [[ -n "$username" ]] && printf "Username: %s\n" "$username"
    printf "Password: %s\n" "$pw"
  } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
      -out "$vault_file" -pass fd:3 3<<<"$MASTER"

  hmac=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$vault_file" 3<<<"$MASTER" | awk '{print $2}')
  echo "$hmac  $(basename "$vault_file")" > "$VAULT_DIR/$name.hmac"
  secure_unset
}

###################################################################
# Decrypt and view an entry
# Uses HMAC for integrity check and shows password handling options
###################################################################
decrypt_entry() {
  selected=$(find "$VAULT_DIR" -maxdepth 1 -type f -name "*.bin" | fzf --prompt="Select entry to decrypt: ")
  [[ -z "$selected" ]] && echo "Cancelled." >&2 && exit 1

  file="$selected"
  hmac_file="${file%.bin}.hmac"
  [[ ! -f "$hmac_file" ]] && { echo "HMAC file missing for entry." >&2; exit 1; }

  prompt_and_verify_password || exit 1

  expected=$(awk '{print $1}' "$hmac_file")
  actual=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  if ! hash_equals "$expected" "$actual"; then
      echo "Integrity verification failed." >&2
      secure_unset
      exit 1
  fi

  decrypted=$(grep -v '^#' "$file" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -pass fd:3 3<<<"$MASTER") || {
    echo "Decryption failed." >&2
    secure_unset
    exit 1
  }

  user=$(printf '%s\n' "$decrypted" | awk -F': ' '/^Username:/ { print $2 }')
  pass=$(printf '%s\n' "$decrypted" | awk -F': ' '/^Password:/ { print $2 }')

  pass_action=$(printf "%s\n" \
      "Display password only" \
      "Copy password only" \
      "Display and copy password" \
      "Show ASCII QR code (clears after 30s)" \
      "Breach check" \
      "Cancel" \
      | fzf --prompt="Choose password handling method: ")

  case "$pass_action" in
    "Display password only")
        printf 'Password: %s\n' "$pass"
        ;;
    "Copy password only")
        copy_to_clipboard "$pass"
        ;;
    "Display and copy password")
        printf 'Password: %s\n' "$pass"
        copy_to_clipboard "$pass"
        ;;
    "Show ASCII QR code (clears after 30s)")
        [[ -n "$user" ]] && printf 'Username: %s\n' "$user"
        display_ascii_qr_temp "$pass"
        ;;
    "Breach check")
        if check_pwned_password "$pass"; then
            echo "Password not found in any known breaches." >&2
        fi
        ;;
    *)
        echo "Action cancelled." >&2
        ;;
  esac

  if [[ "$pass_action" != "Breach check" && "$pass_action" != "Show ASCII QR code (clears after 30s)" && -n "$user" ]]; then
      printf 'Username: %s\n' "$user"
  fi

  secure_unset
}

######################################################
# Edit an existing vault entry (username and password)
######################################################
edit_entry() {
  selected=$(find "$VAULT_DIR" -maxdepth 1 -type f -name "*.bin" | fzf --prompt="Select entry to edit: ")
  [[ -z "$selected" ]] && echo "Cancelled." >&2 && return

  file="$selected"
  name=$(basename "$file" .bin)

  if ! prompt_and_verify_password; then
      echo "Master password verification failed." >&2
      return
  fi

  tmpfile="/tmp/vault_plain_$$.txt"

  # Decrypt entry to temp file (strips comment lines)
  grep -v '^#' "$file" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -pass fd:3 3<<<"$MASTER" > "$tmpfile" || {
      echo "Failed to decrypt entry." >&2
      rm -f "$tmpfile"
      secure_unset
      return
  }

  current_user=$(awk -F': ' '/^Username:/ { print $2 }' "$tmpfile")
  current_pass=$(awk -F': ' '/^Password:/ { print $2 }' "$tmpfile")

  read -r -p "Update username (leave blank to keep current: '$current_user'): " username
  [[ -z "$username" ]] && username="$current_user"

  echo "Update password:"
  pw=$(generate_password_prompt) || { rm -f "$tmpfile"; return; }

  {
    echo "# Vault encrypted with OpenSSL AES-256-CBC, PBKDF2, 200000 iterations"
    [[ -n "$username" ]] && printf "Username: %s\n" "$username"
    printf "Password: %s\n" "$pw"
  } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -out "$file" -pass fd:3 3<<<"$MASTER"

  rm -f "$tmpfile"

  hmac=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  echo "$hmac  $(basename "$file")" > "$VAULT_DIR/$name.hmac"

  echo "Entry '$name' successfully updated."
  secure_unset
}

################################
# Delete an entry from the vault
################################
delete_entry() {
  selected=$(find "$VAULT_DIR" -maxdepth 1 -type f -name "*.bin" \
      | fzf --prompt="Select entry to delete: ")
  [[ -z "$selected" ]] && echo "Cancelled." >&2 && exit 1

  read -t 30 -r -p "Delete '$(basename "$selected")'? [y/N]: " confirm
  if [[ "$confirm" =~ ^[yY]$ ]]; then
      rm -f "$selected" "${selected%.bin}.hmac" 
      echo "Entry deleted."
  else
      echo "Operation cancelled."
  fi
}

#########################################################
# Create a ZIP archive backup of the current vault folder
# Backup goes to BACKUP_DIR or falls back to $HOME
#########################################################
backup_vault() {
  ts=$(date +"%Y%m%d") 
  mkdir -p "$BACKUP_DIR" 
  backup="${BACKUP_DIR:-$HOME}/$vault_choice-$ts.zip"
  zip -rq "$backup" "$VAULT_DIR"
  chmod 600 "$backup"
  echo "Backup for vault '$vault_choice' saved at $backup."
}

#####################################################
# Audit vault contents - list entries with timestamps
#####################################################
audit_vault() {
  echo "Listing contents of '$vault_choice' vault:"
  find "$VAULT_DIR" -maxdepth 1 -name "*.bin" | while read -r entry; do
    label=$(basename "$entry" .bin)
    modified=$(stat -c '%y' "$entry")
    echo "- $label (last modified: $modified)"
  done
}
