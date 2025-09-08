# lib/option.sh

############################################################
# Save new entry to vault (with optional username)
# Ensures unique name, encrypts, generates HMAC and metadata
############################################################
save_new_entry() {
  if ! prompt_and_verify_password; then
    log_action "Interactive: FAILED AUTHENTICATION while saving new password in Vault: '$vault_choice'." 
    exit 1
  fi

  rsa_pubkey="$VAULT_RSA/id_rsa_vault.pub.pem"
  if [[ "$TWO_FA_ENABLED" == true && ! -f "$rsa_pubkey" ]]; then
    echo "RSA Public Key not found at $rsa_pubkey" >&2
    exit 1
  fi

  read -t 30 -r -p "Entry name for '$vault_choice' vault (e.g. github) [timeout 30s]: " selected || {
    echo -e "\nTimeout reached." >&2
    exit 1
  }
  [[ -z "$selected" || ! "$selected" =~ ^[A-Za-z0-9._-]+$ ]] && {
    echo "Invalid entry name. Use letters, numbers, dots, underscores, or hyphens only." >&2
    exit 1
  }

  vault_file_base="$VAULT_DIR/$selected"
  vault_file_tmp="$vault_file_base.aes"
  vault_file="$vault_file_base.bin"
  counter=2
  while [[ -f "$vault_file" ]]; do
    vault_file_base="$VAULT_DIR/$selected-$counter"
    vault_file_tmp="$vault_file_base.aes"
    vault_file="$vault_file_base.bin"
    ((counter++))
  done

  vault_root=$(realpath -m "$VAULT_DIR")
  [[ "$(realpath -m "$vault_file")" != "$vault_root/"* ]] && {
    echo "Invalid vault path." >&2
    exit 1
  }

  read -t 30 -r -p "Username (optional) [timeout 30s]: " username || username=""

  pw=$(generate_password_prompt) || exit 1

  {
    echo "# Vault encrypted with OpenSSL AES-256-CBC, PBKDF2, 200000 iterations"
    [[ -n "$username" ]] && printf "Username: %s\n" "$username"
    printf "Password: %s\n" "$pw"
  } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
      -out "$vault_file_tmp" -pass fd:3 3<<<"$MASTER"

  if [[ "$TWO_FA_ENABLED" == true ]]; then
    openssl pkeyutl -encrypt -pubin -inkey "$rsa_pubkey" -in "$vault_file_tmp" -out "$vault_file" || {
      echo "RSA encryption failed." >&2
      rm -f "$vault_file_tmp"
      exit 1
    }
    echo "2FA enabled – file encrypted with AES + RSA public key."
    rm -f "$vault_file_tmp"
  else
    mv "$vault_file_tmp" "$vault_file"
    echo "2FA disabled – file encrypted with AES only."
  fi

  # Generate HMAC for integrity
  hmac=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$vault_file" 3<<<"$MASTER" | awk '{print $2}')
  echo "$hmac  $(basename "$vault_file")" > "$vault_file_base.hmac"

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
  base="${file%.bin}"
  hmac_file="$base.hmac"

  [[ ! -f "$hmac_file" ]] && {
    echo "HMAC file missing for this entry." >&2
    exit 1
  }

  rsa_privkey="$VAULT_RSA/id_rsa_vault.pem"
  if [[ "$TWO_FA_ENABLED" == true && ! -f "$rsa_privkey" ]]; then
    echo "RSA Private Key not found at $rsa_privkey" >&2
    exit 1
  fi

  tmpfile="/tmp/vault_dec_$$.aes"

  if [[ "$TWO_FA_ENABLED" == true ]]; then
    openssl pkeyutl -decrypt -inkey "$rsa_privkey" -in "$file" -out "$tmpfile" || {
      echo "RSA decryption failed." >&2
      rm -f "$tmpfile"
      exit 1
    }
  else
    cp "$file" "$tmpfile"
  fi

  if ! prompt_and_verify_password; then
    log_action "Interactive: FAILED AUTHENTICATION while decrypting '$selected' in Vault: '$vault_choice'."
    rm -f "$tmpfile"
    exit 1
  fi

  expected=$(awk '{print $1}' "$hmac_file")
  actual=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  if ! hash_equals "$expected" "$actual"; then
    echo "Integrity verification failed – possible tampering or wrong master password." >&2
    rm -f "$tmpfile"
    secure_unset
    exit 1
  fi

  decrypted=$(grep -v '^#' "$tmpfile" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a -pass fd:3 3<<<"$MASTER") || {
    echo "AES decryption failed – incorrect master password or corrupted data." >&2
    rm -f "$tmpfile"
    secure_unset
    exit 1
  }

  rm -f "$tmpfile"

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
            echo "Password not found in any known data breaches." >&2
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

  # Avoid multiple password prompts - check if already verified
  if [[ -z "$MASTER" ]]; then
    if ! prompt_and_verify_password; then
      log_action "Interactive: FAILED AUTHENTICATION while editing '$selected' in Vault: '$vault_choice'."
      return
    fi
  fi

  tmpfile="/tmp/vault_plain_$$.txt"
  rsa_privkey="$VAULT_RSA/id_rsa_vault.pem"

  if [[ "$TWO_FA_ENABLED" == true && ! -f "$rsa_privkey" ]]; then
    echo "RSA Private Key not found at $rsa_privkey" >&2
    return
  fi

  # Step 1: RSA Decryption or direct use if 2FA is off
  if [[ "$TWO_FA_ENABLED" == true ]]; then
    openssl pkeyutl -decrypt -inkey "$rsa_privkey" -in "$file" -out "$tmpfile" || {
      echo "RSA decryption failed." >&2
      rm -f "$tmpfile"
      secure_unset
      return
    }
  else
    cp "$file" "$tmpfile"
  fi

  # Step 2: AES decryption
  decrypted=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
              -in "$tmpfile" -pass fd:3 3<<<"$MASTER") || {
    echo "AES decryption failed – wrong password or corrupted data." >&2
    rm -f "$tmpfile"
    secure_unset
    return
  }

  current_user=$(awk -F': ' '/^Username:/ { print $2 }' <<< "$decrypted")
  current_pass=$(awk -F': ' '/^Password:/ { print $2 }' <<< "$decrypted")

  # Prompt for updated values
  read -r -p "Update username (leave blank to keep current: '$current_user'): " username
  [[ -z "$username" ]] && username="$current_user"

  read -r -p "Do you want to change the password? [y/N]: " change_pw
  if [[ "$change_pw" =~ ^[Yy]$ ]]; then
    pw=$(generate_password_prompt) || {
      echo "Password generation failed or cancelled." >&2
      rm -f "$tmpfile"
      secure_unset
      return
    }
  else
    pw="$current_pass"
  fi

  # Step 3: Create new plaintext content
  {
    echo "# Vault encrypted with OpenSSL AES-256-CBC, PBKDF2, 200000 iterations"
    [[ -n "$username" ]] && printf "Username: %s\n" "$username"
    printf "Password: %s\n" "$pw"
  } > "$tmpfile"

  vault_file_tmp="$VAULT_DIR/$name.aes"

  # Step 4: AES encrypt updated entry
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -a \
              -in "$tmpfile" -out "$vault_file_tmp" -pass fd:3 3<<<"$MASTER" || {
    echo "AES encryption failed." >&2
    rm -f "$tmpfile"
    secure_unset
    return
  }

  rsa_pubkey="$VAULT_RSA/id_rsa_vault.pub.pem"
  if [[ "$TWO_FA_ENABLED" == true ]]; then
    [[ ! -f "$rsa_pubkey" ]] && {
      echo "RSA Public Key not found at $rsa_pubkey" >&2
      return
    }

    openssl pkeyutl -encrypt -pubin -inkey "$rsa_pubkey" \
                    -in "$vault_file_tmp" -out "$file" || {
      echo "RSA encryption failed." >&2
      rm -f "$tmpfile" "$vault_file_tmp"
      secure_unset
      return
    }

    echo "2FA enabled – entry updated using AES + RSA encryption."
    rm -f "$vault_file_tmp"
  else
    mv "$vault_file_tmp" "$file"
    echo "2FA disabled – entry updated using AES encryption only."
  fi

  # Step 5: HMAC recalculation
  hmac=$(openssl dgst -sha256 -mac HMAC -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" | awk '{print $2}')
  echo "$hmac  $(basename "$file")" > "$VAULT_DIR/$name.hmac"

  echo "Entry '$name' successfully updated."
  rm -f "$tmpfile"
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
  ts=$(date +"%Y-%m-%dT_%H:%M:%S")
  mkdir -p "$BACKUP_DIR" 
  backup="${BACKUP_DIR:-$HOME}/$vault_choice-$ts.zip"
  zip -rq "$backup" "$VAULT_DIR"
  chmod 600 "$backup"
  echo "Backup for vault '$vault_choice' saved at $backup."
}

##############################
# list entries with timestamps
##############################
list_vault() {
  echo "Listing contents of '$vault_choice' vault:"
  find "$VAULT_DIR" -maxdepth 1 -name "*.bin" | while read -r entry; do
    label=$(basename "$entry" .bin)
    modified=$(stat -c '%y' "$entry")
    echo "- $label (last modified: $modified)"
  done
}
