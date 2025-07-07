#!/usr/bin/env bash

# Vault-Konfiguration
VAULT="${VAULT_DIR:-vault}"
mkdir -p "$VAULT"
MASTER_HASH_FILE="$VAULT/.vault_master.hash"

prompt_and_verify_password() {
  read -s -p "Master password: " MASTER
  echo
  HASHED_MASTER=$(echo -n "$MASTER" | sha256sum | awk '{print $1}')
  if [[ ! -f "$MASTER_HASH_FILE" ]]; then
    echo "$HASHED_MASTER" > "$MASTER_HASH_FILE"
    echo "Master password initialized."
  else
    STORED_HASH=$(awk '{print $1}' "$MASTER_HASH_FILE")
    if [[ "$HASHED_MASTER" != "$STORED_HASH" ]]; then
      echo "Incorrect master password."
      unset MASTER
      return 1
    fi
  fi
  return 0
}

secure_unset() {
  unset MASTER pw pw2 username note name selected HASHED_MASTER STORED_HASH
}

main_menu() {
  actions=(
    "Save new entry"
    "Decrypt entry"
    "Delete entry"
    "Backup vault"
    "Audit mode"
    "Cancel"
  )

  action=$(printf "%s\n" "${actions[@]}" | fzf --prompt="Select action: ")
  [[ -z "$action" ]] && echo "No action selected." && exit 1

  case "$action" in
    "Save new entry")
      read -p "Entry name (e.g. github): " name
      [[ -z "$name" || "$name" =~ [^a-zA-Z0-9._-] ]] && echo "Invalid entry name." && return

      read -p "Username (optional): " username
      read -s -p "Password: " pw
      echo
      read -s -p "Repeat password: " pw2
      echo
      [[ "$pw" != "$pw2" ]] && echo "Passwords do not match." && return
      [[ -z "$pw" ]] && echo "Empty password is not allowed." && return

      if ! prompt_and_verify_password; then return; fi

      {
        [[ -n "$username" ]] && echo "Username: $username"
        echo "Password: $pw"
      } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
          -out "$VAULT/$name.bin" -pass pass:"$MASTER"

      timestamp=$(date +"%Y-%m-%d %H:%M:%S")
      read -p "Optional note for this entry: " note
      {
        echo "Label: $name"
        echo "Created: $timestamp"
        echo "Note: $note"
      } > "$VAULT/$name.note"

      echo "Saved as $VAULT/$name.bin"
      ;;

    "Decrypt entry")
      selected=$(find "$VAULT" -type f -name "*.bin" | fzf --prompt="Choose entry: ")
      [[ -z "$selected" ]] && echo "Cancelled." && return

      if ! prompt_and_verify_password; then return; fi

      openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$selected" \
        -pass pass:"$MASTER" || echo "Decryption failed."
      ;;

    "Delete entry")
      selected=$(find "$VAULT" -type f -name "*.bin" | fzf --prompt="Select entry to delete: ")
      [[ -z "$selected" ]] && echo "Cancelled." && return

      read -p "Delete '$(basename "$selected")'? [y/N]: " confirm
      if [[ "$confirm" =~ ^[yY]$ ]]; then
        rm -f "$selected" "${selected%.bin}.note"
        echo "Deleted."
      else
        echo "Deletion aborted."
      fi
      ;;

    "Backup vault")
      timestamp=$(date +"%Y%m%d-%H%M%S")
      backup_file="$HOME/vault-backup-$timestamp.zip"
      zip -r "$backup_file" "$VAULT" > /dev/null
      echo "Backup created at $backup_file"
      ;;

    "Audit mode")
      echo "Vault contents:"
      find "$VAULT" -type f -name "*.bin" | while read -r entry; do
        name=$(basename "$entry" .bin)
        mod_time=$(stat -c '%y' "$entry")
        echo "- $name (Last modified: $mod_time)"
        [[ -f "$VAULT/$name.note" ]] && head -n 3 "$VAULT/$name.note" | sed 's/^/  /'
      done
      ;;

    "Cancel")
      echo "Goodbye."
      exit 0
      ;;
  esac

  secure_unset
}

main_menu

