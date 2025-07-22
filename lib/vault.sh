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
