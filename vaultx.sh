#!/bin/bash
set -euo pipefail
umask 077

# Load config
CONFIG_FILE="$HOME/.config/vaultx/config.env"
if [[ -f "$CONFIG_FILE" ]]; then
  source "$CONFIG_FILE"
else
  echo "No config file found at $CONFIG_FILE. Using defaults." >&2
fi

VAULT="${VAULT_DIR:-vault}"
export TMOUT="${TMOUT_VALUE:-300}"
readonly TMOUT
PASSWORD_LENGTH="${PASSWORD_LENGTH:-24}"

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

# Session timer utilities
start_timer() {
  ( sleep "$TMOUT" && kill -ALRM $$ ) &
  TIMER_PID=$!
}

cleanup_timer() {
  kill "${TIMER_PID:-}" 2>/dev/null || true
}

trap 'echo "Error on line $LINENO: $BASH_COMMAND" >&2; cleanup_timer; exit 1' ERR
trap 'echo "Session timed out after $TMOUT seconds." >&2; cleanup_timer; exit 1' ALRM
trap 'cleanup_timer' EXIT
start_timer

# Predeclare variables for strict mode
MASTER="" HASHED="" STORED_HASH=""
pw="" pw2="" username="" note=""
name="" selected="" action=""

# Vault configuration
MASTER_HASH_FILE="$VAULT/.master_hash"
FAIL_COUNT_FILE="$VAULT/.fail_count"
LAST_FAIL_FILE="$VAULT/.last_fail"
mkdir -p "$VAULT"
chmod 700 "$VAULT"

# Secure temp dir
TMP_DIR=$(mktemp -d -p "$VAULT" vaultx-tmp.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# Lockout policy
MAX_ATTEMPTS=5
LOCKOUT_DURATION=600

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

# Constant-time comparison
hash_equals() {
  local a="$1" b="$2"
  (( ${#a} != ${#b} )) && return 1
  local res=0 i
  for (( i=0; i<${#a}; i++ )); do
    res=$(( res | ( $(printf '%d' "'${a:i:1}") ^ $(printf '%d' "'${b:i:1}") ) ))
  done
  (( res == 0 ))
}

# Clipboard helper
copy_to_clipboard() {
  local timeout=30
  if command -v wl-copy &>/dev/null; then
    echo "$1" | wl-copy
    echo "Copied to clipboard using wl-copy. It will be cleared in $timeout seconds." >&2
    ( sleep "$timeout" && wl-copy < /dev/null ) &
  elif command -v xclip &>/dev/null; then
    echo "$1" | xclip -selection clipboard
    echo "Copied to clipboard using xclip. It will be cleared in $timeout seconds." >&2
    ( sleep "$timeout" && echo -n | xclip -selection clipboard ) &
  else
    echo "No clipboard tool found. Install wl-clipboard or xclip." >&2
  fi
}

# Generate password prompt
generate_password_prompt() {
  local choice pw copy_choice custom_len
  choice=$(printf "%s\n" "Enter manually" "Generate secure password" | fzf --prompt="Choose password method: ")
  case "$choice" in
    "Enter manually")
      read -t 60 -s -r -p "Password (timeout 60s): " pw; echo
      read -t 60 -s -r -p "Repeat password (timeout 60s): " pw2; echo
      [[ "$pw" != "$pw2" ]] && echo "Passwords do not match." >&2 && return 1
      [[ -z "$pw" ]] && echo "Empty password not allowed." >&2 && return 1
      printf '%s' "$pw"
      ;;
    "Generate secure password")
      read -r -p "Desired password length (default: $PASSWORD_LENGTH): " custom_len
      custom_len="${custom_len:-$PASSWORD_LENGTH}"
      pw=$(openssl rand -base64 "$custom_len")
      echo "Generated password: $pw" >&2
      read -r -p "Copy generated password to clipboard? [y/N]: " copy_choice
      if [[ "$copy_choice" =~ ^[Yy]$ ]]; then
        copy_to_clipboard "$pw"
      fi
      printf '%s' "$pw"
      ;;
    *)
      echo "No selection made." >&2
      return 1
      ;;
  esac
}

# Prompt and verify master password
prompt_and_verify_password() {
  if [[ -f $FAIL_COUNT_FILE && -f $LAST_FAIL_FILE ]]; then
    fails=$(<"$FAIL_COUNT_FILE")
    last=$(<"$LAST_FAIL_FILE")
    now=$(date +%s)
    if (( fails >= MAX_ATTEMPTS && now - last < LOCKOUT_DURATION )); then
      wait_time=$(( LOCKOUT_DURATION - (now - last) ))
      echo "Too many failed attempts. Retry in $wait_time seconds." >&2
      return 1
    fi
  fi

  if ! read -t 60 -s -r -p "Master password (timeout 60s): " MASTER; then
    echo -e "\nTimeout or no input. Aborting." >&2
    return 1
  fi
  echo

  if [[ ! -f "$MASTER_HASH_FILE" ]]; then
    HASHED=$(htpasswd -nbB dummy "$MASTER" | cut -d: -f2)
    echo "$HASHED" > "$MASTER_HASH_FILE"
    echo "Master password initialized successfully." >&2
    rm -f "$FAIL_COUNT_FILE" "$LAST_FAIL_FILE"
    return 0
  fi

  tmp="$TMP_DIR/tmpfile"
  STORED_HASH=$(<"$MASTER_HASH_FILE")
  printf 'dummy:%s\n' "$STORED_HASH" > "$tmp"

  if htpasswd -vbB "$tmp" dummy "$MASTER" &>/dev/null; then
    rm -f "$tmp" "$FAIL_COUNT_FILE" "$LAST_FAIL_FILE"
    return 0
  else
    rm -f "$tmp"
    now=$(date +%s)
    prev=0
    [[ -f "$FAIL_COUNT_FILE" ]] && prev=$(<"$FAIL_COUNT_FILE")
    fails=$(( prev + 1 ))
    echo "$fails" > "$FAIL_COUNT_FILE"
    echo "$now" > "$LAST_FAIL_FILE"
    backoff=$(( fails * 2 ))
    (( backoff > LOCKOUT_DURATION )) && backoff=$LOCKOUT_DURATION
    sleep "$backoff"
    echo "Invalid master password. Attempt $fails of $MAX_ATTEMPTS." >&2
    return 1
  fi
}

# Display ASCII QR Code temporarily
display_ascii_qr_temp() {
  local secret="$1"
  if command -v qrencode &>/dev/null; then
    echo "$secret" | qrencode -t ANSIUTF8
    echo -e "\nQR-Code will be cleared in 30 seconds..."
    sleep 30
    clear
  else
    echo "qrencode not installed. Cannot generate QR code." >&2
    return 1
  fi
}

# Save new entry to vault
save_new_entry() {
  read -t 30 -r -p "Entry name (e.g. github) [timeout 30s]: " name \
    || { echo -e "\nTimeout reached." >&2; exit 1; }
  [[ -z "$name" || ! "$name" =~ ^[A-Za-z0-9._-]+$ ]] \
    && { echo "Invalid entry name." >&2; exit 1; }

  # Ensure entry name is unique, like you are :) (e.g. google, google-2, google-3)
  vault_file="$VAULT/$name.bin"
  counter=2
  while [[ -f "$vault_file" ]]; do
    vault_file="$VAULT/$name-$counter.bin"
    name="$name-$counter"
    ((counter++))
  done

  vault_root=$(realpath -m "$VAULT")
  [[ "$(realpath -m "$vault_file")" != "$vault_root/"* ]] \
    && { echo "Invalid path." >&2; exit 1; }

  read -t 30 -r -p "Username (optional) [timeout 30s]: " username || username=""

  pw=$(generate_password_prompt) || exit 1

  prompt_and_verify_password || exit 1

  {
    [[ -n "$username" ]] && printf "Username: %s\n" "$username"
    printf "Password: %s\n" "$pw"
  } | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
      -out "$vault_file" -pass fd:3 3<<<"$MASTER"

  hmac=$(openssl dgst -sha256 -mac HMAC \
    -macopt key:file:/dev/fd/3 "$vault_file" 3<<<"$MASTER" \
    | awk '{print $2}')
  echo "$hmac  $(basename "$vault_file")" > "$VAULT/$name.hmac"

  secure_unset

  read -t 60 -r -p "Optional note [timeout 60s]: " note || note=""
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  {
    echo "Label: $name"
    echo "Created: $timestamp"
    echo "Note: $note"
  } > "$VAULT/$name.note"
  chmod 600 "$VAULT/$name.note"

  echo "Saved entry '$name' with HMAC."
}

# Decrypt existing entry from vault
decrypt_entry() {
  selected=$(find "$VAULT" -maxdepth 1 -type f -name "*.bin" \
      | fzf --prompt="Select entry to decrypt: ")
  [[ -z "$selected" ]] && echo "Cancelled." >&2 && exit 1

  file="$selected"
  hmac_file="${file%.bin}.hmac"
  [[ ! -f "$hmac_file" ]] \
      && { echo "HMAC file missing for entry." >&2; exit 1; }

  prompt_and_verify_password || exit 1

  expected=$(awk '{print $1}' "$hmac_file")
  actual=$(openssl dgst -sha256 -mac HMAC \
      -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" \
      | awk '{print $2}')
  if ! hash_equals "$expected" "$actual"; then
      echo "Integrity verification failed." >&2
      secure_unset
      exit 1
  fi

  decrypted=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
      -in "$file" -pass fd:3 3<<<"$MASTER")

  user=$(printf '%s\n' "$decrypted" | awk -F': ' '/^Username:/ { print $2 }')
  pass=$(printf '%s\n' "$decrypted" | awk -F': ' '/^Password:/ { print $2 }')

  [[ -n "$user" ]] && printf 'Username: %s\n' "$user"

  pass_action=$(printf "%s\n" \
      "Display password only" \
      "Copy password only" \
      "Display and copy password" \
      "Show ASCII QR code (clears after 30s)" \
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
          display_ascii_qr_temp "$pass"
          ;;
      *)
          echo "Action cancelled." >&2
          ;;
  esac

  secure_unset
}

# Delete an entry
delete_entry() {
  selected=$(find "$VAULT" -maxdepth 1 -type f -name "*.bin" \
      | fzf --prompt="Select entry to delete: ")
  [[ -z "$selected" ]] && echo "Cancelled." >&2 && exit 1

  read -t 30 -r -p "Delete '$(basename "$selected")'? [y/N]: " confirm
  if [[ "$confirm" =~ ^[yY]$ ]]; then
      rm -f "$selected" "${selected%.bin}.hmac" "${selected%.bin}.note"
      echo "Entry deleted."
  else
      echo "Operation cancelled."
  fi
}

# Backup the vault
backup_vault() {
  ts=$(date +"%Y%m%d-%H%M%S")
  backup="${BACKUP_DIR:-$HOME}/vault-backup-$ts.zip"
  zip -rq "$backup" "$VAULT"
  chmod 600 "$backup"
  echo "Vault backup saved to $backup."
}

# Audit vault contents
audit_vault() {
  echo "Listing vault contents:"
  find "$VAULT" -maxdepth 1 -name "*.bin" | while read -r entry; do
    label=$(basename "$entry" .bin)
    modified=$(stat -c '%y' "$entry")
    echo "- $label (last modified: $modified)"
    [[ -f "$VAULT/$label.note" ]] \
      && head -n3 "$VAULT/$label.note" | sed 's/^/    /'
  done
}

# Main menu
main_menu() {
  action=$(printf "%s\n" \
    "Save new entry" \
    "Decrypt entry" \
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

