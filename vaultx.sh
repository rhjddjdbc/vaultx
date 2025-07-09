#!/usr/bin/env bash
set -euo pipefail
umask 077

if   command -v doas  &>/dev/null; then ESC_CMD="doas"
elif command -v sudo  &>/dev/null; then ESC_CMD="sudo"
else                            ESC_CMD=""
fi

perms=$(stat -Lc '%a' /proc/self/fd)
other=${perms: -1}
if (( other != 0 )); then
  echo "WARNING: /proc/self/fd mode is ${perms}, FDs may leak to other users!" >&2
  if [[ -n $ESC_CMD ]]; then
    echo "Attempting to remount /proc with hidepid=2 via ${ESC_CMD}…" >&2
    $ESC_CMD mount -o remount,hidepid=2 /proc
    if [[ $? -eq 0 ]]; then
      echo "SUCCESS: /proc is now mounted with hidepid=2." >&2
    else
      echo "ERROR: remount failed. Please check your ${ESC_CMD} setup." >&2
    fi
  else
    echo "No sudo/doas found – cannot remount /proc automatically." >&2
  fi
fi

# Session timeout in seconds
export TMOUT=300
readonly TMOUT

# Start a background timer that sends ALRM to this script after TMOUT seconds
start_timer() {
  ( sleep "$TMOUT" && kill -ALRM $$ ) &
  TIMER_PID=$!
}

# Kill the background timer
cleanup_timer() {
  kill "${TIMER_PID:-}" 2>/dev/null || true
}

# Trap handlers
trap 'echo "Error on line $LINENO: $BASH_COMMAND"; cleanup_timer; exit 1' ERR
trap 'echo "Session timed out after '"$TMOUT"' seconds."; cleanup_timer; exit 1' ALRM
trap 'cleanup_timer' EXIT

# initialize timer
start_timer

# Predeclare vars for set -u
MASTER="" HASHED="" STORED_HASH=""
pw="" pw2="" username="" note=""
name="" selected="" action=""

# Vault configuration
VAULT="${VAULT_DIR:-vault}"
MASTER_HASH_FILE="$VAULT/.master_hash"
FAIL_COUNT_FILE="$VAULT/.fail_count"
LAST_FAIL_FILE="$VAULT/.last_fail"
mkdir -p "$VAULT"

# Lockout policy
MAX_ATTEMPTS=5
LOCKOUT_DURATION=600   # seconds

# Securely wipe sensitive variables
secure_unset() {
  local val len var
  for var in MASTER pw pw2 username; do
    val=${!var:-}
    if [[ -n $val ]]; then
      len=${#val}
      printf -v "$var" '%*s' "$len" ''
      unset "$var"
    fi
  done
  unset HASHED STORED_HASH
}

# Constant-time string compare to thwart timing attacks
hash_equals() {
  local a="$1" b="$2"
  (( ${#a} != ${#b} )) && return 1
  local res=0 i
  for (( i=0; i<${#a}; i++ )); do
    res=$(( res | ( $(printf '%d' "'${a:i:1}") ^ $(printf '%d' "'${b:i:1}") ) ))
  done
  (( res == 0 ))
}

# Prompt/init or verify master password, enforce lockout
prompt_and_verify_password() {
  # check for active lockout
  if [[ -f $FAIL_COUNT_FILE && -f $LAST_FAIL_FILE ]]; then
    fails=$(<"$FAIL_COUNT_FILE")
    last=$(<"$LAST_FAIL_FILE")
    now=$(date +%s)
    if (( fails >= MAX_ATTEMPTS && now - last < LOCKOUT_DURATION )); then
      wait_time=$(( LOCKOUT_DURATION - (now - last) ))
      echo "Too many failed attempts. Try again in ${wait_time}s."
      return 1
    fi
  fi

  # read master password
  if ! read -t 60 -s -r -p "Master password (60s timeout): " MASTER; then
    echo -e "\nNo input for 60s. Aborting."
    return 1
  fi
  echo

  # initialize if first run
  if [[ ! -f "$MASTER_HASH_FILE" ]]; then
    HASHED=$(htpasswd -nbB dummy "$MASTER" | cut -d: -f2)
    echo "$HASHED" > "$MASTER_HASH_FILE"
    echo "Master password initialized."
    rm -f "$FAIL_COUNT_FILE" "$LAST_FAIL_FILE"
    return 0
  fi

  # verify stored hash
  STORED_HASH=$(<"$MASTER_HASH_FILE")
  tmp=$(mktemp)
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
    echo "$now"   > "$LAST_FAIL_FILE"
    backoff=$(( fails * 2 ))
    (( backoff > LOCKOUT_DURATION )) && backoff=$LOCKOUT_DURATION
    sleep "$backoff"
    echo "Incorrect master password. Attempt $fails of $MAX_ATTEMPTS."
    return 1
  fi
}

main_menu() {
  action=$(printf "%s\n" \
    "Save new entry" \
    "Decrypt entry" \
    "Delete entry" \
    "Backup vault" \
    "Audit vault" \
    "Exit" \
  | fzf --prompt="Select action: ")
  [[ -z "$action" ]] && echo "No action selected." && exit 1

  case "$action" in
    "Save new entry")
      if ! read -t 30 -r -p "Entry name (e.g. github) [30s]: " name; then
        echo -e "\nTimed out."; exit 1
      fi
      [[ -z "$name" || ! "$name" =~ ^[A-Za-z0-9._-]+$ ]] && echo "Invalid entry name." >&2 && exit 1

      vault_root=$(realpath -m "$VAULT")
      vault_file="$VAULT/$name.bin"
      [[ "$(realpath -m "$vault_file")" != "$vault_root/"* ]] && echo "Invalid path." >&2 && exit 1

      read -t 30 -r -p "Username (optional) [30s]: " username || username=""

      read -t 60 -s -r -p "Password (60s): " pw; echo
      read -t 60 -s -r -p "Repeat password (60s): " pw2; echo
      [[ "$pw" != "$pw2" ]] && echo "Passwords do not match." >&2 && exit 1
      [[ -z "$pw" ]] && echo "Empty password not allowed." >&2 && exit 1

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

      read -t 60 -r -p "Optional note [60s]: " note || note=""
      timestamp=$(date +"%Y-%m-%d %H:%M:%S")
      {
        echo "Label: $name"
        echo "Created: $timestamp"
        echo "Note: $note"
      } > "$VAULT/$name.note"
      chmod 600 "$VAULT/$name.note"

      echo "Saved entry '$name' with HMAC."
      ;;

    "Decrypt entry")
      selected=$(find "$VAULT" -maxdepth 1 -type f -name "*.bin" \
        | fzf --prompt="Choose entry to decrypt: ")
      [[ -z "$selected" ]] && echo "Cancelled." && exit 1

      file="$selected"
      hmac_file="${file%.bin}.hmac"
      [[ ! -f "$hmac_file" ]] && echo "HMAC missing." && exit 1

      prompt_and_verify_password || exit 1

      expected=$(awk '{print $1}' "$hmac_file")
      actual=$(openssl dgst -sha256 -mac HMAC \
        -macopt key:file:/dev/fd/3 "$file" 3<<<"$MASTER" \
        | awk '{print $2}')
      if ! hash_equals "$expected" "$actual"; then
        echo "Integrity check failed."
        secure_unset
        exit 1
      fi

      openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
        -in "$file" -pass fd:3 3<<<"$MASTER" \
        || echo "Decryption failed."

      secure_unset
      ;;

    "Delete entry")
      selected=$(find "$VAULT" -maxdepth 1 -type f -name "*.bin" \
        | fzf --prompt="Select entry to delete: ")
      [[ -z "$selected" ]] && echo "Cancelled." && exit 1

      read -t 30 -r -p "Delete '$(basename "$selected")'? [y/N]: " confirm
      if [[ "$confirm" =~ ^[yY]$ ]]; then
        rm -f "$selected" "${selected%.bin}.hmac" "${selected%.bin}.note"
        echo "Deleted entry."
      else
        echo "Aborted."
      fi
      ;;

    "Backup vault")
      ts=$(date +"%Y%m%d-%H%M%S")
      backup="$HOME/vault-backup-$ts.zip"
      zip -rq "$backup" "$VAULT"
      chmod 600 "$backup"
      echo "Backup created at $backup."
      ;;

    "Audit vault")
      echo "Vault contents:"
      find "$VAULT" -maxdepth 1 -name "*.bin" | while read -r e; do
        n=$(basename "$e" .bin)
        m=$(stat -c '%y' "$e")
        echo "- $n (modified: $m)"
        [[ -f "$VAULT/$n.note" ]] && head -n3 "$VAULT/$n.note" | sed 's/^/    /'
      done
      ;;

    "Exit")
      echo "Goodbye."
      exit 0
      ;;
  esac
}

main_menu
