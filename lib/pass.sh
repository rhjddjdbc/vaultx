# lib/pass.sh

########################################################################
# Generate password prompt
# Allows user to either enter password manually or generate a secure one
########################################################################
generate_password_prompt() {
  local choice pw copy_choice custom_len
  choice=$(printf "%s\n" "Enter manually" "Generate secure password" | fzf --prompt="Choose password method: ")

  case "$choice" in
    "Enter manually")
      read -t 60 -s -r -p "Password (timeout 60s): " pw; echo >&2
      read -t 60 -s -r -p "Repeat password (timeout 60s): " pw2; echo >&2

      if [[ "$pw" != "$pw2" ]]; then
        echo "Passwords do not match." >&2
        return 1
      fi

      if [[ -z "$pw" ]]; then
        echo "Empty password not allowed." >&2
        return 1
      fi

      read -r -p "Do you want to check if this password has appeared in data breaches? [y/N]: " check_choice
      if [[ "$check_choice" =~ ^[Yy]$ ]]; then
        if ! check_pwned_password "$pw"; then
          return 1
        fi
      fi

      printf '%s' "$pw"
      ;;

    "Generate secure password")
      read -r -p "Desired password length (default: $PASSWORD_LENGTH): " custom_len
      custom_len="${custom_len:-$PASSWORD_LENGTH}"

      if ! [[ "$custom_len" =~ ^[0-9]+$ ]]; then
        echo "Invalid length input." >&2
        return 1
      fi

      pw=$(LC_ALL=C tr -dc 'A-Za-z0-9@#%&+=_' </dev/urandom | head -c "$custom_len")
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

##########################################################################
# Prompt and verify master password
# Handles lockout logic on repeated failures and compares hashed passwords
##########################################################################
LOCKOUT_STATE_FILE="$VAULT_DIR/.lockout_state"
LOCKOUT_SECRET_FILE="$VAULT_DIR/.lockout_secret"

# === Initialize lockout secret if missing ===
init_lockout_secret() {
  mkdir -p "$VAULT_DIR"
  if [[ ! -f "$LOCKOUT_SECRET_FILE" ]]; then
    head -c 32 /dev/urandom | hexdump -v -e '/1 "%02x"' > "$LOCKOUT_SECRET_FILE"
    chmod 600 "$LOCKOUT_SECRET_FILE"
  fi
}

# === Load lockout secret from file ===
load_lockout_secret() {
  LOCKOUT_SECRET=$(<"$LOCKOUT_SECRET_FILE")
}

# === Calculate HMAC for integrity check ===
calc_hmac() {
  local data="$1"
  echo -n "$data" | openssl dgst -sha256 -hmac "$LOCKOUT_SECRET" | awk '{print $2}'
}

# === Read lockout state from file ===
TAMPER_LOCK_FILE="$VAULT_DIR/.tamper_lock"

read_lockout_state() {
  local now
  now=$(date +%s)

  if [[ -f "$TAMPER_LOCK_FILE" ]]; then
    local tamper_start
    tamper_start=$(<"$TAMPER_LOCK_FILE")
    local elapsed=$(( now - tamper_start ))

    if (( elapsed < TAMPER_LOCKOUT_DURATION )); then
      local remaining=$(( TAMPER_LOCKOUT_DURATION - elapsed ))
      echo "Vault tampering detected. Retry in $remaining seconds." >&2
      exit 1
    else
      echo "Tamper lock expired. Creating new lockout state." >&2
      rm -f "$TAMPER_LOCK_FILE"
      write_lockout_state 0 0
      global_fails=0
      global_last=0
      return
    fi
  fi

  if [[ -f "$LOCKOUT_STATE_FILE" ]]; then
    local line
    line=$(<"$LOCKOUT_STATE_FILE")
    IFS=":" read -r fails last sig <<< "$line"
    local data="$fails:$last"
    local expected_sig
    expected_sig=$(calc_hmac "$data")

    if [[ "$sig" != "$expected_sig" ]]; then
      echo "Lockout state was manipulated!" >&2
      if [[ -f "$MASTER_HASH_FILE" ]]; then
        echo "A one-time lockout of $TAMPER_LOCKOUT_DURATION seconds will be applied due to manipulation." >&2
        echo "$now" > "$TAMPER_LOCK_FILE"
        exit 1
      else
        global_fails=9999
        global_last=$now
        return
      fi
    fi

    if (( fails >= MAX_ATTEMPTS )); then
      if (( now - last < LOCKOUT_DURATION )); then
        global_fails=$fails
        global_last=$last
        return
      else
        fails=0
        last=0
        write_lockout_state "$fails" "$last"
      fi 
    fi

    global_fails=$fails
    global_last=$last

  elif [[ ! -f "$MASTER_HASH_FILE" ]]; then
    global_fails=0
    global_last=0

  else
    echo "Lockout state file missing! Creating new state with a one-time lockout." >&2
    echo "A one-time lockout of $TAMPER_LOCKOUT_DURATION seconds will be applied." >&2
    echo "$now" > "$TAMPER_LOCK_FILE"
    exit 1
  fi
}

write_lockout_state() {
  local fails="$1"
  local last="$2"
  local data="$fails:$last"
  local sig
  sig=$(calc_hmac "$data")
  echo "$fails:$last:$sig" > "$LOCKOUT_STATE_FILE"
  chmod 600 "$LOCKOUT_STATE_FILE"
  log_action "Lockout state written: $fails fails, last attempt at $last"
}


prompt_and_verify_password() {
  local now
  now=$(date +%s)

  read_lockout_state  

  if (( global_fails >= MAX_ATTEMPTS )); then
    if (( now - global_last < LOCKOUT_DURATION )); then
      local wait_time=$(( LOCKOUT_DURATION - (now - global_last) ))
      echo "Too many failed attempts. Retry in $wait_time seconds." >&2
      return 1
    fi
  fi

  if ! read -t 60 -s -r -p "Master password for '$vault_choice' vault (timeout 60s): " MASTER; then
    echo -e "\nTimeout or no input. Aborting." >&2
    return 1
  fi
  echo

  if [[ ! -f "$MASTER_HASH_FILE" ]]; then
    if [[ "$MASTER_HASH_ALGO" == "argon2" ]]; then
      SALT=$(head -c "$ARGON2_SALT_BYTES" /dev/urandom | base64)
      HASHED=$(echo -n "$MASTER" | argon2 "$SALT" -id \
               -t "$ARGON2_TIME" -m "$ARGON2_MEMORY" -p "$ARGON2_THREADS" -e)
      { echo "$SALT"; echo "$HASHED"; } > "$MASTER_HASH_FILE"
    else
      HASHED=$(htpasswd -nbB -C "$PASSWORD_COST" dummy "$MASTER" | cut -d: -f2)
      echo "$HASHED" > "$MASTER_HASH_FILE"
    fi
    chmod 600 "$MASTER_HASH_FILE"
    echo "Master password initialized successfully for '$vault_choice'." >&2
    write_lockout_state 0 0
    return 0
  fi

  read -r FIRST_LINE < "$MASTER_HASH_FILE"
  if [[ "$FIRST_LINE" =~ ^\$argon2 ]]; then
    STORED_HASH="$FIRST_LINE"
    if [[ "$(echo -n "$MASTER" | argon2 "" -id \
             -t "$ARGON2_TIME" -m "$ARGON2_MEMORY" -p "$ARGON2_THREADS" -e)" == "$STORED_HASH" ]]; then
      write_lockout_state 0 0
      return 0
    fi
  elif [[ "$FIRST_LINE" =~ ^[A-Za-z0-9+/=]+$ ]]; then
    SALT="$FIRST_LINE"
    STORED_HASH=$(tail -n +2 "$MASTER_HASH_FILE")
    if [[ "$(echo -n "$MASTER" | argon2 "$SALT" -id \
             -t "$ARGON2_TIME" -m "$ARGON2_MEMORY" -p "$ARGON2_THREADS" -e)" == "$STORED_HASH" ]]; then
      write_lockout_state 0 0
      return 0
    fi
  elif [[ "$FIRST_LINE" =~ ^\$2[aby]\$ ]]; then
    # bcrypt
    STORED_HASH="$FIRST_LINE"
    local tmp
    tmp=$(mktemp)
    printf 'dummy:%s\n' "$STORED_HASH" > "$tmp"
    if htpasswd -vbB "$tmp" dummy "$MASTER" &>/dev/null; then
      rm -f "$tmp"
      write_lockout_state 0 0
      return 0
    fi
    rm -f "$tmp"
  else
    echo "Unknown master password format for vault '$vault_choice'." >&2
    return 1
  fi

  now=$(date +%s)
  global_fails=$((global_fails + 1))
  (( global_fails > MAX_ATTEMPTS )) && global_fails=$MAX_ATTEMPTS
  write_lockout_state "$global_fails" "$now"

  local backoff=$(( global_fails * 2 ))
  (( backoff > LOCKOUT_DURATION )) && backoff=$LOCKOUT_DURATION
  sleep "$backoff"

  echo "Invalid master password for '$vault_choice'. Attempt $global_fails of $MAX_ATTEMPTS." >&2
  return 1
}

########################################################################
# Check password against Have I Been Pwned API (using K-Anonymity model)
# Returns 1 if breached, 0 if clean or API unreachable
########################################################################
check_pwned_password() {
  local password="$1"
  local sha1hash prefix suffix response line hash

  # SHA1 hash in uppercase
  sha1hash=$(printf '%s' "$password" | sha1sum | awk '{print toupper($1)}')
  prefix=${sha1hash:0:5}
  suffix=${sha1hash:5}

  # Query the API using K-Anonymity
  response=$(curl -s "https://api.pwnedpasswords.com/range/$prefix")
  if [[ -z "$response" ]]; then
    echo "Warning: Unable to reach HIBP API. Password was not checked." >&2
    log_action "Warning: Unable to reach HIBP API. Password was not checked." >&2
    return 0  # return 0 if no breach check is done (i.e., API not reachable)
  fi

  # Check if the suffix appears in the response
  while read -r line; do
    hash=${line%%:*}
    if [[ "$hash" == "$suffix" ]]; then
       
       echo -e "\033[1;33mPassword got breached.\033[0m" >&2
       log_action "Password got breached Vault: '$vault_choice', entry: '$selected'." 
       return 1  # Return 1 to signal the password should not be saved
    fi
   done <<< "$response"

  return 0  # return 0 if no issues found
}
