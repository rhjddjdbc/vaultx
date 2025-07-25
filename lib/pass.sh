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
prompt_and_verify_password() {
  # Check for lockout
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

  # Prompt user
  if ! read -t 60 -s -r -p "Master password for '$vault_choice' vault (timeout 60s): " MASTER; then
    echo -e "\nTimeout or no input. Aborting." >&2
    return 1
  fi
  echo

  # First-time password setup
  if [[ ! -f "$MASTER_HASH_FILE" ]]; then
    HASHED=$(htpasswd -nbB -C "$PASSWORD_COST" dummy "$MASTER" | cut -d: -f2)
    echo "$HASHED" > "$MASTER_HASH_FILE"
    chmod 600 "$MASTER_HASH_FILE"
    echo "Master password initialized successfully for '$vault_choice'." >&2
    rm -f "$FAIL_COUNT_FILE" "$LAST_FAIL_FILE"
    return 0
  fi

  # Load stored hash
  STORED_HASH=$(<"$MASTER_HASH_FILE")
  tmp=$(mktemp)
  printf 'dummy:%s\n' "$STORED_HASH" > "$tmp"

  # Verify password WITHOUT using -C (fix)
  if htpasswd -vbB "$tmp" dummy "$MASTER" &>/dev/null; then
    rm -f "$tmp" "$FAIL_COUNT_FILE" "$LAST_FAIL_FILE"

    # Optional: rehash with higher cost if desired
    # if [[ "$STORED_HASH" =~ ^\$2[aby]?\$([0-9]{2})\$ ]]; then
    #   current_cost="${BASH_REMATCH[1]}"
    #   if (( current_cost < PASSWORD_COST )); then
    #     NEW_HASH=$(htpasswd -nbB -C "$PASSWORD_COST" dummy "$MASTER" | cut -d: -f2)
    #     echo "$NEW_HASH" > "$MASTER_HASH_FILE"
    #     chmod 600 "$MASTER_HASH_FILE"
    #   fi
    # fi

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
    echo "Invalid master password for '$vault_choice'. Attempt $fails of $MAX_ATTEMPTS." >&2
    return 1
  fi
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
    return 0  # return 0 if no breach check is done (i.e., API not reachable)
  fi

  # Check if the suffix appears in the response
  while read -r line; do
    hash=${line%%:*}
    if [[ "$hash" == "$suffix" ]]; then
       
       echo -e "\033[1;33mPassword got breached.\033[0m" >&2
       return 1  # Return 1 to signal the password should not be saved
    fi
   done <<< "$response"

  return 0  # return 0 if no issues found
}
