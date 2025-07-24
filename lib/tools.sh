# lib/tools.sh

###########################################################
# Constant-time string comparison to prevent timing attacks
# Returns 0 if strings are equal, 1 otherwise
###########################################################
hash_equals() {
  local a="$1" b="$2"
  (( ${#a} != ${#b} )) && return 1
  local res=0 i
  for (( i=0; i<${#a}; i++ )); do
    res=$(( res | ( $(printf '%d' "'${a:i:1}") ^ $(printf '%d' "'${b:i:1}") ) ))
  done
  (( res == 0 ))
}

#########################################################
# Copy input string to clipboard and auto-clear after 30s
# Supports wl-copy and xclip
#########################################################
copy_to_clipboard() {
  local timeout=30

  if command -v wl-copy &>/dev/null; then
    echo "$1" | wl-copy
    echo "Copied to clipboard using wl-copy. It will be cleared in $timeout seconds." >&2

    ( sleep "$timeout" && wl-copy < /dev/null ) >/dev/null 2>&1 &
  elif command -v xclip &>/dev/null; then
    echo "$1" | xclip -selection clipboard
    echo "Copied to clipboard using xclip. It will be cleared in $timeout seconds." >&2

    ( sleep "$timeout" && echo -n | xclip -selection clipboard ) >/dev/null 2>&1 &
  else
    echo "No clipboard tool found. Install wl-clipboard or xclip." >&2
  fi
}

###########################################################
# Display a temporary QR code of the secret in the terminal
# Requires qrencode; clears after 30 seconds
###########################################################
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
