# VaultX – Secure Command-Line Password Manager

**VaultX** is a minimal, script-based password manager for the command line. It allows you to securely manage multiple isolated vaults, use strong encryption, perform password breach checks, export QR codes, **and now log all major actions** — all within a transparent and portable Bash script.

---

## Features

* **Multiple Vaults**: Separate storage areas (e.g., for personal, work, family, or clients)
* **Master Password Protection**: Each vault is protected by its own master password
* **Strong Encryption**: AES-256-CBC with PBKDF2 (200,000 iterations) and HMAC integrity
* **Fuzzy Selection Menus**: Interactive vault, action, and entry selection via `fzf`
* **Clipboard Integration**: Copied passwords are automatically cleared after 30 seconds
* **Secure Password Generation**: Random password creation with configurable length
* **Optional Breach Check**: Query Have I Been Pwned (HIBP) API using SHA-1 k-anonymity model
* **Vault Backups**: Vault directories are zipped with secure permissions (`chmod 600`)
* **Vault List**: Overview of stored entries with last-modified timestamps
* **QR Code Export**: Display password as ASCII QR code directly in the terminal
* **Brute-Force Protection**: Lockout mechanism with exponential backoff on repeated failures
* **Secure Memory Cleanup**: Temporary variables are zeroed and unset after usage
* **script/cli mode**: for add, get, delete, audit, Backup vault/ all vaults
* **Action Logging**: All major operations are logged with timestamps and user, including vault access, entry changes, Vault creation, password output actions (such as copying to clipboard or displaying as QR code — without logging or storing the password itself and the **username of the associated website** or service,) as well as failed authentications.
* **Help function**: Outputs a documentation.

---

## Requirements

**Required tools:**

* `bash` ≥ 4.0
* `openssl`
* `htpasswd` (from `apache2-utils` or `httpd-tools`)

**Optional tools:**

* `xclip` or `wl-clipboard` (clipboard support)
* `qrencode` (QR code rendering in the terminal)
* `curl`
* `fzf`
  
---

## Installation

```bash
git clone https://github.com/rhjddjdbc/vaultx.git
cd vaultx
chmod +x vaultx.sh lib/*.sh
```

Optional: create a configuration file:

```bash
mkdir -p ~/.config/vaultx
nano ~/.config/vaultx/config.env
```

Example `config.env`:

```bash
# ~/.config/vaultx/config.env
###################################################
#                                                 #
#                            _ _                  #
#          /\   /\__ _ _   _| | |___  __          #
#          \ \ / / _` | | | | | __\ \/ /          #
#           \ V / (_| | |_| | | |_ >  <           #
#            \_/ \__,_|\__,_|_|\__/_/\_\          #
#                                                 #
#                   V A U L T X                   #
#            Locked. Encrypted. Yours.            #
#                                                 #
###################################################
# Base directories
VAULT_DIR="$HOME/.vault"            # Directory where vaults are stored
BACKUP_DIR="$HOME/vault_backups"    # Location for encrypted vault backups
LOG_FILE="$HOME/.vaultx.log"        # log file


# Password options
PASSWORD_LENGTH=36                  # Default length for generated passwords
PASSWORD_COST=16                    # BCrypt cost factor for master hash strength
HIBP_CHECK_CLI=true                 # Auto breach check for cli mode

# Security settings
MAX_ATTEMPTS=5                      # Max allowed login attempts before lockout
LOCKOUT_DURATION=600                # Seconds after max attempts
TAMPER_LOCKOUT_DURATION=900         # Lockout if lockout file is missing (tampering)
LOGGING_ENABLED=true                # enabeling logging
```

## Installation for Arch Linux Users

You can build and install VaultX directly from the provided PKGBUILD:

```bash
git clone https://github.com/rhjddjdbc/vaultx-arch-PKGBUILD.git
cd vaultx-arch-PKGBUILD
makepkg -si
```

---

## Usage

### Help function
```bash
./vaultx.sh --help
./vaultx.sh -h
```

Run the script:

```bash
./vaultx.sh
```

At startup, VaultX prompts you to select or create a vault, then shows the main menu:

### Main Menu Options

1. **Save New Entry**

   * Enter an entry name (e.g. `github`), optional username, and password (manual or generated)
   * Optionally check for breaches using HIBP
   * The entry is encrypted and integrity-protected

2. **Decrypt Entry**

   * Select an entry via `fzf`
   * After master password verification and HMAC validation, you can:

     * Display, copy, or QR-export the password
     * Perform a breach check
     * Show the username (unless QR or breach mode is chosen)

3. **Edit Existing Entry**

   * Update username and/or password
   * The script re-encrypts and recalculates HMAC

4. **Delete Entry**

   * Removes the `.bin` and `.hmac` files after confirmation

5. **Backup Vault**

   * Creates a ZIP archive of the vault, timestamped and permission-restricted, in the configured backup directory

6. **List Vault**

   * Displays all entries with last-modified timestamps

7. **Exit**

   * Quit the script

---

## Vault Structure

```
~/.vault/
  ├── default/
  │   ├── github.bin
  │   ├── github.hmac
  │   ├── .master_hash
  │   ├── .fail_count
  │   └── .last_fail
  └── work/
```

---

## Configurable Settings

Located in `~/.config/vaultx/config.env`:

| Variable           | Description                                                      |
| ------------------ | ---------------------------------------------------------------- |
| `VAULT_DIR`        | Base directory for storing all vaults                            |
| `PASSWORD_LENGTH`  | Default length for generated passwords                           |
| `PASSWORD_COST`    | BCrypt cost factor for master password hashing                   |
| `BACKUP_DIR`       | Directory where ZIP backups are saved                            |
| `MAX_ATTEMPTS`     | Max failed login attempts before lockout (default: 5)            |
| `LOCKOUT_DURATION` | Lockout duration in seconds after failed attempts (default: 600) |
| `LOGGING_ENABLED`  | Enable or disable logging (`true` or `false`)                    |
| `LOG_FILE`         | Path to the log file                                             |
---

## Security Overview

* **Master Password**

  * Stored using bcrypt (via `htpasswd -B -C`)
  * Lockout with exponential backoff on repeated failures

* **Entry Encryption**

  * AES-256-CBC with PBKDF2 (200,000 iterations), salt, and per-entry HMAC

* **Clipboard and QR Safety**

  * Automatic clearance after 30 seconds
  * QR codes are removed after display

* **Breach Checking**

  * Uses SHA-1 k-anonymity: only the hash prefix is communicated
  * Completely optional; no password leaves the system unless explicitly requested

---

## Logging Feature

VaultX includes a logging system that records all significant actions for auditing and debugging.

### What is logged

- Vault and entry operations (create, edit, decrypt, delete)
- Authentication attempts, including failures
- Timestamp for every event
- Vault and entry references (never the actual password or decrypted content)

### Security Note

VaultX does not log sensitive information such as plaintext passwords, decrypted content, or master passwords.

### Example log output
```bash
[2025-07-30 17:09:42] [user:user] Interactive: FAILED AUTHENTICATION by saving new password in Vault: 'default'.
[2025-07-30 17:09:59] [user:user] Interactive: Selected action: 'Decrypt entry', vault: 'default'.
[2025-07-30 17:10:12] [user:user] Interactive: FAILED AUTHENTICATION by decrypting '~/.vault/default/github.bin' in Vault: 'default'.
[2025-07-30 17:12:25] [user:user] Interactive: Selected action: 'List vault', vault: 'default'.
[2025-07-30 17:12:54] [user:user] Interactive: Selected action: 'Delete entry', vault: 'job' entry: '~/.vault/job/asdfjj.bin'
[2025-07-30 17:13:32] [user:user] Interactive: FAILED AUTHENTICATION by editing '~/.vault/job/slack.bin' in Vault: 'job'.
[2025-07-30 17:13:32] [user:user] Interactive: Selected action: 'Edit existing entry', vault: 'job' entry: '~/.vault/job/slack.bin'
```
### Lockout 
---VaultX includes a tamper-resistant lockout system that protects against brute-force attacks:

- After `MAX_ATTEMPTS` failed master password logins, the vault enters lockout for `LOCKOUT_DURATION` seconds.
- Each vault stores its own lockout metadata in:
```
~/.vault/<vault>/ 
  ├── .lockout_state      # Tracks failed attempts and last failure timestamp 
  ├── .lockout_secret     # HMAC key to verify lockout file integrity 
  └── .tamper_lock        # Temporary lock if tampering is detected
```
- `.lockout_state` is signed with an HMAC to detect file manipulation.
- If the signature is invalid or the file is missing, a one-time tamper lock is applied (duration: `TAMPER_LOCKOUT_DURATION`).
- Lockout files are set to `chmod 600`.

> This mechanism ensures that vault access is protected even if an attacker tries to reset the state manually.

---

### config.env Security

The user config file `~/.config/vaultx/config.env` contains paths and security settings.

VaultX verifies and enforces:

- `chmod 644` permissions
- Ownership by `root:root`  
- If incorrect, VaultX uses `sudo` or `doas` to fix it automatically
- If neither is available, the script exits with an error

This ensures the config is readable only as intended and cannot be silently altered by other users.

---

## CLI Mode Usage

VaultX supports a **CLI mode** that allows you to perform essential operations directly via command line flags without interactive menus.

### General Options

| Flag             | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--cli`          | Enables CLI mode                                             |
| `-v, --vault`    | Specify the vault name (e.g., `default`)                     |
| `-a, --action`   | Action to perform: `add`, `get`, `delete`, `backup`, `audit` |
| `-e, --entry`    | Entry name (required for `add`, `get`, `delete`)             |
| `-u, --username` | Username for the entry (used with `add`)                     |
| `-m, --method`   | Password method for `add`: `manual` or `generate`            |
| `--all`          | Flag for the `backup` action: backup all vaults              |

---

### 1. **Add a new entry**

Using manual password input:

```bash
./vaultx.sh --cli --vault default --action add --entry github --username your_username --method manual
```

Using automatically generated password:

```bash
./vaultx.sh --cli --vault default --action add --entry github --username your_username --method generate
```

---

### 2. **Get an entry**

Retrieve the username and password after master password prompt:

```bash
./vaultx.sh --cli --vault default --action get --entry github
```

---

### 3. **Delete an entry**

Securely removes the specified entry:

```bash
./vaultx.sh --cli --vault default --action delete --entry github
```

---

### 4. **Backup vault**

Backup a single vault:

```bash
./vaultx.sh --cli --vault default --action backup
```

Backup **all vaults** using the `--all` flag:

```bash
./vaultx.sh --cli --action backup --all
```

---

### 5. **List vault**

Displays all entries with last-modified timestamps:

```bash
./vaultx.sh --cli --vault default --action list
```

---

### Example

Backup all vaults via cron job:

```bash
0 3 * * * /path/to/vaultx.sh --cli --action backup --all
```

---

## License

VaultX is licensed under the **GNU General Public License v3.0** (GPL‑3.0). See the `LICENSE` file for details.
