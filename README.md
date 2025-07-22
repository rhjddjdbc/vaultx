# VaultX – Secure Command-Line Password Manager

**VaultX** is a minimal, script-based password manager for the command line. It allows you to securely manage multiple isolated vaults, use strong encryption, perform password breach checks, and export QR codes—all within a transparent and portable Bash script.

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
* **Vault Audit**: Overview of stored entries with last-modified timestamps
* **QR Code Export**: Display password as ASCII QR code directly in the terminal
* **Brute-Force Protection**: Lockout mechanism with exponential backoff on repeated failures
* **Secure Memory Cleanup**: Temporary variables are zeroed and unset after usage
* **basic script/cli mode**: for add, get, delete

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
chmod +x vaultx.sh
chmod +x lib/pass.sh
chmod +x lib/tools.sh
chmod +x lib/option.sh
chmod +x lib/cli.sh
chmod +x lib/vault.sh
```

Optional: create a configuration file:

```bash
mkdir -p ~/.config/vaultx
nano ~/.config/vaultx/config.env
```

Example `config.env`:

```bash
# config.env
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

# Password options
PASSWORD_LENGTH=24                  # Default length for generated passwords
PASSWORD_COST=16                    # BCrypt cost factor for master hash strength
HIBP_CHECK_CLI=true                 # Auto breach check for cli mode

# Security settings
MAX_ATTEMPTS=5                      # Max allowed login attempts before lockout
LOCKOUT_DURATION=600                # Duration of lockout in seconds after failures
```

---

## Usage

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

6. **Audit Vault**

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

## CLI Mode Usage

VaultX now supports a **CLI mode**, allowing you to perform essential operations (`add`, `get`, `delete`) via command-line flags without the need for interactive menus.

### 1. **Add an Entry**

To add a new entry (e.g., `github`) with a username and password:

```bash
./vaultx.sh --cli --vault default --action add --entry github --username your_username --password your_password
```

You can also generate a password automatically for the entry:

```bash
./vaultx.sh --cli --vault default --action add --entry github --username your_username --generate
```

---

### 2. **Get an Entry**

To retrieve an entry (e.g., `github`) and show the username and password:

```bash
./vaultx.sh --cli --vault default --action get --entry github
```

This command will prompt you for the master password and then show the username and password for the entry.

---

### 3. **Delete an Entry**

To delete an entry (e.g., `github`):

```bash
./vaultx.sh --cli --vault default --action delete --entry github
```

This will securely remove the entry’s data from the vault.

---

## Example Usage Flow

1. **Add an entry** (with manual username and password):

   ```bash
   ./vaultx.sh --cli --vault default --action add --entry github --username myuser --password mypassword
   ```

2. **Get the entry**:

   ```bash
   ./vaultx.sh --cli --vault default --action get --entry github
   ```

3. **Delete the entry**:

   ```bash
   ./vaultx.sh --cli --vault default --action delete --entry github
   ```

---

## License

VaultX is licensed under the **GNU General Public License v3.0** (GPL‑3.0). See the `LICENSE` file for details.
