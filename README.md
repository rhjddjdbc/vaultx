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

---

## Requirements

**Required tools:**

* `bash` ≥ 4.0
* `openssl`
* `htpasswd` (from `apache2-utils` or `httpd-tools`)
* `curl`
* `fzf`

**Optional tools:**

* `xclip` or `wl-clipboard` (clipboard support)
* `qrencode` (QR code rendering in the terminal)

---

## Installation

```bash
git clone https://github.com/yourusername/vaultx.git
cd vaultx
chmod +x vaultx.sh
```

Optional: create a configuration file:

```bash
mkdir -p ~/.config/vaultx
nano ~/.config/vaultx/config.env
```

Example `config.env`:

```bash
VAULT_DIR="$HOME/.vaultx"
PASSWORD_LENGTH=24
PASSWORD_COST=16
BACKUP_DIR="$HOME/vault_backups"
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
  │   ├── github.note     (optional)
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

## License

VaultX is licensed under the **GNU General Public License v3.0** (GPL‑3.0). See the `LICENSE` file for details.
