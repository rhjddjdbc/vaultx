# VaultX - Secure Command-Line Password Manager

VaultX is a secure, minimal, and auditable password manager written in Bash. It allows you to manage multiple isolated vaults, store encrypted credentials, and perform optionally breach checks against the [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/) database. It’s designed with simplicity, transparency, and privacy in mind.

## Features

* **Multiple Vaults**: Isolated vaults for separation of data (e.g., personal, work, family, or client).
* **Strong Encryption**: Uses AES-256-CBC with PBKDF2 (200,000 iterations) and per-entry HMACs.
* **Master Password Authentication**: Vaults are protected by individual master passwords.
* **Clipboard Integration**: Passwords can be copied to clipboard and are auto-cleared after 30 seconds.
* **Password Generator**: Secure password generation via `openssl rand`.
* **Optional Breach Check**: Query HIBP API using K-Anonymity (SHA-1 prefix) to check if passwords appear in public leaks.
* **ASCII QR Code Output**: Optionally render credentials as QR codes in the terminal.
* **Vault Audit**: View a list of all entries with last modified timestamps and optional note previews.
* **Lockout Protection**: Repeated failed attempts trigger backoff and temporary vault lockout.
* **Encrypted Backups**: Vault directories can be zipped for backup with proper permissions.
* **Minimal Dependencies**: Works on any Unix-like system with standard tools and optional extras for advanced features.

---

## Requirements

* `bash` ≥ 4.0
* `openssl`
* `htpasswd` (from `apache2-utils` or `httpd-tools`)
* `curl` (for HIBP breach check)
* `fzf` (for fuzzy search menus)

### Optional Tools

* `xclip` or `wl-copy` (for clipboard integration)
* `qrencode` (to generate ASCII QR codes)

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/vaultx.git
   cd vaultx
   ```

2. Make the script executable:

   ```bash
   chmod +x vaultx.sh
   ```

3. (Optional) Create a configuration file:

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

4. Run the script:

   ```bash
   ./vaultx.sh
   ```

---

## Usage

Upon startup, VaultX will prompt you to select or create a vault, then show a main menu of actions.

### 1. Save New Entry

* Select a vault and provide:

  * Entry name
  * Optional username
  * Password (manually entered or generated)
* You will be prompted to optionally check the password against the HIBP breach database before saving.
* Entries are encrypted using your vault’s master password.

### 2. Decrypt Entry

* Select a saved entry from your vault.
* After master password verification and HMAC integrity check, you can:

  * Display the password
  * Copy it to clipboard
  * Show it as an ASCII QR code
  * Perform a breach check
* The username (if present) is also shown unless QR or breach modes are selected.

### 3. Delete Entry

* Select an entry to remove.
* Deletes the `.bin` file and associated `.hmac` and `.note` files after confirmation.

### 4. Backup Vault

* Zips the current vault directory to a timestamped archive in the configured backup directory.
* Output file is created with `chmod 600`.

### 5. Audit Vault

* Lists all `.bin` entries in the current vault.
* Displays last modified timestamp and up to three lines from optional `.note` files.

---

## Security Details

### Master Password and Hashing

* The master password is stored using bcrypt via `htpasswd` (`-B -C` options).
* The vault enforces a lockout after multiple failed attempts, with exponential backoff.

### Encryption

* All entries are encrypted with `openssl enc -aes-256-cbc` using:

  * PBKDF2 with 200,000 iterations
  * AES-256 and a salt
* Each entry is signed with an HMAC-SHA256 to ensure tamper-resistance.

### Clipboard and QR Safety

* Clipboard contents are cleared automatically after 30 seconds.
* QR codes auto-clear from the terminal screen after 30 seconds.

### Breach Checking

* Uses the HIBP API with SHA-1 k-anonymity range queries.
* Only the first 5 characters of the password’s hash are sent to HIBP.
* The check is strictly **opt-in**, preserving your privacy.

---

## Configuration File

Location: `$HOME/.config/vaultx/config.env`

Available variables:

| Variable           | Description                                       |
| ------------------ | ------------------------------------------------- |
| `VAULT_DIR`        | Base directory for storing all vaults             |
| `PASSWORD_LENGTH`  | Default length for generated passwords            |
| `PASSWORD_COST`    | Bcrypt cost factor for master password hashing    |
| `BACKUP_DIR`       | Directory where `.zip` backups are saved          |
| `MAX_ATTEMPTS`     | Max failed login attempts before lockout          |
| `LOCKOUT_DURATION` | Lockout duration in seconds after failed attempts |

Example:

```bash
VAULT_DIR="$HOME/.vaultx"
PASSWORD_LENGTH=24
BACKUP_DIR="$HOME/vault_backups"
MAX_ATTEMPTS=5
LOCKOUT_DURATION=600
```

---

## Vault Structure

Each vault is a self-contained directory:

```
~/.vault/
  ├── personal/
  │   ├── github.bin
  │   ├── github.hmac
  │   ├── github.note (optional)
  │   ├── .master_hash
  │   ├── .fail_count
  │   └── .last_fail
  └── work/
```

* `.bin`: Encrypted password + username
* `.hmac`: Integrity signature for the `.bin` file
* `.note`: Optional plain text note
* `.master_hash`: bcrypt-hashed master password
* `.fail_count`, `.last_fail`: Lockout tracking files

---

## License

VaultX is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the `LICENSE` file for full terms.
