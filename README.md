# VaultX - Secure Password Manager

VaultX is a command-line-based password manager designed to securely store, manage, and retrieve passwords. It uses strong encryption and integrates with the **Have I Been Pwned** (HIBP) API to check if a password has been involved in any known data breaches. VaultX is implemented in Bash and requires minimal dependencies to function.

## Features

* **Password Storage**: Securely store passwords and related information in encrypted files.
* **Master Password**: Passwords are encrypted using a master password, ensuring that only the user can access their vault.
* **Password Breach Check**: Before saving a password, VaultX will ask if you would like to check the password against the **Have I Been Pwned** (HIBP) database to ensure it hasn't been compromised in a breach. The password check will **not** be done automatically; it requires user confirmation to proceed.
* **Clipboard Support**: Copy passwords to the clipboard (with automatic expiration after 30 seconds).
* **ASCII QR Code**: Display passwords as an ASCII QR code for quick access on other devices.
* **Timeout Mechanism**: Session timeout to automatically log out after a period of inactivity.
* **Lockout Mechanism**: Prevent brute force attacks by locking the vault after a specified number of failed attempts.
* **Vault Backup**: Create encrypted backups of your vault.
* **Entry Audit**: Audit existing vault entries and view basic details such as modification time and notes.

## Requirements

* **Bash** (version 4.0 or above)
* **openssl** for AES-256-CBC encryption
* **htpasswd** for password hashing
* **curl** (optional, for HIBP breach check)
* **fzf** for fuzzy searching entries (optional)
* **xclip** or **wl-copy** for clipboard functionality (optional)
* **qrencode** for generating ASCII QR codes (optional)

## Installation

1. Clone the repository or download the script file `vaultx.sh`.

   ```bash
   git clone https://github.com/yourusername/vaultx.git
   cd vaultx
   ```

2. Make the script executable:

   ```bash
   chmod +x vaultx.sh
   ```

3. Create a configuration file at `$HOME/.config/vaultx/config.env` (optional but recommended).

   Example:

   ```bash
   VAULT_DIR="$HOME/.vaultx"
   PASSWORD_LENGTH=24
   BACKUP_DIR="$HOME/vault_backups"
   ```

4. Run the script:

   ```bash
   ./vaultx.sh
   ```

## Usage

When you run the script, it will prompt you with a menu of options to choose from. Below are the key features and how to use them:

### 1. **Save New Entry**

* Create a new password entry in the vault.
* You will be prompted to enter a name, username (optional), and password.
* Passwords can be generated or entered manually.
* **Breach Check**: Before saving the password, VaultX will ask if you want to check the password against the **Have I Been Pwned** (HIBP) database. If the password has been involved in a breach, the script will notify you. However, the breach check **does not happen automatically**. It requires explicit user confirmation to proceed with the check.
* Once saved, the password and associated username are encrypted with your master password.

### 2. **Decrypt Entry**

* Decrypt a password entry from the vault.
* Select the entry using `fzf` (a fuzzy search tool).
* You can choose to display the password, copy it to the clipboard, or display it as an ASCII QR code.
* If you want, you can also check if the password has been leaked, against the **Have I Been Pwned** (HIBP) database.

### 3. **Delete Entry**

* Delete an existing entry from the vault.
* After selecting an entry, you will be asked for confirmation before deletion.
* The associated password, HMAC, and note files will be removed.

### 4. **Backup Vault**

* Create an encrypted backup of your vault directory.
* The backup is saved as a `.zip` file in the backup directory.

### 5. **Audit Vault**

* List all vault entries and show basic information (such as the label, last modified time, and optional notes).

### 6. **Exit**

* Exit the script.

## Security Considerations

### Master Password

* The **master password** is used to encrypt and decrypt all stored passwords. Ensure that you choose a strong master password and do not forget it.
* The script does not store the master password in memory after it is used, reducing the risk of leaking it.

### Encryption

* Passwords are encrypted using **AES-256-CBC** with a key derived from the master password using PBKDF2, which is a secure key derivation function.
* The **HMAC (Hash-based Message Authentication Code)** is used to verify the integrity of the stored password entries.

### Session Timeout

* A session timeout mechanism is implemented. If the script is inactive for a specified duration, the session will automatically be logged out.
* The timeout duration is configurable via the `$TMOUT` variable.

### Lockout Mechanism

* After a certain number of failed login attempts, the script will lock the vault for a specified duration to prevent brute force attacks.

### Breach Check

* When saving a password, VaultX will ask you whether you want to check the password against the **Have I Been Pwned** (HIBP) database.
* If you choose to check, VaultX will query the HIBP API and notify you if the password has been involved in any known data breaches.
* The breach check is **not automatic**; you will be prompted for confirmation before the check is performed.

## Configuration

VaultX can be configured using a configuration file located at `$HOME/.config/vaultx/config.env`. This file allows you to set various parameters such as:

* `VAULT_DIR`: Directory where the vault will be stored.
* `PASSWORD_LENGTH`: Default length for generated passwords.
* `BACKUP_DIR`: Directory for storing vault backups.
* `MAX_ATTEMPTS`: Maximum number of failed login attempts before locking the vault.
* `LOCKOUT_DURATION`: Duration (in seconds) of the lockout after exceeding the maximum failed attempts.

Example:

```bash
VAULT_DIR="$HOME/.vaultx"
PASSWORD_LENGTH=24
BACKUP_DIR="$HOME/vault_backups"
MAX_ATTEMPTS=5
LOCKOUT_DURATION=600
```

## License

This script is licensed under the **GPL-3.0 License**.

