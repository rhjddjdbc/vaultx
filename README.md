# pash

**pash** is a simple, secure, and offline password manager written in Bash. It uses OpenSSL to encrypt credentials and stores each entry in your local vault folder. Entries are protected using a master password, which is hashed and validated on use.

---

## Features

- Save encrypted password entries with optional usernames and notes
- Secure encryption using AES-256-CBC with PBKDF2 and 200,000 iterations
- Stores metadata (creation timestamp, label, optional note)
- Securely verifies the master password using a SHA-256 hash
- Backup vaults as ZIP archives
- Audit all stored entries with metadata
- Search and select entries using [fzf](https://github.com/junegunn/fzf)

---

## Requirements

- `bash` (version 4 or later recommended)
- `openssl`
- `sha256sum`
- `zip`
- `fzf`

---

## Setup

Clone or copy the script into a file (e.g., `pash.sh`) and make it executable:

```bash
chmod +x vault.sh
./vault.sh
```

The first time you save or decrypt an entry, you'll be prompted to set a master password. This will be hashed and stored in `.vault_master.hash`.

You can set a custom vault location using the environment variable:

```bash
export VAULT_DIR="$HOME/.myvault"
```

---

## Usage

You can perform the following actions using an interactive menu powered by `fzf`:

- **Save new entry**: Add a password with optional username and note.
- **Decrypt entry**: View an existing password entry.
- **Delete entry**: Permanently remove a saved entry.
- **Backup vault**: Create a ZIP archive of your vault.
- **Audit mode**: View a summary of all saved entries with timestamps.
- **Cancel**: Exit the script safely.

---

## Security Notes

- Master password is never stored in plaintext—only a hash is saved for validation.
- Password data is encrypted using OpenSSL with salt, strong key derivation (`pbkdf2`), and AES-256.
- Sensitive data like passwords and the master password are unset from memory after use.

---

## might come later

- Clipboard integration and automatic password generation are not included.
- This tool is designed for local use only and does not sync with cloud services.

---

## License

This project is licensed under the [GNU General Public License v3.0.].
