# LOCKSMITH — Time-Locked, Zero-Knowledge Code Vault

LOCKSMITH is a PHP + MySQL web app that lets users generate a secret code, encrypt it **client-side** (Web Crypto), and store only ciphertext on the server until a chosen reveal date.

## Requirements
- PHP 8.1+ (with `openssl`, `pdo_mysql`, `mbstring`)
- MySQL 8.0+ or MariaDB 10.6+
- HTTPS in production (required for secure cookies + clipboard API)

## Quick setup

### 1) Database
```sql
mysql -u root -p < config/schema.sql
```

If you are upgrading an existing install, apply the migration:
```sql
mysql -u root -p locksmith < config/migrations/001_email_verification.sql
```

### 2) Configuration
Edit `config/database.php`:
- `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`
- `APP_HMAC_SECRET` (HMAC for CSRF + audit log integrity, **not used for encryption**)
- `MAIL_FROM` (sender address used for verification emails)

Generate a secret:
```bash
php -r "echo bin2hex(random_bytes(32));"
```

## App pages
- `index.php` — home/marketing page
- `signup.php` — create account (email verification required)
- `login.php` — login
- `account.php` — account + resend verification email
- `verify.php` — email verification link target
- `dashboard.php` — authenticated, verified dashboard (generate/list/reveal)
- `logout.php` — logout

## API endpoints
Located in `api/`:
- `auth.php` — register/login/logout + resend verification
- `salt.php` — issues one-time PBKDF2 salt for a new code
- `generate.php` — stores ciphertext + metadata (never plaintext)
- `locks.php` — lists code metadata and status
- `reveal.php` — enforces time gate + vault passphrase verification, then returns ciphertext for client-side decryption
- `confirm.php`, `copied.php`, `delete.php`

## Security model (high level)
- **Zero-knowledge storage**: server stores only ciphertext (AES-256-GCM), IVs, tags, salts, and metadata.
- **Key derivation in browser**: PBKDF2 with per-code salt (`PBKDF2_ITERATIONS` in config).
- **Server-enforced time gate**: reveals are blocked until `reveal_date` passes on the server.
- **CSRF**: state-changing API calls require the CSRF header.
- **Email verification**: required before accessing the dashboard or API code operations.

## Notes
- The vault passphrase is used in the browser for encryption/decryption, but is also verified server-side (Argon2id) during reveal to ensure the user is authorized.
- If a user loses their vault passphrase, stored ciphertext cannot be recovered.
