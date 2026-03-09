# Controle — Time-Locked Codes (Zero-Knowledge Vault)
## PHP Web Application

Controle is a multi-page PHP app that lets users generate and store **time-locked “codes”** in a **zero-knowledge vault**:
- Encryption/decryption happens in the browser (Web Crypto: PBKDF2 + AES-256-GCM)
- The server stores only ciphertext + metadata
- The server enforces the reveal time (server clock, not client clock)
- Users must verify their email before accessing the dashboard

## Requirements
- PHP 8.1+ (with `openssl`, `pdo_mysql`, `mbstring` extensions)
- MySQL 8.0+ or MariaDB 10.6+
- Apache or Nginx
- HTTPS in production (secure cookies + Clipboard API)

## Install (recommended)

### Web installer (first-run)

On first access, the app redirects to `/install/index.php` until installation is complete.

### CLI installer

```bash
php install/install.php
```

See `install/INSTALL.md` for non-interactive usage.

## Manual Setup (alternative)

### 1) Database
Run the schema:

```sql
mysql -u root -p < config/schema.sql
```

If you are upgrading an existing install, apply migrations in `config/migrations/`.

### 2) Configuration
Edit `config/database.php`:
- `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS`
- `APP_HMAC_SECRET` (generate with `php -r "echo bin2hex(random_bytes(32));"`)
- `APP_ENV` (`development` or `production`)
- `APP_BASE_URL` (recommended in production; used for emailed links)
- `MAIL_FROM` (used for verification emails)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_SECURE`, `SMTP_VERIFY_PEER` (recommended)

**Important:** ensure your web server does **not** serve `config/` (it contains secrets). If using Apache, `config/.htaccess` denies access; for Nginx add an equivalent deny rule.

## Project Layout

Pages:
- `index.php` — home/marketing page
- `signup.php` — create account (sends verification email)
- `login.php` — login page
- `forgot.php` / `reset.php` — password reset UI
- `verify.php` — handles verification token
- `dashboard.php` — authenticated, email-verified app UI
- `create_code.php` — create a new time-locked code (and wallet PIN locks)
- `my_codes.php` — list/reveal/delete your locks (browser-side decryption)
- `backup.php` — local export/import + cloud backups
- `vault_settings.php` — vault / passphrase / recovery settings
- `notifications.php` — in-app notifications
- `rooms.php` / `room.php` — saving rooms (discovery + room detail)
- `admin.php` — super admin dashboard (requires admin)
- `account.php` — account security settings
- `logout.php` — destroys session

API:
- `api/auth.php` — register/login/logout + resend verification
- `api/password_reset.php` — password reset endpoints
- `api/csrf.php` — CSRF token utilities
- `api/account.php` — account info + security status
- `api/notifications.php` — in-app notifications
- `api/salt.php` — issues one-time per-lock KDF salt
- `api/generate.php` — store a new encrypted code
- `api/locks.php` — list user codes (metadata)
- `api/confirm.php` — confirm/reject/auto-save flow
- `api/copied.php` — mark as copied
- `api/reveal.php` — time-gated retrieval of ciphertext blobs (browser decrypts)
- `api/delete.php` — delete a code
- `api/backup.php` — local export/import + cloud backups
- `api/vault.php` / `api/vault_verify.php` — vault verification + setup
- `api/totp.php` / `api/webauthn.php` — 2FA / passkeys
- `api/trust.php` — trust passport
- `api/rooms.php` / `api/rooms_stream.php` — saving rooms API + activity stream
- `api/carriers.php` — list mobile money carrier templates
- `api/wallet_create.php` / `api/wallet_locks.php` — wallet PIN locks
- `api/wallet_confirm.php` / `api/wallet_reveal.php` / `api/wallet_delete.php` / `api/wallet_fail.php` — wallet lock lifecycle
- `api/admin.php` — super admin data endpoints

Workers:
- `scripts/rooms_worker.php` — cron worker for saving rooms

## Security Model (high level)
- **Zero plaintext storage**: the server never stores plaintext codes.
- **Browser-only crypto**: keys are derived from the user’s vault passphrase in the browser.
- **Server-side time gate**: reveal date enforced by server clock.
- **CSRF protection** on state-changing API calls.
- **Hardened sessions**: HttpOnly, Strict SameSite, strict mode, regen on login.

## Notes
- Email verification uses SMTP if `SMTP_HOST` is set, otherwise it falls back to PHP `mail()`.
- Cloud backups store ciphertext-only snapshots in the app DB.
- Clipboard support and secure cookies require HTTPS in production.