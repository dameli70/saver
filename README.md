# LOCKSMITH — Time-Locked Codes (Zero-Knowledge Vault)
## PHP Web Application

LOCKSMITH is a multi-page PHP app that lets users generate and store **time-locked “codes”** in a **zero-knowledge vault**:
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
- `MAIL_FROM` (used for verification emails)

## Project Layout

Pages:
- `index.php` — home/marketing page
- `signup.php` — create account (sends verification email)
- `login.php` — login page (redirects based on verification)
- `account.php` — account + email verification status, resend link
- `verify.php` — handles verification token
- `dashboard.php` — authenticated, email-verified app UI
- `admin.php` — super admin dashboard (requires admin)
- `logout.php` — destroys session

API:
- `api/auth.php` — register/login/logout + resend verification
- `api/salt.php` — issues one-time per-lock KDF salt
- `api/generate.php` — store a new encrypted code
- `api/locks.php` — list user codes (metadata)
- `api/confirm.php` — confirm/reject/auto-save flow
- `api/copied.php` — mark as copied
- `api/reveal.php` — time-gated retrieval of ciphertext blobs (browser decrypts)
- `api/delete.php` — delete a code
- `api/admin.php` — super admin data endpoints (users + codes)

## Security Model (high level)
- **Zero plaintext storage**: the server never stores plaintext codes.
- **Browser-only crypto**: keys are derived from the user’s vault passphrase in the browser.
- **Server-side time gate**: reveal date enforced by server clock.
- **CSRF protection** on state-changing API calls.
- **Hardened sessions**: HttpOnly, Strict SameSite, strict mode, regen on login.

## Notes
- Email verification uses PHP `mail()`; in production you should have a real MTA configured.
- Clipboard support and secure cookies require HTTPS in production.
