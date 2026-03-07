# LOCKSMITH — Time-Locked Codes (Zero-Knowledge Vault)
## PHP Web Application

LOCKSMITH is a multi-page PHP app that includes:

1) **Vault (time-locked codes)** — encrypt/decrypt exclusively in the browser (Web Crypto: PBKDF2 + AES-256-GCM). The server stores ciphertext + metadata and enforces reveal dates.
2) **Saving Rooms (collaborative savings coordination)** — contribution tracking, trust/strike rules, disputes, voting, and destination-account unlock workflows (cron/worker driven).
3) **Wallet Locks (mobile money PIN-change helper)** — time-locked ciphertext for the Android companion to execute USSD PIN changes.

### Important: scope of “zero-knowledge”
- **Zero-knowledge applies to vault codes and wallet locks ciphertext**: the server never receives the vault passphrase and cannot decrypt those items.
- **Not everything is zero-knowledge**: the server can decrypt some server-managed secrets to function (e.g. `totp_secret_enc` for TOTP verification, and Saving Rooms destination account unlock codes when a room unlocks).

Users must verify their email before accessing the dashboard.

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
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_SECURE`, `SMTP_VERIFY_PEER` (recommended)

## Project Layout

Pages:
- `index.php` — home/marketing page
- `signup.php` — create account (sends verification email)
- `login.php` — login page (redirects based on verification)
- `account.php` — account + email verification status, resend link
- `verify.php` — handles verification token
- `dashboard.php` — authenticated, email-verified app UI
- `backup.php` — local export/import + cloud backups
- `rooms.php` / `room.php` — Saving Rooms UI
- `notifications.php` — in-app inbox
- `admin.php` — super admin dashboard (requires admin)
- `logout.php` — destroys session

API:
- Vault
  - `api/auth.php` — register/login/logout + resend verification
  - `api/salt.php` — issues one-time per-lock KDF salt
  - `api/generate.php` — store a new encrypted code
  - `api/locks.php` — list user codes (metadata)
  - `api/confirm.php` — confirm/reject/auto-save flow
  - `api/copied.php` — mark as copied
  - `api/reveal.php` — time-gated retrieval of ciphertext blobs (browser decrypts)
  - `api/delete.php` — delete a code
  - `api/vault.php` — vault setup + rotation
  - `api/totp.php` / `api/webauthn.php` — 2FA + step-up auth

- Backups
  - `api/backup.php` — local export/import + cloud backups

- Saving Rooms
  - `api/rooms.php` — room lifecycle + participation + contributions
  - `api/rooms_stream.php` — SSE activity stream
  - `api/trust.php` — trust passport

- Wallet Locks
  - `api/wallet_create.php` / `api/wallet_locks.php` / `api/wallet_reveal.php`
  - `api/wallet_confirm.php` / `api/wallet_fail.php`
  - `api/carriers.php` — list carriers

- Admin
  - `api/admin.php` — admin data endpoints (users, codes, rooms, carriers, destination accounts)

## Security Model (high level)
- **Vault codes are zero-knowledge**: the server never stores plaintext vault codes and never receives the vault passphrase.
- **Browser-only crypto**: vault encryption keys are derived from the user’s vault passphrase in the browser.
- **Server-side time gate**: reveal date enforced by server clock.
- **Some server-managed secrets exist** (not zero-knowledge): e.g. TOTP secrets for verification and Saving Rooms destination unlock codes.
- **CSRF protection** on state-changing API calls.
- **Hardened sessions**: HttpOnly, Strict SameSite, strict mode, regen on login.

## Notes
- Email verification uses SMTP if `SMTP_HOST` is set, otherwise it falls back to PHP `mail()`.
- Cloud backups store ciphertext-only snapshots in the app DB.
- Clipboard support and secure cookies require HTTPS in production.