# LOCKSMITH — Time-Locked Password Vault
## PHP Web Application

---

## Requirements
- PHP 8.1+ (with `openssl`, `pdo_mysql`, `mbstring` extensions)
- MySQL 8.0+ or MariaDB 10.6+
- Apache with `mod_rewrite` and `mod_headers` enabled
- HTTPS in production (required for Clipboard API + secure cookies)

---

## Quick Setup

### 1. Database
```sql
-- Run the schema file:
mysql -u root -p < config/schema.sql
```

### 2. Configuration
Edit `config/database.php`:
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'locksmith');
define('DB_USER', 'your_db_user');
define('DB_PASS', 'your_db_password');
define('APP_SECRET_KEY', 'generate_a_64+_char_random_string_here');
define('APP_ENV', 'production');
```

**Generate a secret key:**
```bash
php -r "echo bin2hex(random_bytes(32));"
```

### 3. Deploy
```
/var/www/html/locksmith/
├── index.php           ← Main app (single-page UI)
├── .htaccess           ← Security + URL rules
├── config/
│   ├── database.php    ← DB config + connection
│   └── schema.sql      ← DB setup (run once)
├── includes/
│   └── helpers.php     ← Crypto, auth, utilities
└── api/
    ├── auth.php        ← Register / login / logout
    ├── generate.php    ← Generate + store encrypted password
    ├── copied.php      ← Mark password as copied (fires on clipboard)
    ├── locks.php       ← List active locks
    ├── reveal.php      ← Decrypt + return password (if date passed)
    └── delete.php      ← Remove a lock
```

### 4. Apache VirtualHost (example)
```apache
<VirtualHost *:443>
    ServerName locksmith.yourdomain.com
    DocumentRoot /var/www/html/locksmith

    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/your_cert.pem
    SSLCertificateKeyFile /etc/ssl/private/your_key.pem

    <Directory /var/www/html/locksmith>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

---

## Security Model

| Layer | What's Protected |
|---|---|
| **AES-256-GCM** | Password encrypted on server using derived key |
| **PBKDF2 (100k rounds)** | Key derived from `APP_SECRET_KEY` + `user_id` |
| **CSRF tokens** | All state-changing API calls require CSRF header |
| **Server-side time gate** | Reveal date enforced by server — device clock irrelevant |
| **Session security** | HttpOnly, strict mode, regenerated on login |
| **Zero plaintext storage** | Plaintext password returned ONCE at generation, never stored |
| **Argon2id hashing** | User login passwords hashed with Argon2id |

---

## How the Copy Flow Works

1. User clicks **Generate & Lock** → server generates password, encrypts it, stores ciphertext
2. Server returns plaintext password **once** in the HTTP response
3. User sees the password and clicks **Copy to Clipboard**
4. `navigator.clipboard.writeText()` copies to clipboard
5. **Immediately**, a `POST /api/copied.php` call fires → server records `copied_at` timestamp
6. After 3 seconds, the displayed password is replaced with `••••••••`
7. The password cannot be retrieved again until the reveal date is reached

---

## Notes
- **No plaintext is ever stored** — only AES-256-GCM ciphertext
- **Locks persist** even if the user changes their password (key is derived from APP_SECRET_KEY + user_id, not user password)
- **Clock manipulation** is prevented — the server checks its own clock on reveal
- **Offline use** will block reveals until server connectivity is restored (by design)
