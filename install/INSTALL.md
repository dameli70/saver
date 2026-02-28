# LOCKSMITH Installer

This project ships with:
- a **web installer** (`/install/index.php`) that runs automatically on first app access until installation is complete
- a **CLI installer** (`php install/install.php`) for server-side setup

Both installers:
- generate required secrets
- write `config/database.php`
- optionally initialize the database schema and apply migrations
- write `config/installed.flag` so the app can bypass the installer on future requests

## Run (interactive)

From the project root:

```bash
php install/install.php
```

## Run (non-interactive)

```bash
php install/install.php --non-interactive --init-db=1 --apply-migrations=1 \
  --db-host=localhost --db-name=locksmith --db-user=root --db-pass='' \
  --app-env=development --app-name=LOCKSMITH --mail-from=no-reply@localhost \
  --email-verify-ttl-hours=24
```

## Notes

- The installer makes a timestamped backup of `config/database.php` before editing.
- In production you should use HTTPS (secure cookies + clipboard support).
- Email verification uses PHP `mail()`. In development, verification links may be displayed by the app depending on environment.
