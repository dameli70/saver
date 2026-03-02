# LOCKSMITH Android (USSD Companion)

This is the Android companion app for LOCKSMITH (Option A): it can execute USSD locally (Android 8+ / API 26+) and keep wallet PINs out of the dialer UI.

## Requirements
- Android Studio (Giraffe+ recommended)
- Android device running Android 8.0+ (API 26+)
- Your LOCKSMITH server must be reachable over HTTPS (recommended).

## Server requirements
Apply migrations (includes carriers + wallet_locks):
- `config/migrations/009_wallet_locks.sql`

## App configuration
The app lets you set a **Base URL** (example):
- `https://example.com/locksmith`

Do not include a trailing `/api`.

## Permissions
The app requests:
- `CALL_PHONE` (required for `TelephonyManager.sendUssdRequest`)

## UI previews / screenshots
This project includes Jetpack Compose previews that you can export as screenshots from Android Studio:
- `MainActivity.kt`: Login + TOTP previews
- `WalletHomeScreen.kt`: Wallet Locks tab + Setup tab previews

In Android Studio:
1. Open the file.
2. Open the "Preview" tool window.
3. Use the preview actions to export/save the rendered preview as an image.

## Notes
- USSD automation support varies by carrier/OEM.
- This project does not include the Gradle wrapper JAR (binary). If your environment requires it, generate it via Android Studio or `gradle wrapper`.
