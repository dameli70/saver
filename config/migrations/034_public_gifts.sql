-- Public gift links
--
-- Token hash is stored server-side (hex sha256) and is the lookup key.
-- Ciphertext is opaque and client-decryptable only.

CREATE TABLE IF NOT EXISTS public_gifts (
  token_hash     CHAR(64) PRIMARY KEY,

  cipher_blob    TEXT NOT NULL,
  iv             VARCHAR(64) NOT NULL,
  auth_tag       VARCHAR(64) NOT NULL,
  kdf_salt       VARCHAR(64) NOT NULL,
  kdf_iterations INT UNSIGNED NOT NULL DEFAULT 310000,

  reveal_date    DATETIME NOT NULL,
  created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,

  expires_at     DATETIME NULL,
  revoked_at     DATETIME NULL,

  INDEX idx_reveal (reveal_date),
  INDEX idx_expires (expires_at)
) ENGINE=InnoDB;
