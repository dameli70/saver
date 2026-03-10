-- Lock share reveal policy
-- Adds a per-share toggle to allow revealing the code to anyone with the link after reveal_date.

ALTER TABLE lock_shares
    ADD COLUMN allow_reveal_after_date TINYINT(1) NOT NULL DEFAULT 1;
