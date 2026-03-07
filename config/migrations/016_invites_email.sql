-- Allow private-room invites to be issued to emails that do not yet have an account.

ALTER TABLE saving_room_invites
    ADD COLUMN invited_email VARCHAR(255) NULL AFTER invited_user_id,
    ADD INDEX idx_invited_email (invited_email);

-- Backfill invited_email for existing private_user invites.
UPDATE saving_room_invites i
JOIN users u ON u.id = i.invited_user_id
SET i.invited_email = u.email
WHERE i.invite_mode = 'private_user'
  AND i.invited_user_id IS NOT NULL
  AND (i.invited_email IS NULL OR i.invited_email = '');
