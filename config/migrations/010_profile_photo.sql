-- Add user profile photo (stored as a server path; file itself is stored in uploads/)

ALTER TABLE users
    ADD COLUMN profile_photo VARCHAR(255) NULL AFTER email;
