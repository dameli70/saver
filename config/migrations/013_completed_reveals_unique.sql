-- Ensure completed reveal records are not duplicated

ALTER TABLE user_completed_reveals
    ADD UNIQUE KEY uniq_user_room (user_id, room_id);
