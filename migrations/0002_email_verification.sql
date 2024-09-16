-- Migration number: 0002 	 2024-09-12T12:45:32.102Z


create table email_verification_codes
(
    id    INTEGER not null primary key,
    email TEXT,
    user_id TEXT unique,
    code TEXT,
    expires_at TEXT
);

alter table users add column email_verified boolean default false;