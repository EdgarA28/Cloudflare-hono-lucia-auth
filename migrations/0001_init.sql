-- Migration number: 0001 	 2024-09-11T10:12:58.403Z


create table users
(
    id    TEXT not null primary key,
    email TEXT not null unique,
    hashed_password TEXT
);

create table sessions
(
    id         TEXT    not null primary key,
    expires_at INTEGER not null,
    user_id    TEXT    not null
);