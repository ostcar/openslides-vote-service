CREATE SCHEMA IF NOT EXISTS vote;

CREATE TABLE IF NOT EXISTS vote.poll(
    id INTEGER UNIQUE NOT NULL,
    stopped BOOLEAN NOT NULL,

    -- user_ids is managed by the application. It stores all user ids in a way
    -- that makes it impossible to see the sequence in which the users have
    -- voted.
    user_ids BYTEA
);

CREATE TABLE IF NOT EXISTS vote.objects (
    id SERIAL PRIMARY KEY,

    -- There are many raws per poll.
    poll_id INTEGER NOT NULL REFERENCES vote.poll(id) ON DELETE CASCADE,

    -- The vote object.
    vote BYTEA
);
