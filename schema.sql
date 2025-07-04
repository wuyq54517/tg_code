-- Drop tables if they exist to ensure a clean slate with new structure
--DROP TABLE IF EXISTS proxies;
--DROP TABLE IF EXISTS sessions;
--DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, -- Nullable for guest sessions
    uuid TEXT UNIQUE NOT NULL,
    name TEXT, -- For custom naming
    session_string TEXT NOT NULL,
    chat_id TEXT,
    phone TEXT,
    country TEXT,
    created_at TIMESTAMP NOT NULL, -- Will be stored in Shanghai time
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    proxy_string TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

