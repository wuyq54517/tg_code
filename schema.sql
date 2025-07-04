-- Drop tables if they exist to ensure a clean slate.
-- Use with caution in production.
-- DROP TABLE IF EXISTS proxies;
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS users;

-- Users table to store login credentials
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Sessions table to store Telegram session data
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    name TEXT, -- For custom naming by the user
    session_string TEXT NOT NULL,
    chat_id TEXT,
    phone TEXT,
    country TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Proxies table (optional, if you need proxy management)
CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    proxy_string TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
