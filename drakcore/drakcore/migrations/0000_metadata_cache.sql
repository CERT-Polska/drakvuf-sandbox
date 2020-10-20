CREATE TABLE metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Length of karton UUID
    uid VARCHAR(36) NOT NULL UNIQUE, 
    -- Serialized metadata JSON
    value TEXT NOT NULL
);
