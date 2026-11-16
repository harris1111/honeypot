-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS llm_runtime_settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    base_url TEXT NOT NULL DEFAULT '',
    api_key_enc BYTEA,
    model TEXT NOT NULL DEFAULT 'deepseek-chat',
    max_daily_usd NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
    allow_unauthenticated_chat BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS llm_runtime_settings;
-- +goose StatementEnd
