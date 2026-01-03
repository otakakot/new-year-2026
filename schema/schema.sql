CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    der_public_key BYTEA NOT NULL,
    redirect_uri TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jwk_sets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    der_private_key BYTEA NOT NULL
);
