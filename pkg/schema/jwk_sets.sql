-- name: SelectJwkSets :many
SELECT
    *
FROM
    jwk_sets;

-- name: SelectJwkSetByID :one
SELECT
    *
FROM
    jwk_sets
WHERE
    id = $1;

-- name: InsertJwkSet :one
INSERT INTO
    jwk_sets (der_private_key)
VALUES
    ($1) RETURNING *;
