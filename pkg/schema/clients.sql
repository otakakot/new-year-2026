-- name: SelectClientByID :one
SELECT
    *
FROM
    clients
WHERE
    id = $1;

-- name: InsertClient :one
INSERT INTO
    clients (der_public_key, redirect_uri)
VALUES
    ($1, $2) RETURNING *;
