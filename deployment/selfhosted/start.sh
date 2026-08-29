#!/bin/sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "No .env file found."
    echo "Creating one from .env.example..."

    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"

    echo
    echo "Created $ENV_FILE"
    echo "Please edit it and configure the required values."
    echo "Then run ./start.sh again."
    exit 1
fi

set -a
. "$ENV_FILE"
set +a

if [ -z "${TOTP_SECRET_ENCRYPTION_KEY:-}" ]; then
    echo "Generating TOTP encryption key..."

    TOTP_SECRET_ENCRYPTION_KEY="$(
        docker run --rm alpine:3.22 sh -c '
            apk add --no-cache openssl >/dev/null 2>&1
            openssl rand -hex 32
        '
    )"

    sed -i.bak \
        "s|^TOTP_SECRET_ENCRYPTION_KEY=.*|TOTP_SECRET_ENCRYPTION_KEY=$TOTP_SECRET_ENCRYPTION_KEY|" \
        "$ENV_FILE"

    rm -f "$ENV_FILE.bak"

    echo "TOTP encryption key generated and saved."
fi

case "$TOTP_SECRET_ENCRYPTION_KEY" in
    '' )
        ;;
    *[!0123456789abcdefABCDEF]* )
        echo "ERROR: TOTP_SECRET_ENCRYPTION_KEY must contain only hexadecimal characters."
        exit 1
        ;;
esac

if [ "${#TOTP_SECRET_ENCRYPTION_KEY}" -ne 64 ]; then
    echo "ERROR: TOTP_SECRET_ENCRYPTION_KEY must be exactly 64 hexadecimal characters."
    exit 1
fi

echo "Starting SeguraPass..."
docker compose up --build -d

echo
echo "SeguraPass started."