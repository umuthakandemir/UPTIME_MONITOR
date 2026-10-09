#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

docker compose up -d --build

echo
printf 'Uptime Monitor Service: http://localhost:%s\n' "${APP_PORT:-8080}"
printf 'Durum: docker compose ps\n'
printf 'Log:    docker compose logs -f app\n'
