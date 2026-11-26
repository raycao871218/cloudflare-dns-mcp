#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
test -f .env || { echo 'Create .env from .env.example before deploying.' >&2; exit 1; }
git pull --ff-only
docker compose build
docker compose up -d --no-build --wait --wait-timeout 60
docker compose ps
