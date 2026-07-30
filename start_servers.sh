#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$ROOT_DIR/backend"
uvicorn server:app --reload --port 8000 &
BACKEND_PID=$!

cd "$ROOT_DIR/frontend"

trap "kill $BACKEND_PID 2>/dev/null || true" INT

npm start

kill $BACKEND_PID 2>/dev/null || true

