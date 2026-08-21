#!/bin/sh
# Fix ownership of Docker volumes (created as root), then drop to uid 10001.
set -eu

if [ "$(id -u)" = "0" ]; then
  mkdir -p \
    /app/nexus-control/downloads \
    /app/nexus-control/reports \
    /app/nexus-control/logs \
    /app/.cache/nexus-control \
    /app/.config/nexus-control
  chown -R app:app /app/nexus-control /app/.cache /app/.config
  exec gosu app "$@"
fi

exec "$@"
