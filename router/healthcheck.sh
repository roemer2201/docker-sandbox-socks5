#!/usr/bin/env bash
#
# healthcheck.sh
#
# Description:
#   Docker healthcheck for the sandbox router. Reports healthy only when the
#   local SOCKS listener and redsocks port are open and unbound answers a query
#   end to end (which exercises the tunnel, since unbound forwards over TCP).
#
# Usage:
#   healthcheck.sh            (invoked by Docker; no arguments)
#
# Version: 1.0.0  (2026-09-19)

set -euo pipefail

SOCKS_PORT="${SANDBOX_SOCKS_PORT:-1080}"
REDSOCKS_PORT="${SANDBOX_REDSOCKS_PORT:-12345}"
PROBE_NAME="${SANDBOX_HEALTH_PROBE:-example.com}"

# Local SOCKS listener must be up.
nc -z 127.0.0.1 "${SOCKS_PORT}" 2>/dev/null \
    || { printf 'unhealthy: SOCKS port %s closed\n' "${SOCKS_PORT}" >&2; exit 1; }

# redsocks must be listening.
nc -z 127.0.0.1 "${REDSOCKS_PORT}" 2>/dev/null \
    || { printf 'unhealthy: redsocks port %s closed\n' "${REDSOCKS_PORT}" >&2; exit 1; }

# End-to-end DNS through unbound (and thus through the tunnel).
dig +tries=1 +time=3 @127.0.0.1 "${PROBE_NAME}" >/dev/null 2>&1 \
    || { printf 'unhealthy: unbound did not resolve %s\n' "${PROBE_NAME}" >&2; exit 1; }

printf 'healthy\n'
exit 0
