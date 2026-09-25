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
# Version: 1.1.0  (2026-09-26)

set -euo pipefail

SOCKS_PORT="${SANDBOX_SOCKS_PORT:-1080}"
REDSOCKS_PORT="${SANDBOX_REDSOCKS_PORT:-12345}"
PROBE_NAME="${SANDBOX_HEALTH_PROBE:-example.com}"

# True if something listens on 127.0.0.1:<port>. Checked via the socket table
# rather than "nc -z": a connect to redsocks would be forwarded into the tunnel
# as a bogus request to 127.0.0.1:<port> on the ssh server (log noise), and a
# connect to the SOCKS port opens a pointless ssh channel.
listening() {
    ss -Hltn "sport = :${1}" 2>/dev/null | grep -q '127.0.0.1:'
}

# Local SOCKS listener must be up.
listening "${SOCKS_PORT}" \
    || { printf 'unhealthy: SOCKS port %s closed\n' "${SOCKS_PORT}" >&2; exit 1; }

# redsocks must be listening.
listening "${REDSOCKS_PORT}" \
    || { printf 'unhealthy: redsocks port %s closed\n' "${REDSOCKS_PORT}" >&2; exit 1; }

# End-to-end DNS through unbound (and thus through the tunnel).
dig +tries=1 +time=3 @127.0.0.1 "${PROBE_NAME}" >/dev/null 2>&1 \
    || { printf 'unhealthy: unbound did not resolve %s\n' "${PROBE_NAME}" >&2; exit 1; }

printf 'healthy\n'
exit 0
