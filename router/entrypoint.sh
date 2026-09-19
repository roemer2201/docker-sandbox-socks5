#!/usr/bin/env bash
#
# entrypoint.sh
#
# Description:
#   Boots the sandbox router container: resolves the ssh server, renders the
#   redsocks and unbound configs, installs the fail-closed firewall, then starts
#   and supervises unbound, the autossh SOCKS5 tunnel and redsocks. If any
#   supervised service dies, the entrypoint exits so the container is restarted.
#
# Program flow:
#   1. Validate required environment and the mounted ssh material.
#   2. Resolve SSH_HOST to an IPv4 address (before the firewall closes DNS).
#   3. Render redsocks.conf and unbound.conf from their templates.
#   4. Stage the ssh private key with strict permissions.
#   5. Apply the firewall (from here the netns is fail-closed).
#   6. Start unbound, then autossh (wait for the SOCKS port), then redsocks.
#   7. Supervise; exit if any service terminates.
#
# Usage:
#   Invoked as the container ENTRYPOINT. Configuration is passed via the
#   SANDBOX_* environment variables (see .env.example and README.md).
#
# Version: 1.0.0  (2026-09-19)

set -euo pipefail

SCRIPT_NAME="$(basename -- "${0}")"

# Message helpers. Errors to STDERR, status to STDOUT.
# TODO(logging): syslog/journal integration is intentionally deferred.
msg() { printf '%s: %s\n' "${SCRIPT_NAME}" "$*"; }
err() { printf '%s: error: %s\n' "${SCRIPT_NAME}" "$*" >&2; }
die() { err "$*"; exit 1; }

# --- Parameters (env with built-in defaults) -----------------------------
SSH_HOST="${SANDBOX_SSH_HOST:-}"
SSH_PORT="${SANDBOX_SSH_PORT:-22}"
SSH_USER="${SANDBOX_SSH_USER:-}"
SSH_KEY_SRC="${SANDBOX_SSH_KEY_PATH:-/etc/sandbox/ssh/id_key}"
SSH_KNOWN_HOSTS="${SANDBOX_SSH_KNOWN_HOSTS_PATH:-/etc/sandbox/ssh/known_hosts}"
SOCKS_PORT="${SANDBOX_SOCKS_PORT:-1080}"
REDSOCKS_PORT="${SANDBOX_REDSOCKS_PORT:-12345}"
DNS_UPSTREAM="${SANDBOX_DNS_UPSTREAM:-9.9.9.9}"
TUNNEL_WAIT="${SANDBOX_TUNNEL_WAIT:-30}"

KEY_DST="/home/tunnel/.ssh/id_key"

# --- 1. Validate ---------------------------------------------------------
[ -n "${SSH_HOST}" ] || die "SANDBOX_SSH_HOST is required"
[ -n "${SSH_USER}" ] || die "SANDBOX_SSH_USER is required"
[ -r "${SSH_KEY_SRC}" ] || die "ssh key not readable: ${SSH_KEY_SRC} (mount it read-only)"
if [ ! -s "${SSH_KNOWN_HOSTS}" ]; then
    die "known_hosts missing or empty: ${SSH_KNOWN_HOSTS} (populate it; strict host key checking is enforced)"
fi

# --- 2. Resolve SSH_HOST to an IPv4 address ------------------------------
# Done while the Docker-provided resolver is still reachable, i.e. before the
# firewall closes off DNS. If SSH_HOST is already an IPv4 literal, keep it.
resolve_ipv4() {
    local host="${1}"
    case "${host}" in
        *[!0-9.]*)
            # Contains non-digit/dot: treat as a name and resolve it.
            getent ahostsv4 "${host}" 2>/dev/null | awk 'NR==1 {print $1}'
            ;;
        *)
            printf '%s' "${host}"
            ;;
    esac
}

SSH_HOST_IP="$(resolve_ipv4 "${SSH_HOST}")"
[ -n "${SSH_HOST_IP}" ] || die "could not resolve SANDBOX_SSH_HOST to an IPv4 address: ${SSH_HOST}"
msg "ssh server ${SSH_HOST} resolved to ${SSH_HOST_IP}"

# --- 3. Render templates -------------------------------------------------
# envsubst only substitutes the variables we name, so literal $ in the configs
# (there are none, but as a safeguard) stays intact.
export SANDBOX_REDSOCKS_PORT="${REDSOCKS_PORT}"
export SANDBOX_SOCKS_PORT="${SOCKS_PORT}"
export SANDBOX_DNS_UPSTREAM="${DNS_UPSTREAM}"

envsubst '${SANDBOX_REDSOCKS_PORT} ${SANDBOX_SOCKS_PORT}' \
    < /etc/sandbox/redsocks.conf.tmpl > /etc/sandbox/redsocks.conf
envsubst '${SANDBOX_DNS_UPSTREAM}' \
    < /etc/sandbox/unbound.conf.tmpl > /etc/sandbox/unbound.conf

# --- 4. Stage the ssh private key ---------------------------------------
# The mount is read-only and may be group/world readable on the host; ssh
# refuses loose permissions, so copy it to a private, tunnel-owned location.
install -m 0600 -o tunnel -g tunnel "${SSH_KEY_SRC}" "${KEY_DST}"

# --- 5. Apply the firewall (fail-closed from here) -----------------------
export SANDBOX_SSH_HOST_IP="${SSH_HOST_IP}"
export SANDBOX_SSH_PORT="${SSH_PORT}"
/usr/local/bin/firewall.sh

# --- 6. Start services ---------------------------------------------------
PIDS=()

# Forward termination to the supervised children.
terminate() {
    msg "shutting down"
    kill "${PIDS[@]}" 2>/dev/null || true
    wait 2>/dev/null || true
    exit 0
}
trap terminate TERM INT

# unbound: caching resolver, upstream forced over TCP (rendered config).
msg "starting unbound"
unbound -d -c /etc/sandbox/unbound.conf &
PIDS+=("$!")

# autossh: keeps the ssh -D SOCKS5 tunnel alive. Runs as the tunnel account so
# its packets carry the tunnel UID that the firewall allows out.
msg "starting ssh tunnel via autossh"
runuser -u tunnel -- env \
    AUTOSSH_GATETIME=0 \
    HOME=/home/tunnel \
    autossh -M 0 -N \
        -D "127.0.0.1:${SOCKS_PORT}" \
        -i "${KEY_DST}" \
        -p "${SSH_PORT}" \
        -o "HostKeyAlias=${SSH_HOST}" \
        -o "UserKnownHostsFile=${SSH_KNOWN_HOSTS}" \
        -o "StrictHostKeyChecking=yes" \
        -o "ExitOnForwardFailure=yes" \
        -o "ServerAliveInterval=15" \
        -o "ServerAliveCountMax=3" \
        -o "IdentitiesOnly=yes" \
        "${SSH_USER}@${SSH_HOST_IP}" &
PIDS+=("$!")

# Wait for the local SOCKS listener before starting redsocks.
msg "waiting for the SOCKS listener on 127.0.0.1:${SOCKS_PORT} (timeout ${TUNNEL_WAIT}s)"
waited=0
until nc -z 127.0.0.1 "${SOCKS_PORT}" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "${waited}" -ge "${TUNNEL_WAIT}" ]; then
        die "ssh tunnel did not open the SOCKS port within ${TUNNEL_WAIT}s"
    fi
    sleep 1
done
msg "SOCKS listener is up"

# redsocks: transparent TCP redirector. Drops privileges to the tunnel account
# per its config, so its connection to the SOCKS listener is not re-redirected.
msg "starting redsocks"
redsocks -c /etc/sandbox/redsocks.conf &
PIDS+=("$!")

# --- 7. Supervise --------------------------------------------------------
msg "router is up; supervising services"
wait -n
err "a supervised service exited; stopping the router"
kill "${PIDS[@]}" 2>/dev/null || true
exit 1
