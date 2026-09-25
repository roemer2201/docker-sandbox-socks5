#!/usr/bin/env bash
#
# firewall.sh
#
# Description:
#   Installs the enforcing iptables/ip6tables ruleset for the sandbox router.
#   The rules live in the router's network namespace, which is shared with the
#   application container, so they govern the application's traffic too.
#
#   Net effect:
#     - All TCP from any process except the tunnel account is transparently
#       redirected into redsocks (nat table).
#     - The only non-loopback egress permitted is the ssh tunnel itself, from
#       the tunnel UID to SSH_HOST:SSH_PORT (filter table, default DROP).
#     - UDP and ICMP have no path out; DNS works because the application talks
#       to the local unbound over loopback and unbound forwards over TCP.
#     - IPv6 is fully closed.
#
# Program flow:
#   1. Read parameters from the environment and validate them.
#   1b. Select the iptables backend (legacy/nft) matching Docker's rules.
#   2. Flush any previous sandbox chains (idempotent re-apply).
#   3. nat table: build SANDBOX_REDIR and hook it into OUTPUT.
#   4. filter table: default-DROP policies plus the tunnel allowance.
#   5. Close IPv6 completely.
#
# Usage:
#   firewall.sh [-h|--help]
#
#   All parameters are passed via environment variables:
#     SANDBOX_TUNNEL_UID     UID that runs ssh and redsocks (default 10002)
#     SANDBOX_REDSOCKS_PORT  local redsocks port (default 12345)
#     SANDBOX_SOCKS_PORT     local ssh -D SOCKS5 port (default 1080)
#     SANDBOX_SSH_HOST_IP    resolved IP of the ssh server (required)
#     SANDBOX_SSH_PORT       ssh server port (default 22)
#     SANDBOX_SUBNET         sandbox subnet in CIDR (default 172.28.77.0/24)
#     SANDBOX_IPTABLES_BACKEND  auto|nft|legacy (default auto: match the
#                            backend Docker already uses in this netns)
#
# Version: 1.1.0  (2026-09-26)

set -euo pipefail

SCRIPT_NAME="$(basename -- "${0}")"

# Print usage to STDOUT.
usage() {
    cat <<'USAGE'
Usage: firewall.sh [-h|--help]

Installs the sandbox router firewall. Parameters come from the environment:
  SANDBOX_TUNNEL_UID     UID that runs ssh and redsocks   (default 10002)
  SANDBOX_REDSOCKS_PORT  local redsocks port              (default 12345)
  SANDBOX_SOCKS_PORT     local ssh -D SOCKS5 port         (default 1080)
  SANDBOX_SSH_HOST_IP    resolved IP of the ssh server    (required)
  SANDBOX_SSH_PORT       ssh server port                  (default 22)
  SANDBOX_SUBNET         sandbox subnet in CIDR           (default 172.28.77.0/24)
  SANDBOX_IPTABLES_BACKEND  auto|nft|legacy               (default auto)
USAGE
}

# Minimal message helper. Errors go to STDERR; status to STDOUT.
# TODO(logging): structured syslog/journal logging is intentionally deferred
# until the logging format and facility are defined.
err() { printf '%s: error: %s\n' "${SCRIPT_NAME}" "$*" >&2; }
die() { err "$*"; exit 1; }

# --- Parse the single supported flag -------------------------------------
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    "")        ;;
    *)         err "unknown argument: ${1}"; usage >&2; exit 2 ;;
esac

# --- Parameters from the environment -------------------------------------
TUNNEL_UID="${SANDBOX_TUNNEL_UID:-10002}"
REDSOCKS_PORT="${SANDBOX_REDSOCKS_PORT:-12345}"
SOCKS_PORT="${SANDBOX_SOCKS_PORT:-1080}"
SSH_HOST_IP="${SANDBOX_SSH_HOST_IP:-}"
SSH_PORT="${SANDBOX_SSH_PORT:-22}"
SUBNET="${SANDBOX_SUBNET:-172.28.77.0/24}"
BACKEND="${SANDBOX_IPTABLES_BACKEND:-auto}"

[ -n "${SSH_HOST_IP}" ] || die "SANDBOX_SSH_HOST_IP is required (resolved ssh server IP)"

# Sanity check: the resolved ssh host must be an IPv4 address, not a name.
case "${SSH_HOST_IP}" in
    *[!0-9.]*) die "SANDBOX_SSH_HOST_IP is not an IPv4 address: ${SSH_HOST_IP}" ;;
esac

# --- Select the iptables backend -----------------------------------------
# Docker installs the NAT rules for its embedded DNS (127.0.0.11) into this
# netns using the backend the *host* daemon uses. Our rules must use the same
# backend: mixing legacy and nft tables splits the ruleset across two engines,
# and some kernels (e.g. OpenVZ/Virtuozzo) refuse to create the nft nat OUTPUT
# base chain while a legacy nat table exists ("CHAIN_ADD failed (Device or
# resource busy)"). "auto" picks legacy if legacy rules are already present.
select_backend() {
    case "${BACKEND}" in
        nft|legacy) ;;
        auto)
            if iptables-legacy -t nat -S 2>/dev/null | grep -q '^-[AN] ' \
               || iptables-legacy -S 2>/dev/null | grep -q '^-[AN] '; then
                BACKEND=legacy
            else
                BACKEND=nft
            fi
            ;;
        *) die "SANDBOX_IPTABLES_BACKEND must be auto, nft or legacy: ${BACKEND}" ;;
    esac
    IPT="iptables-${BACKEND}"
    IP6T="ip6tables-${BACKEND}"
    command -v "${IPT}" >/dev/null 2>&1 || die "${IPT} not found"
}
select_backend

# --- nat table: transparent TCP redirection ------------------------------
# Rebuild SANDBOX_REDIR from scratch so re-applying is idempotent.
"${IPT}" -t nat -F SANDBOX_REDIR 2>/dev/null || true
"${IPT}" -t nat -N SANDBOX_REDIR 2>/dev/null || true

# Do not touch traffic created by the tunnel account (ssh + redsocks); this is
# what prevents the redsocks -> REDIRECT -> redsocks loop.
"${IPT}" -t nat -A SANDBOX_REDIR -m owner --uid-owner "${TUNNEL_UID}" -j RETURN
# Leave loopback and intra-subnet traffic alone.
"${IPT}" -t nat -A SANDBOX_REDIR -d 127.0.0.0/8 -j RETURN
"${IPT}" -t nat -A SANDBOX_REDIR -d "${SUBNET}" -j RETURN
# Everything else that is TCP goes to redsocks.
"${IPT}" -t nat -A SANDBOX_REDIR -p tcp -j REDIRECT --to-ports "${REDSOCKS_PORT}"

# Hook the chain into OUTPUT exactly once.
"${IPT}" -t nat -C OUTPUT -p tcp -j SANDBOX_REDIR 2>/dev/null \
    || "${IPT}" -t nat -A OUTPUT -p tcp -j SANDBOX_REDIR

# --- filter table: default deny, allow only the tunnel -------------------
"${IPT}" -P INPUT DROP
"${IPT}" -P FORWARD DROP
"${IPT}" -P OUTPUT DROP

# Flush the built-in chains so a re-apply does not stack duplicate rules.
"${IPT}" -F INPUT
"${IPT}" -F FORWARD
"${IPT}" -F OUTPUT

# Loopback is unrestricted. REDIRECTed packets leave via lo (destination becomes
# 127.0.0.1), so this rule also covers the path into redsocks.
"${IPT}" -A INPUT  -i lo -j ACCEPT
"${IPT}" -A OUTPUT -o lo -j ACCEPT

# REDIRECTed connections: the -o lo rule above is not enough. On some kernels
# (seen on OpenVZ/Virtuozzo) the filter OUTPUT chain still sees the original
# egress interface for the first packet after the nat rewrite, so the SYN to
# redsocks hits the DROP policy. Accept exactly that: NATed TCP to redsocks.
"${IPT}" -A OUTPUT -p tcp -d 127.0.0.1 --dport "${REDSOCKS_PORT}" \
    -m conntrack --ctstate DNAT -j ACCEPT

# Keep established flows (return traffic of the tunnel and of loopback).
"${IPT}" -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"${IPT}" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# The single permitted non-loopback egress: the ssh tunnel itself.
"${IPT}" -A OUTPUT -p tcp -d "${SSH_HOST_IP}" --dport "${SSH_PORT}" \
    -m owner --uid-owner "${TUNNEL_UID}" -j ACCEPT

# --- IPv6: closed completely --------------------------------------------
# IPv6 is a classic bypass. It is disabled via sysctl in compose; the DROP
# policy here is the belt-and-suspenders second half.
"${IP6T}" -P INPUT DROP   2>/dev/null || true
"${IP6T}" -P FORWARD DROP 2>/dev/null || true
"${IP6T}" -P OUTPUT DROP  2>/dev/null || true
"${IP6T}" -F INPUT   2>/dev/null || true
"${IP6T}" -F OUTPUT  2>/dev/null || true
"${IP6T}" -A INPUT  -i lo -j ACCEPT 2>/dev/null || true
"${IP6T}" -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true

printf 'sandbox firewall applied (backend=%s, tunnel uid=%s, ssh=%s:%s)\n' \
    "${BACKEND}" "${TUNNEL_UID}" "${SSH_HOST_IP}" "${SSH_PORT}"
