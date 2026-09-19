#!/usr/bin/env bash
#
# apply-rules.sh
#
# Description:
#   Optional host-side firewall for the network sandbox: a second enforcement
#   layer independent of the container's own rules. It restricts the sandbox
#   bridge so that forwarded traffic may only reach the ssh endpoint, and the
#   sandbox cannot reach services on the host itself.
#
# Program flow:
#   1. Parse arguments and resolve configuration (CLI > env > default; .env is
#      sourced if present).
#   2. Determine the ssh endpoint IP and read blocked-subnets.conf.
#   3. Depending on the mode: apply, remove, show status, or dry-run the rules.
#
# The rules:
#   filter/DOCKER-USER  -i BRIDGE -> SANDBOX_EGRESS
#     established/related        -> RETURN
#     to the sandbox subnet      -> RETURN
#     tcp to SSH_HOST:SSH_PORT   -> RETURN
#     each blocked-subnets entry -> DROP
#     everything else            -> DROP
#   filter/INPUT        -i BRIDGE -> SANDBOX_IN
#     established/related        -> RETURN
#     everything else            -> DROP   (sandbox may not reach host services)
#
# Usage:
#   apply-rules.sh [--apply|--remove|--status|--dry-run] [-v|--verbose] [-s|--silent]
#
#   Options:
#     --apply        Install the rules (default).
#     --remove       Remove the rules and chains.
#     --status       Show the current sandbox chains.
#     --dry-run      Print the iptables commands without executing them.
#     -v, --verbose  Verbose output.              Env: SANDBOX_VERBOSE   Default: 0
#     -s, --silent   Only errors.                 Env: SANDBOX_SILENT    Default: 0
#     -h, --help     Show this help and exit.
#
#   Parameters (env, overridable in .env):
#     SANDBOX_SUBNET    sandbox subnet CIDR         Default: 172.28.77.0/24
#     SANDBOX_BRIDGE    bridge interface name       Default: br-sandbox
#     SANDBOX_SSH_HOST  ssh server host or IP       (required)
#     SANDBOX_SSH_PORT  ssh server port             Default: 22
#
# Version: 1.0.0  (2026-09-19)

set -euo pipefail

SCRIPT_NAME="$(basename -- "${0}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${0}")" && pwd)"
BLOCKED_FILE="${SANDBOX_BLOCKED_FILE:-${SCRIPT_DIR}/blocked-subnets.conf}"

# --- Output helpers ------------------------------------------------------
# TODO(logging): syslog/journal integration is intentionally deferred.
VERBOSE=0
SILENT=0
info()  { [ "${SILENT}" -eq 1 ] || printf '%s\n' "$*"; }
debug() { [ "${VERBOSE}" -eq 1 ] && printf 'debug: %s\n' "$*" || true; }
err()   { printf '%s: error: %s\n' "${SCRIPT_NAME}" "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() { sed -n '3,60p' -- "${0}" | sed 's/^# \{0,1\}//'; }

# --- Load .env if present (values become defaults below) ------------------
if [ -r "${SCRIPT_DIR}/.env" ]; then
    # .env is user-controlled local config; sourcing keeps it to shell builtins.
    set +u
    # shellcheck source=/dev/null
    . "${SCRIPT_DIR}/.env"
    set -u
fi

# --- Defaults (env > built-in) ------------------------------------------
MODE="apply"
SUBNET="${SANDBOX_SUBNET:-172.28.77.0/24}"
BRIDGE="${SANDBOX_BRIDGE:-br-sandbox}"
SSH_HOST="${SANDBOX_SSH_HOST:-}"
SSH_PORT="${SANDBOX_SSH_PORT:-22}"
VERBOSE="${SANDBOX_VERBOSE:-0}"
SILENT="${SANDBOX_SILENT:-0}"

# --- Argument parsing (highest precedence) -------------------------------
while [ "$#" -gt 0 ]; do
    case "${1}" in
        --apply)   MODE="apply";   shift ;;
        --remove)  MODE="remove";  shift ;;
        --status)  MODE="status";  shift ;;
        --dry-run) MODE="dry-run"; shift ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -s|--silent)  SILENT=1;  shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown argument: ${1}"; usage >&2; exit 2 ;;
    esac
done

if [ "${SILENT}" -eq 1 ] && [ "${VERBOSE}" -eq 1 ]; then
    die "--silent and --verbose are mutually exclusive"
fi

# --- iptables wrapper: run or, in dry-run, only print --------------------
IPT="iptables"
run_ipt() {
    if [ "${MODE}" = "dry-run" ]; then
        printf '%s %s\n' "${IPT}" "$*"
        return 0
    fi
    debug "${IPT} $*"
    # Word splitting is intended here: arguments are controlled by this script.
    # shellcheck disable=SC2086
    "${IPT}" $*
}

# Root is required for anything that touches iptables (not for --status/dry-run
# strictly, but iptables -L needs it too on most systems).
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "must run as root (try: sudo ${SCRIPT_NAME} --${MODE})"
    fi
}

# Resolve the ssh endpoint to an IPv4 address.
resolve_ssh_ip() {
    [ -n "${SSH_HOST}" ] || die "SANDBOX_SSH_HOST is required"
    case "${SSH_HOST}" in
        *[!0-9.]*)
            getent ahostsv4 "${SSH_HOST}" 2>/dev/null | awk 'NR==1 {print $1}'
            ;;
        *)
            printf '%s' "${SSH_HOST}"
            ;;
    esac
}

# Ensure Docker's DOCKER-USER chain exists before we try to hook into it.
check_docker_user() {
    [ "${MODE}" = "dry-run" ] && return 0
    iptables -L DOCKER-USER -n >/dev/null 2>&1 \
        || die "DOCKER-USER chain not found; is Docker running and the network created?"
}

# Build the two sandbox chains and hook them in idempotently.
apply_rules() {
    local ssh_ip
    ssh_ip="$(resolve_ssh_ip)"
    [ -n "${ssh_ip}" ] || die "could not resolve SANDBOX_SSH_HOST: ${SSH_HOST}"
    info "applying host rules (bridge=${BRIDGE}, subnet=${SUBNET}, ssh=${ssh_ip}:${SSH_PORT})"

    # --- egress chain (forwarded traffic) ---
    run_ipt "-F SANDBOX_EGRESS" 2>/dev/null || true
    run_ipt "-N SANDBOX_EGRESS" 2>/dev/null || true
    run_ipt "-A SANDBOX_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    run_ipt "-A SANDBOX_EGRESS -d ${SUBNET} -j RETURN"
    run_ipt "-A SANDBOX_EGRESS -p tcp -d ${ssh_ip} --dport ${SSH_PORT} -j RETURN"
    # Blocked subnets from the config file become explicit DROPs.
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "${line}" | tr -d '[:space:]')"
        [ -n "${line}" ] || continue
        run_ipt "-A SANDBOX_EGRESS -d ${line} -j DROP"
    done < "${BLOCKED_FILE}"
    run_ipt "-A SANDBOX_EGRESS -j DROP"
    # Hook into DOCKER-USER exactly once, matching on the bridge interface.
    if ! iptables -C DOCKER-USER -i "${BRIDGE}" -j SANDBOX_EGRESS 2>/dev/null; then
        run_ipt "-I DOCKER-USER 1 -i ${BRIDGE} -j SANDBOX_EGRESS"
    fi

    # --- input chain (traffic to the host itself) ---
    run_ipt "-F SANDBOX_IN" 2>/dev/null || true
    run_ipt "-N SANDBOX_IN" 2>/dev/null || true
    run_ipt "-A SANDBOX_IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    run_ipt "-A SANDBOX_IN -j DROP"
    if ! iptables -C INPUT -i "${BRIDGE}" -j SANDBOX_IN 2>/dev/null; then
        run_ipt "-I INPUT 1 -i ${BRIDGE} -j SANDBOX_IN"
    fi

    info "host rules applied"
}

# Remove the hooks and the chains.
remove_rules() {
    info "removing host rules"
    iptables -D DOCKER-USER -i "${BRIDGE}" -j SANDBOX_EGRESS 2>/dev/null || true
    iptables -D INPUT -i "${BRIDGE}" -j SANDBOX_IN 2>/dev/null || true
    iptables -F SANDBOX_EGRESS 2>/dev/null || true
    iptables -X SANDBOX_EGRESS 2>/dev/null || true
    iptables -F SANDBOX_IN 2>/dev/null || true
    iptables -X SANDBOX_IN 2>/dev/null || true
    info "host rules removed"
}

# Show the current sandbox chains.
show_status() {
    for chain in SANDBOX_EGRESS SANDBOX_IN; do
        printf '=== %s ===\n' "${chain}"
        iptables -L "${chain}" -n -v 2>/dev/null || printf '(chain not present)\n'
    done
}

# --- Dispatch ------------------------------------------------------------
case "${MODE}" in
    apply)
        require_root
        check_docker_user
        apply_rules
        ;;
    remove)
        require_root
        remove_rules
        ;;
    status)
        require_root
        show_status
        ;;
    dry-run)
        apply_rules
        ;;
esac
