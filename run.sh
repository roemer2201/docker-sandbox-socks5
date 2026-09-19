#!/usr/bin/env bash
#
# run.sh
#
# Description:
#   Lifecycle wrapper for the two-container network sandbox. Checks
#   prerequisites, optionally applies the host firewall, and drives docker
#   compose to build, start, inspect and tear down the sandbox.
#
# Program flow:
#   1. Parse the subcommand and options; load .env.
#   2. Resolve the docker compose invocation and verify prerequisites.
#   3. Run the requested action (build/up/down/shell/status/test/logs).
#
# Usage:
#   run.sh <command> [-v|--verbose] [-s|--silent]
#
#   Commands:
#     build     Build both images.
#     up        Build if needed, start the sandbox, wait until healthy.
#     down      Stop and remove the sandbox (and host rules, if applied).
#     shell     Open a shell in the application container.
#     status    Show container and health status.
#     test      Run the leak tests against the running sandbox.
#     logs      Follow the router and app logs.
#     help      Show this help.
#
#   Options:
#     -v, --verbose  Verbose output.   Env: SANDBOX_VERBOSE  Default: 0
#     -s, --silent   Only errors.      Env: SANDBOX_SILENT   Default: 0
#
# Version: 1.0.0  (2026-09-19)

set -euo pipefail

SCRIPT_NAME="$(basename -- "${0}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${0}")" && pwd)"

# --- Output helpers ------------------------------------------------------
# TODO(logging): syslog/journal integration is intentionally deferred.
VERBOSE=0
SILENT=0
info()  { [ "${SILENT}" -eq 1 ] || printf '%s\n' "$*"; }
debug() { [ "${VERBOSE}" -eq 1 ] && printf 'debug: %s\n' "$*" || true; }
err()   { printf '%s: error: %s\n' "${SCRIPT_NAME}" "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() { sed -n '3,33p' -- "${0}" | sed 's/^# \{0,1\}//'; }

# --- Load .env -----------------------------------------------------------
if [ -r "${SCRIPT_DIR}/.env" ]; then
    set +u
    # shellcheck source=/dev/null
    . "${SCRIPT_DIR}/.env"
    set -u
fi

VERBOSE="${SANDBOX_VERBOSE:-0}"
SILENT="${SANDBOX_SILENT:-0}"
APPLY_HOST_RULES="${SANDBOX_APPLY_HOST_RULES:-0}"
ROUTER_NAME="${SANDBOX_ROUTER_NAME:-sandbox-router}"
APP_NAME="${SANDBOX_APP_NAME:-sandbox-app}"
SSH_KEY="${SANDBOX_SSH_KEY:-./secrets/id_ed25519}"
KNOWN_HOSTS="${SANDBOX_SSH_KNOWN_HOSTS:-./secrets/known_hosts}"

# --- Parse subcommand + options ------------------------------------------
COMMAND="${1:-help}"
[ "$#" -gt 0 ] && shift || true
while [ "$#" -gt 0 ]; do
    case "${1}" in
        -v|--verbose) VERBOSE=1; shift ;;
        -s|--silent)  SILENT=1;  shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "unknown argument: ${1}"; usage >&2; exit 2 ;;
    esac
done
if [ "${SILENT}" -eq 1 ] && [ "${VERBOSE}" -eq 1 ]; then
    die "--silent and --verbose are mutually exclusive"
fi

# --- Resolve the docker compose invocation -------------------------------
detect_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE="docker-compose"
    else
        die "docker compose not found (install Docker Engine with the compose plugin)"
    fi
    debug "using compose command: ${COMPOSE}"
}

# --- Prerequisite checks for starting ------------------------------------
check_prereqs() {
    command -v docker >/dev/null 2>&1 || die "docker not found"
    [ -r "${SCRIPT_DIR}/.env" ] || die ".env not found; copy .env.example to .env and edit it"
    [ -s "${SCRIPT_DIR}/${SSH_KEY}" ] 2>/dev/null || [ -s "${SSH_KEY}" ] 2>/dev/null \
        || die "ssh key not found or empty: ${SSH_KEY}"
    [ -s "${SCRIPT_DIR}/${KNOWN_HOSTS}" ] 2>/dev/null || [ -s "${KNOWN_HOSTS}" ] 2>/dev/null \
        || die "known_hosts not found or empty: ${KNOWN_HOSTS} (add the ssh server key)"
}

# Run apply-rules.sh, using sudo when not already root.
apply_host_rules() {
    local mode="${1}"
    [ "${APPLY_HOST_RULES}" = "1" ] || { debug "host rules disabled"; return 0; }
    local runner=""
    [ "$(id -u)" -ne 0 ] && runner="sudo"
    info "applying host firewall (${mode})"
    ${runner} "${SCRIPT_DIR}/apply-rules.sh" "--${mode}" || die "apply-rules.sh --${mode} failed"
}

# Wait until the router container reports healthy.
wait_healthy() {
    local timeout="${1:-90}"
    local waited=0 status
    info "waiting for the router to become healthy (timeout ${timeout}s)"
    while :; do
        status="$(docker inspect --format '{{.State.Health.Status}}' "${ROUTER_NAME}" 2>/dev/null || true)"
        debug "router health: ${status:-unknown}"
        [ "${status}" = "healthy" ] && { info "router is healthy"; return 0; }
        waited=$((waited + 2))
        [ "${waited}" -ge "${timeout}" ] && die "router did not become healthy within ${timeout}s (see: ${SCRIPT_NAME} logs)"
        sleep 2
    done
}

detect_compose

case "${COMMAND}" in
    build)
        check_prereqs
        ${COMPOSE} -f "${SCRIPT_DIR}/docker-compose.yml" build
        ;;
    up)
        check_prereqs
        apply_host_rules apply
        ${COMPOSE} -f "${SCRIPT_DIR}/docker-compose.yml" up -d --build
        wait_healthy 90
        info "sandbox is up. Open a shell with: ${SCRIPT_NAME} shell"
        ;;
    down)
        ${COMPOSE} -f "${SCRIPT_DIR}/docker-compose.yml" down
        apply_host_rules remove
        ;;
    shell)
        docker exec -it "${APP_NAME}" /bin/bash 2>/dev/null \
            || docker exec -it "${APP_NAME}" /bin/sh
        ;;
    status)
        ${COMPOSE} -f "${SCRIPT_DIR}/docker-compose.yml" ps
        printf 'router health: %s\n' \
            "$(docker inspect --format '{{.State.Health.Status}}' "${ROUTER_NAME}" 2>/dev/null || echo unknown)"
        ;;
    test)
        "${SCRIPT_DIR}/tests/leak-test.sh"
        ;;
    logs)
        ${COMPOSE} -f "${SCRIPT_DIR}/docker-compose.yml" logs -f
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        err "unknown command: ${COMMAND}"
        usage >&2
        exit 2
        ;;
esac
