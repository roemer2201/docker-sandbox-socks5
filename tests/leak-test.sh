#!/usr/bin/env bash
#
# leak-test.sh
#
# Description:
#   Verifies that the sandbox does not leak traffic around the tunnel. All
#   probes run inside the application container via "docker exec", so they see
#   exactly the network the workload sees. Probes that need a tool the app image
#   does not ship are reported as SKIP rather than failing.
#
# Program flow:
#   1. Load .env, resolve the app container name, check it is running.
#   2. Run each probe and classify it PASS / FAIL / SKIP / INFO.
#   3. Print a summary; exit non-zero if any hard probe failed.
#
# Usage:
#   leak-test.sh [-h|--help]
#
#   Env (overridable in .env):
#     SANDBOX_APP_NAME   application container name   Default: sandbox-app
#
# Version: 1.0.0  (2026-09-19)

set -uo pipefail

SCRIPT_NAME="$(basename -- "${0}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${0}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

case "${1:-}" in
    -h|--help) sed -n '3,26p' -- "${0}" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

# Load .env for the container name.
if [ -r "${ROOT_DIR}/.env" ]; then
    set +u; . "${ROOT_DIR}/.env"; set -u
fi
APP_NAME="${SANDBOX_APP_NAME:-sandbox-app}"

# Result counters.
FAILURES=0

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
skip() { printf '  SKIP  %s\n' "$*"; }
info() { printf '  INFO  %s\n' "$*"; }

# Run a command inside the app container.
ax() { docker exec "${APP_NAME}" sh -c "$*"; }
# True if a tool exists in the app container.
have() { docker exec "${APP_NAME}" sh -c "command -v $1 >/dev/null 2>&1"; }

docker inspect "${APP_NAME}" >/dev/null 2>&1 \
    || { printf '%s: error: container not found: %s\n' "${SCRIPT_NAME}" "${APP_NAME}" >&2; exit 1; }

printf 'Leak tests against container %s\n' "${APP_NAME}"

# T1 (INFO): observed egress IP should be the ssh server, not the host.
if have curl; then
    ip="$(ax 'curl -s --max-time 15 https://ifconfig.co' 2>/dev/null || true)"
    if [ -n "${ip}" ]; then
        info "egress IP seen by the workload: ${ip} (should be the ssh server)"
    else
        fail "egress via curl produced no result (tunnel down?)"
    fi
else
    skip "egress IP check (curl not in app image)"
fi

# T2 (HARD): DNS resolves through unbound over the tunnel.
if ax 'getent hosts example.com >/dev/null 2>&1'; then
    pass "DNS resolution works (getent hosts example.com)"
else
    fail "DNS resolution failed (getent hosts example.com)"
fi

# T3 (HARD if dig present): no direct UDP DNS to the outside.
if have dig; then
    if ax 'dig +notcp +time=3 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1'; then
        fail "direct UDP DNS to 1.1.1.1 succeeded (leak)"
    else
        pass "direct UDP DNS to 1.1.1.1 is blocked"
    fi
else
    skip "UDP DNS leak check (dig not in app image)"
fi

# T4 (HARD if ping present): ICMP is blocked.
if have ping; then
    if ax 'ping -c1 -W2 1.1.1.1 >/dev/null 2>&1'; then
        fail "ICMP to 1.1.1.1 succeeded (should be blocked)"
    else
        pass "ICMP to 1.1.1.1 is blocked"
    fi
else
    skip "ICMP check (ping not in app image)"
fi

# T5 (HARD if curl present): IPv6 egress is blocked.
if have curl; then
    if ax 'curl -6 -s --max-time 5 "https://[2606:4700:4700::1111]" >/dev/null 2>&1'; then
        fail "IPv6 egress succeeded (should be blocked)"
    else
        pass "IPv6 egress is blocked"
    fi
else
    skip "IPv6 check (curl not in app image)"
fi

printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
    printf '%s: all hard checks passed\n' "${SCRIPT_NAME}"
    exit 0
fi
printf '%s: %d hard check(s) failed\n' "${SCRIPT_NAME}" "${FAILURES}" >&2
exit 1
