#!/usr/bin/env bash
#
# app-entrypoint.sh
#
# Description:
#   Entry point of the application container. Runs the workload defined in
#   SANDBOX_APP_CMD. If no command is configured, it idles so an operator can
#   exec into the container for inspection. All network access is governed by
#   the router container that shares this network namespace.
#
# Usage:
#   Invoked as the container ENTRYPOINT. Set SANDBOX_APP_CMD to the command to
#   run (see .env.example). Anything after the entrypoint on the command line is
#   executed instead, if given.
#
# Version: 1.0.0  (2026-09-19)

set -euo pipefail

SCRIPT_NAME="$(basename -- "${0}")"
msg() { printf '%s: %s\n' "${SCRIPT_NAME}" "$*"; }

APP_CMD="${SANDBOX_APP_CMD:-}"

# An explicit command line (docker run ... <cmd>) wins over the env variable.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

if [ -n "${APP_CMD}" ]; then
    msg "starting workload"
    # Run through a shell so SANDBOX_APP_CMD may contain arguments and quoting.
    exec /bin/sh -c "${APP_CMD}"
fi

# No workload configured: stay alive for inspection instead of exiting.
msg "no SANDBOX_APP_CMD set; idling (exec into this container to work)"
exec tail -f /dev/null
