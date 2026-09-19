# syntax=docker/dockerfile:1
#
# Application container image for the network sandbox.
#
# Deliberately minimal: it carries the untrusted workload and nothing that could
# interfere with it. It has no network tooling of its own; at runtime it shares
# the router container's network namespace and is subject to the router's
# firewall. The concrete application is not baked in here - it is selected
# entirely through the SANDBOX_APP_* environment variables.

ARG BASE_IMAGE=ubuntu:26.04
FROM ${BASE_IMAGE}

# Optional space-separated list of apt packages the workload needs. Empty by
# default so the image stays generic and reusable.
ARG APP_PACKAGES=""

RUN if [ -n "${APP_PACKAGES}" ]; then \
        apt-get update \
     && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${APP_PACKAGES} \
     && rm -rf /var/lib/apt/lists/* ; \
    fi

COPY entrypoint.sh /usr/local/bin/app-entrypoint.sh
RUN chmod 0755 /usr/local/bin/app-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/app-entrypoint.sh"]
