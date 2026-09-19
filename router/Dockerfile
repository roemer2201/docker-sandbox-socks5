# syntax=docker/dockerfile:1
#
# Router container image for the network sandbox.
#
# Bundles every network service that forces the sandbox egress through a
# single SOCKS5 tunnel:
#   - autossh / openssh-client : the ssh -D SOCKS5 tunnel
#   - redsocks                 : transparent TCP redirector into the tunnel
#   - unbound                  : caching DNS resolver, upstream over TCP
#   - iptables / ip6tables     : the enforcing firewall
#
# The application itself lives in a separate image (see ../app) and shares this
# container's network namespace, so these rules apply to it as well.

ARG BASE_IMAGE=ubuntu:26.04
FROM ${BASE_IMAGE}

# Numeric UID of the account that runs ssh and redsocks. This UID is the only
# one whose packets are allowed out of the netns, so it must not collide with
# the UID the application runs as (the app runs as root, UID 0, by default).
ARG TUNNEL_UID=10002

# Install the network toolchain. No recommends, clean apt lists afterwards.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        autossh \
        openssh-client \
        redsocks \
        unbound \
        iptables \
        iproute2 \
        ca-certificates \
        dnsutils \
        netcat-openbsd \
        gettext-base \
        tini \
 && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged account for ssh and redsocks. Its numeric UID is what
# the owner-based firewall rules match on.
RUN groupadd --gid "${TUNNEL_UID}" tunnel \
 && useradd --uid "${TUNNEL_UID}" --gid "${TUNNEL_UID}" \
        --home-dir /home/tunnel --create-home \
        --shell /usr/sbin/nologin tunnel \
 && install -d -m 0700 -o tunnel -g tunnel /home/tunnel/.ssh

# Scripts and templates.
COPY entrypoint.sh firewall.sh healthcheck.sh /usr/local/bin/
COPY redsocks.conf.tmpl unbound.conf.tmpl /etc/sandbox/
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
               /usr/local/bin/firewall.sh \
               /usr/local/bin/healthcheck.sh

# tini reaps zombies and forwards signals to the supervised services.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
