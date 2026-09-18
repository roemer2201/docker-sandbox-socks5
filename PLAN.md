# PLAN.md - Docker-Sandbox mit erzwungenem SOCKS5-Egress

Stand: 2026-09-18
Status: Entwurf zur Abstimmung - **noch keine Implementierung**

---

## 1. Ziel

Ein reproduzierbar gebauter Docker-Container auf Basis von Ubuntu 26.04
("Resolute Raccoon"), in dem eine beliebige Anwendung laeuft, deren gesamter
Netzwerkverkehr zwingend durch einen SOCKS5-Proxy geht, der von einem
SSH-Tunnel (`ssh -D`) zu einem externen Host bereitgestellt wird.

Harte Anforderungen:

1. **Transparenz** - die Anwendung braucht keine Proxy-Konfiguration.
2. **Fail-closed** - faellt der Tunnel aus, gibt es *keinen* Netzverkehr,
   insbesondere keinen direkten Fallback.
3. **Default-Deny** - alles ausser dem Proxy-Pfad ist geblockt, und zwar
   sowohl im Container als auch auf dem Host.
4. **Fallback fuer Sonderfaelle** - Anwendungen, die einen Proxy explizit
   ansprechen wollen, finden ihn zusaetzlich unter einer festen Adresse
   (`127.0.0.1:1080`, plus `ALL_PROXY`/`HTTPS_PROXY` in der Umgebung).

Ausserhalb des Zielbilds (vorerst): GUI-Anwendungen (X11/Wayland-Sockets),
eingehende Verbindungen in den Container, Windows-/macOS-Hosts (Docker Desktop
hat keinen direkt kontrollierbaren `DOCKER-USER`-Pfad).

---

## 2. Das zentrale technische Problem

`ssh -D` implementiert einen SOCKS-Server, der **nur TCP** transportiert. Der
SOCKS5-Befehl `UDP ASSOCIATE` wird von OpenSSH nicht unterstuetzt. Daraus
folgen drei Konsequenzen, die das gesamte Design bestimmen:

| Konsequenz | Bedeutung |
|---|---|
| Kein UDP durch den Tunnel | QUIC (HTTP/3), NTP, WireGuard, klassisches DNS-over-UDP funktionieren nicht. |
| Kein ICMP | `ping` und `traceroute` aus dem Container heraus schlagen fehl. Das ist gewollt, muss aber dokumentiert sein. |
| DNS braucht eine Sonderloesung | Ohne funktionierendes DNS ist der Container faktisch unbrauchbar. Siehe Abschnitt 4.3. |

Genau deshalb faellt die Wahl auf **iptables-REDIRECT + redsocks** und nicht
auf einen TUN-basierten Ansatz: ein TUN-Device wuerde auch UDP-Pakete
annehmen, die dann im Tunnel verloren gehen - die Anwendung bekaeme
Timeouts statt sauberer Fehler. Mit REDIRECT wird ausschliesslich TCP
umgelenkt; jedes andere Protokoll wird von der Firewall **hart verworfen**,
was zu klaren, schnellen Fehlern fuehrt.

---

## 3. Architektur

### 3.1 Datenfluss

```
+---------------------------------------------------------------+
|  Container "sandbox"   (eigener Network-Namespace)            |
|                                                               |
|   [Anwendung, UID 10001]                                      |
|        |  connect() -> 93.184.216.34:443                      |
|        v                                                      |
|   nat/OUTPUT -> Kette SANDBOX_REDIR                           |
|        |  (UID 10002 ausgenommen, Loopback ausgenommen)       |
|        |  REDIRECT --to-ports 12345                           |
|        v                                                      |
|   [redsocks, UID 10002]  127.0.0.1:12345                      |
|        |  Originalziel via SO_ORIGINAL_DST rekonstruiert      |
|        |  SOCKS5 CONNECT                                      |
|        v                                                      |
|   [ssh -D 1080, UID 10002]  127.0.0.1:1080                    |
|        |                                                      |
|        |  einzige von filter/OUTPUT erlaubte Verbindung       |
+--------|------------------------------------------------------+
         |  TCP ${SSH_PORT} -> ${SSH_HOST}
         v
   Bridge br-xxxxxxxx (Host)
         |
   FORWARD -> DOCKER-USER -> Kette SANDBOX_EGRESS
         |    (alles ausser ${SSH_HOST}:${SSH_PORT} wird verworfen)
         v
   [externer SSH-Server] ---> Internet
```

Zwei voneinander unabhaengige Verteidigungslinien:

* **Linie 1 (Container):** `filter/OUTPUT` mit Policy `DROP`. Nur Loopback und
  die eine TCP-Verbindung des Tunnel-UID nach `${SSH_HOST}:${SSH_PORT}` sind
  erlaubt. Selbst wenn redsocks abstuerzt, kann kein Paket direkt hinaus.
* **Linie 2 (Host):** `DOCKER-USER` verwirft alles, was aus dem Sandbox-Subnetz
  kommt und nicht an den SSH-Endpunkt geht. Diese Linie haelt auch dann, wenn
  jemand im Container die Container-Firewall abschaltet.

### 3.2 Entscheidung: Wo laeuft der SSH-Client?

| | Variante A: im Container (**Empfehlung**) | Variante B: auf dem Host |
|---|---|---|
| Tunnel-Prozess | `autossh`/`ssh -D` im Container | `ssh -D 0.0.0.0:1080` auf dem Host |
| Container erreicht | nur `${SSH_HOST}:${SSH_PORT}` | nur Bridge-Gateway:1080 |
| Docker-Netz | normale Bridge | kann `internal: true` sein |
| Portabilitaet | Container ist autark, `run.sh` genuegt | Host-Setup noetig (Tunnel + systemd-Unit) |
| Angriffsflaeche | SSH-Key liegt im Container-Kontext | Key bleibt auf dem Host |
| Host-Regeln | nur `DOCKER-USER` (FORWARD) | zusaetzlich `INPUT` (siehe 5.3) |

**Empfehlung: Variante A**, weil damit der gesamte Mechanismus im Repo
abbildbar ist und `run.sh` ohne vorbereiteten Host-Dienst funktioniert. Der
Key-Nachteil laesst sich entschaerfen, indem statt einer Key-Datei der
SSH-Agent-Socket eingebunden wird (`SSH_AUTH_SOCK`), sodass nie ein privater
Schluessel im Container liegt.

Variante B bleibt ueber `.env` (`PROXY_MODE=external`) waehlbar: dann entfaellt
der SSH-Teil im Container und redsocks zeigt auf `${PROXY_HOST}:${PROXY_PORT}`.
Das ist auch der Weg, wenn der SOCKS5-Proxy gar nicht von SSH stammt.

### 3.3 Entscheidung: Transparenz-Layer

| Ansatz | Bewertung |
|---|---|
| **redsocks + iptables REDIRECT** | Gewaehlt. Vollstaendig transparent fuer TCP, unabhaengig von libc und Programmiersprache, kein TUN-Device noetig, in Ubuntu 26.04 als Paket verfuegbar (`redsocks`, universe). |
| `proxychains-ng` (LD_PRELOAD) | Verworfen. Greift nur bei dynamisch gelinkten Programmen, die `connect()` der libc nutzen - statische Go-Binaries und alles mit direkten Syscalls entkommen. Keine Durchsetzung, nur Konvention. |
| `tun2socks` (TUN-Device) | Verworfen als Default. Faengt auch UDP ab, das der SSH-Tunnel nicht transportieren kann - Ergebnis waeren Timeouts statt Fehlern. Braucht `/dev/net/tun`. Als Option sinnvoll, falls spaeter ein UDP-faehiger SOCKS5-Server (z. B. Dante) statt `ssh -D` genutzt wird. |
| `sshuttle` | Verworfen. Loest dasselbe Problem elegant, aber ohne SOCKS5 - widerspricht der Anforderung und bringt eine eigene, weniger kontrollierbare Firewall-Logik mit. |

### 3.4 DNS - der kritische Punkt

Drei Teilprobleme greifen ineinander:

1. **UDP geht nicht durch den Tunnel** (siehe Abschnitt 2).
2. **Docker setzt bei benutzerdefinierten Netzen einen eigenen Resolver**
   auf `127.0.0.11` in den Container-Namespace, der externe Anfragen an die
   Resolver des Hosts weiterreicht. Diese Anfragen wuerden am Proxy
   vorbeilaufen und sind damit ein echter Leak-Pfad - unsere `OUTPUT`-Policy
   `DROP` blockt sie, aber dann gibt es ohne Ersatz gar kein DNS mehr.
3. Ohne DNS-Aufloesung im Container ist fast jede Anwendung unbrauchbar.

**Loesung:** ein lokaler Resolver im Container, der ausschliesslich ueber TCP
nach oben spricht - dieser TCP-Strom wird vom REDIRECT eingefangen und laeuft
damit automatisch durch den Tunnel.

* Primaerwahl: **unbound** mit `tcp-upstream: yes` (die Option existiert laut
  NLnet-Labs-Dokumentation genau fuer Tunnel-Szenarien) und einer
  `forward-zone: name: "."` auf einen konfigurierbaren Upstream. Unbound ist in
  Ubuntu 26.04 in `main`, cached, und ist weniger fragil als die Alternativen.
* Anbindung: In `docker-compose.yml` wird `dns: [127.0.0.1]` gesetzt. Laut
  Docker-Dokumentation bezieht sich `--dns=127.0.0.1` ausdruecklich auf die
  Loopback-Adresse *des Containers*; der eingebettete Resolver leitet dann an
  unseren lokalen unbound weiter statt an die Host-Resolver.
* Alternativen, falls unbound Probleme macht:
  * `dnstc` aus redsocks - ein Fake-DNS-Server, der jede UDP-Anfrage mit
    gesetztem TC-Bit beantwortet und den Resolver so zum TCP-Retry zwingt.
    Funktioniert mit glibc zuverlaessig, ist aber vom Verhalten des Clients
    abhaengig.
  * `dnsu2t` aus redsocks - multiplext UDP-Anfragen in einen TCP-Strom zum
    Upstream. Konzeptionell ideal, im Projekt aber als experimentell markiert.

Im Bauplan wird unbound als Default gesetzt; `dnstc` wird als Schalter in
`.env` (`DNS_MODE=unbound|dnstc`) vorgesehen.

### 3.5 IPv6

IPv6 ist ein klassischer Bypass: `ssh -D` liefert zwar IPv6-Ziele im Tunnel,
aber jede Luecke in den v4-Regeln waere ueber v6 offen. Daher:

* `sysctls: net.ipv6.conf.all.disable_ipv6=1` im Compose-File,
* zusaetzlich `ip6tables` mit Policy `DROP` in allen drei Ketten,
* im Host-Regelwerk optional eine `ip6tables`-Entsprechung.

### 3.6 Ausbaustufe 2: Sidecar-Variante (Empfehlung fuer spaeter)

Die Ein-Container-Loesung hat eine strukturelle Schwaeche: der Container
braucht `CAP_NET_ADMIN`, um seine eigene Firewall zu setzen. Laeuft die
Anwendung als root, kann sie diese Firewall wieder abraeumen. Deshalb gilt
verbindlich: **die Anwendung laeuft unprivilegiert** (`APP_UID`, plus
`no-new-privileges`).

Wenn die Anwendung zwingend root braucht, ist die saubere Loesung eine
Aufteilung in zwei Container, die sich einen Network-Namespace teilen:

```yaml
services:
  gateway:            # ssh -D, redsocks, unbound, Firewall, CAP_NET_ADMIN
  app:
    network_mode: "service:gateway"    # kein eigener Netz-Stack, keine Caps
    depends_on:
      gateway:
        condition: service_healthy
```

`network_mode: "service:{name}"` ist Teil der Compose-Spezifikation. Die
App bekommt dann `cap_drop: [ALL]` und kann die Regeln prinzipiell nicht
anfassen. Das ist dieselbe Struktur, die VPN-Sidecars verwenden. Ich schlage
vor, damit **nicht** zu starten, sondern es als Stufe 2 umzusetzen, sobald
Stufe 1 nachweislich dicht ist.

---

## 4. Dateien

Die von dir vorgeschlagene Struktur bleibt erhalten, mit drei bewussten
Abweichungen (Begruendung darunter):

```
.
|-- PLAN.md                    # dieses Dokument
|-- README.md                  # Dokumentation, Betrieb, Troubleshooting
|-- Dockerfile                 # (statt "dockerfile", s. u.)
|-- docker-compose.yml
|-- .env.example               # (statt ".env", s. u.)
|-- .gitignore                 # .env, Keys, known_hosts
|-- run.sh                     # Lifecycle: build / up / shell / test / down
|-- apply-rules.sh             # Host-Firewall (DOCKER-USER + INPUT)
|-- blocked-subnets.conf       # Ziel-Netze, die der Sandbox verboten sind
|-- container/
|   |-- entrypoint.sh          # Startreihenfolge im Container
|   |-- firewall.sh            # Container-interne iptables-Regeln
|   |-- healthcheck.sh         # Tunnel + Proxy + DNS lebendig?
|   |-- redsocks.conf.tmpl
|   `-- unbound.conf.tmpl
`-- tests/
    `-- leak-test.sh           # Nachweis, dass nichts vorbeilaeuft
```

Abweichungen:

1. **`Dockerfile` statt `dockerfile`** - `docker build` sucht per Default exakt
   nach `Dockerfile`; auf case-sensitiven Dateisystemen wuerde die
   Kleinschreibung nur mit explizitem `-f` funktionieren. Compose setzt
   `dockerfile:` zwar explizit, aber der direkte `docker build`-Aufruf soll
   auch klappen.
2. **`.env.example` im Repo, `.env` in `.gitignore`** - die `.env` enthaelt
   Hostnamen, Benutzernamen und Pfade zu Schluesseln. Die gehoeren nicht ins
   Git. Die Beispieldatei dokumentiert alle Variablen vollstaendig.
3. **Unterverzeichnisse `container/` und `tests/`** - haelt das Wurzelverzeichnis
   bei der von dir gewuenschten Uebersichtlichkeit, obwohl mehrere
   Hilfsdateien dazukommen.

---

## 5. Umsetzung je Datei

### 5.1 `Dockerfile`

* `ARG BASE_IMAGE=ubuntu:26.04` - austauschbar, damit die Sandbox auch auf
  einem anderen Unterbau gebaut werden kann.
* Pakete: `openssh-client`, `autossh`, `redsocks`, `unbound`, `iptables`,
  `iproute2`, `ca-certificates`, `curl`, `dnsutils`, `netcat-openbsd`, `tini`.
  Alle in Ubuntu 26.04 vorhanden (`redsocks`/`autossh` aus `universe`).
* `ARG APP_PACKAGES=""` - zusaetzliche apt-Pakete der Zielanwendung, per
  `.env` steuerbar. Optional `COPY app/ /opt/app` plus Aufruf von
  `/opt/app/install.sh`, falls vorhanden - damit ist "beliebige Anwendung"
  ohne Aenderung am Dockerfile moeglich.
* Zwei feste, nicht-privilegierte Benutzer:
  * `sandbox` (`APP_UID`, Default 10001) - fuehrt die Anwendung aus.
  * `tunnel` (`PROXY_UID`, Default 10002) - fuehrt `ssh` und `redsocks` aus.
    Dieser UID ist der einzige, der die Firewall passieren darf. Die Trennung
    ist das Fundament der ganzen Konstruktion, weil `iptables -m owner` genau
    auf diesen UID matcht.
* `ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]`,
  `CMD` kommt aus `.env` (`APP_CMD`).
* Kein `apt-get upgrade` im Image-Build, stattdessen Base-Image-Pinning per
  Digest als Option - reproduzierbare Builds statt beweglicher Ziele.

### 5.2 `container/firewall.sh` (laeuft als root im Container, vor der App)

```sh
# --- NAT: TCP transparent in redsocks umlenken ---
iptables -t nat -N SANDBOX_REDIR
iptables -t nat -A SANDBOX_REDIR -m owner --uid-owner "${PROXY_UID}" -j RETURN
iptables -t nat -A SANDBOX_REDIR -d 127.0.0.0/8                      -j RETURN
iptables -t nat -A SANDBOX_REDIR -d "${SANDBOX_SUBNET}"              -j RETURN
iptables -t nat -A SANDBOX_REDIR -p tcp -j REDIRECT --to-ports "${REDSOCKS_PORT}"
iptables -t nat -A OUTPUT -p tcp -j SANDBOX_REDIR

# --- FILTER: alles zu, ausser Loopback und dem Tunnel selbst ---
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  DROP
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -d "${SSH_HOST_IP}" --dport "${SSH_PORT}" \
                   -m owner --uid-owner "${PROXY_UID}" -j ACCEPT

# --- IPv6 vollstaendig zu ---
ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT; ip6tables -A OUTPUT -o lo -j ACCEPT
```

Wichtige Details, die leicht uebersehen werden:

* Die `-m owner`-Matches sind laut `iptables-extensions(8)` **nur in OUTPUT und
  POSTROUTING** gueltig - genau dort setzen wir sie ein. In FORWARD-Ketten gibt
  es keinen Socket-Owner, deshalb funktioniert dieser Trick auf dem Host nicht
  und wir brauchen dort eine IP-basierte Allowlist.
* Der RETURN fuer `PROXY_UID` in der NAT-Kette verhindert die Schleife
  "redsocks -> REDIRECT -> redsocks".
* Nach dem REDIRECT hat das Paket das Ziel `127.0.0.1` und verlaesst den
  Stack ueber `lo` - die Regel `-A OUTPUT -o lo -j ACCEPT` deckt es also ab.
* `ALLOW_LAN=0` (Default): keine Regel fuer `${SANDBOX_SUBNET}` in `OUTPUT`.
  Wer Nachbarcontainer erreichen will, setzt `ALLOW_LAN=1`.
* `SSH_HOST` muss als **IP-Adresse** vorliegen oder wird beim Start einmalig
  aufgeloest, *bevor* die Policy auf DROP geht. Sonst entsteht ein
  Henne-Ei-Problem: `ssh` braucht DNS, DNS braucht den Tunnel. Die aufgeloeste
  IP wird zusaetzlich in `/etc/hosts` gepinnt.

### 5.3 `apply-rules.sh` (Host, root)

Baut eine eigene Kette `SANDBOX_EGRESS` und haengt sie an **Position 1** in
`DOCKER-USER`. Laut Docker-Dokumentation ist `DOCKER-USER` genau dafuer
vorgesehen: "A placeholder for user-defined rules that will be processed before
rules in the `DOCKER-FORWARD` and `DOCKER` chains." Regeln, die stattdessen an
`FORWARD` angehaengt werden, laufen zu spaet.

```sh
iptables -N SANDBOX_EGRESS 2>/dev/null || iptables -F SANDBOX_EGRESS
iptables -C DOCKER-USER -s "${SANDBOX_SUBNET}" -j SANDBOX_EGRESS 2>/dev/null \
  || iptables -I DOCKER-USER 1 -s "${SANDBOX_SUBNET}" -j SANDBOX_EGRESS

iptables -A SANDBOX_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A SANDBOX_EGRESS -d "${SANDBOX_SUBNET}" -j RETURN
iptables -A SANDBOX_EGRESS -p tcp -d "${SSH_HOST_IP}" --dport "${SSH_PORT}" -j RETURN
# ... danach jede Zeile aus blocked-subnets.conf als DROP ...
iptables -A SANDBOX_EGRESS -j DROP          # Default-Deny am Ende
```

Zwei Punkte, die in den meisten Anleitungen im Netz fehlen und die das Skript
deshalb explizit behandeln muss:

* **`DOCKER-USER` deckt nur weitergeleiteten Verkehr ab.** Pakete vom Container
  an den Host selbst (Bridge-Gateway-IP, also z. B. ein Dienst auf dem Host)
  laufen ueber `INPUT`, nicht ueber `FORWARD`. Ohne zusaetzliche
  `INPUT`-Regel kann die Sandbox also Host-Dienste erreichen. Das Skript legt
  darum eine zweite Kette `SANDBOX_HOST_IN` an, die von `INPUT` aus dem
  Bridge-Interface gerufen wird. In Variante B ist dort genau ein ACCEPT fuer
  den SOCKS-Port noetig, sonst nur DROP.
* **Die Reihenfolge ist Programm.** Der conntrack-RETURN und die Allowlist
  muessen vor den DROPs stehen, sonst bricht der Tunnel selbst ab.

Skript-Eigenschaften:

* Unterbefehle bzw. Schalter: `--apply` (Default), `--remove`, `--status`,
  `--dry-run` (gibt die Regeln aus, ohne sie zu setzen).
* Idempotent: mehrfacher Aufruf erzeugt keine Duplikate (Kette wird geleert und
  neu gefuellt, Sprung nur bei Bedarf eingefuegt).
* Subnetz-Ermittlung wahlweise aus `.env` (`SANDBOX_SUBNET`) oder per
  `docker network inspect`.
* Hinweis auf fehlende Persistenz: Nach einem Reboot sind die Regeln weg.
  `run.sh` ruft `apply-rules.sh` deshalb bei jedem Start auf; optional wird im
  README eine systemd-Unit beschrieben.
* Interaktion mit `ufw`/`firewalld` wird im README benannt - Docker umgeht
  `ufw` bekanntermassen, weil es im NAT-Pfad vor `INPUT`/`OUTPUT` eingreift.

### 5.4 `blocked-subnets.conf`

Format: ein CIDR pro Zeile, `#` als Kommentar, Leerzeilen erlaubt.
Default-Inhalt entspricht deiner Vorgabe "alles ausser dem containerinternen
Netz":

```
# Destinations that the sandbox subnet must not reach.
# Evaluated AFTER the allow-list (SSH endpoint, container subnet, established).
# Default: deny the entire IPv4 space.
0.0.0.0/0

# Less strict example - comment out 0.0.0.0/0 first:
#10.0.0.0/8
#172.16.0.0/12
#192.168.0.0/16
#169.254.0.0/16
```

### 5.5 `container/redsocks.conf.tmpl`

Wird beim Start aus `.env` mit `envsubst` gefuellt. Belegte Optionen aus der
Beispielkonfiguration des Projekts:

```
base {
    log_debug  = off;
    log_info   = on;
    log        = "stderr";
    daemon     = off;
    user       = tunnel;
    group      = tunnel;
    redirector = iptables;
}

redsocks {
    local_ip   = 127.0.0.1;
    local_port = 12345;
    ip         = 127.0.0.1;     /* ssh -D listener, Variante A */
    port       = 1080;
    type       = socks5;
}
```

`user`/`group` sind hier sicherheitsrelevant und nicht kosmetisch: redsocks
legt damit den UID fest, auf den die `-m owner`-Ausnahme matcht.

### 5.6 `container/unbound.conf.tmpl`

```
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    do-ip6: no
    hide-identity: yes
    hide-version: yes
    tcp-upstream: yes          # zwingt Upstream-Queries auf TCP -> Tunnel

forward-zone:
    name: "."
    forward-addr: ${DNS_UPSTREAM}
```

### 5.7 `container/entrypoint.sh`

Programmablaufplan:

1. `.env`-Variablen pruefen, Pflichtwerte validieren, sonst Abbruch mit klarer
   Meldung.
2. `SSH_HOST` zu einer IP aufloesen (solange noch Netz da ist) und in
   `/etc/hosts` pinnen.
3. Templates rendern (`redsocks.conf`, `unbound.conf`).
4. `firewall.sh` ausfuehren - ab hier ist die Policy `DROP`.
5. `unbound` starten, auf Port 53 warten.
6. `autossh`/`ssh -D` als `tunnel` starten
   (`-N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
   -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes`).
7. Auf den SOCKS-Port warten (Timeout `TUNNEL_WAIT`, Default 30 s); kommt er
   nicht hoch, mit Fehler abbrechen, statt die App ohne Netz zu starten.
8. `redsocks` als `tunnel` starten, auf Port 12345 warten.
9. Optionaler Selbsttest (`EGRESS_SELFTEST=1`): eine TCP-Verbindung nach
   aussen, Vergleich der oeffentlichen IP.
10. Umgebung fuer den nicht-transparenten Fallback setzen
    (`ALL_PROXY=socks5h://127.0.0.1:1080`, `HTTP_PROXY`, `HTTPS_PROXY`,
    `NO_PROXY=localhost,127.0.0.1`).
11. Privilegien ablegen und `APP_CMD` als `sandbox` ausfuehren
    (`setpriv --reuid ... --regid ... --init-groups --no-new-privs`).

`StrictHostKeyChecking=yes` mit eingebundener `known_hosts` ist bewusst
gesetzt: ein SOCKS-Tunnel zu einem nicht verifizierten Host ist eine
Einladung zum MITM und wuerde die gesamte Schutzwirkung aufheben.

### 5.8 `docker-compose.yml` (Auszug)

```yaml
services:
  sandbox:
    build:
      context: .
      args:
        BASE_IMAGE: ${BASE_IMAGE:-ubuntu:26.04}
    cap_drop: [ALL]
    cap_add:  [NET_ADMIN, SETUID, SETGID]
    security_opt: ["no-new-privileges:true"]
    sysctls:
      net.ipv6.conf.all.disable_ipv6: "1"
    dns: ["127.0.0.1"]
    networks: [sandbox_net]
    healthcheck:
      test: ["CMD", "/usr/local/bin/healthcheck.sh"]
      interval: 30s
      start_period: 30s
    restart: unless-stopped

networks:
  sandbox_net:
    driver: bridge
    ipam:
      config:
        - subnet: ${SANDBOX_SUBNET:-172.28.77.0/24}
```

Das Subnetz wird **fest vergeben**, weil `apply-rules.sh` es als Match-Kriterium
braucht - ein von Docker frei gewaehltes Subnetz wuerde die Host-Regeln nach
jedem `docker compose down` ins Leere laufen lassen.

`cap_add: NET_ADMIN` wird nur fuer das Setzen der Regeln im Entrypoint
gebraucht. Da die Anwendung unprivilegiert laeuft, kann sie die Capability
nicht nutzen.

### 5.9 `.env.example`

```
# --- Basis ---
BASE_IMAGE=ubuntu:26.04
CONTAINER_NAME=sandbox-socks5
APP_CMD=/bin/bash
APP_PACKAGES=

# --- Netz ---
SANDBOX_SUBNET=172.28.77.0/24
APP_UID=10001
PROXY_UID=10002
ALLOW_LAN=0

# --- Tunnel (PROXY_MODE=internal: ssh im Container) ---
PROXY_MODE=internal
SSH_HOST=203.0.113.10
SSH_PORT=22
SSH_USER=tunneluser
SSH_KEY_FILE=./secrets/id_ed25519
SSH_KNOWN_HOSTS=./secrets/known_hosts
SOCKS_PORT=1080
REDSOCKS_PORT=12345
TUNNEL_WAIT=30

# --- Tunnel (PROXY_MODE=external: SOCKS5 liegt ausserhalb) ---
#PROXY_HOST=172.28.77.1
#PROXY_PORT=1080

# --- DNS ---
DNS_MODE=unbound
DNS_UPSTREAM=9.9.9.9

# --- Host-Regeln ---
APPLY_HOST_RULES=1
EGRESS_SELFTEST=1
```

### 5.10 `run.sh`

Unterbefehle: `build`, `up`, `down`, `shell`, `status`, `test`, `logs`.
Ablauf bei `up`:

1. Vorbedingungen pruefen (`docker`, `docker compose`, `.env`, Key-Datei,
   `known_hosts` vorhanden und nicht leer).
2. Bei `APPLY_HOST_RULES=1`: `apply-rules.sh --apply` (mit `sudo`, falls noetig).
3. `docker compose up -d --build`.
4. Auf `healthy` warten.
5. Bei `EGRESS_SELFTEST=1`: `tests/leak-test.sh` starten und Ergebnis anzeigen.

### 5.11 `README.md`

Gliederung: Zweck und Bedrohungsmodell / Voraussetzungen / Schnellstart /
Konfigurationsreferenz (jede `.env`-Variable) / Betrieb / bekannte
Einschraenkungen (kein UDP, kein ICMP, kein QUIC) / Troubleshooting
(typische Symptome und ihre Ursache) / Sicherheitshinweise / Deinstallation
(`apply-rules.sh --remove`).

---

## 6. Leak-Analyse

| Bypass-Vektor | Gegenmassnahme | Restrisiko |
|---|---|---|
| Direkte TCP-Verbindung unter Umgehung von redsocks | `nat/OUTPUT` faengt **alles** TCP; `filter/OUTPUT` Policy DROP als zweite Linie | gering |
| UDP (QUIC, DNS, NTP) | Policy DROP - UDP wird verworfen, nicht "irgendwie" transportiert | gering; Anwendungen muessen auf TCP zurueckfallen |
| Docker-interner Resolver `127.0.0.11` -> Host-Resolver | `dns: [127.0.0.1]` + `OUTPUT DROP`; eigener unbound mit `tcp-upstream` | gering, aber **im PoC zu verifizieren** |
| IPv6 | `disable_ipv6` + `ip6tables` DROP | gering |
| Anwendung raeumt die Container-Firewall ab | App laeuft unprivilegiert, `no-new-privileges`; Host-Regeln greifen unabhaengig davon | mittel, solange die App im selben Container laeuft -> Ausbaustufe 2 |
| Zugriff auf Host-Dienste ueber die Gateway-IP | Zusatzkette in `INPUT` (Abschnitt 5.3) | gering |
| Tunnel bricht weg, App faellt auf Direktverbindung zurueck | Fail-closed by design: ohne Tunnel schlaegt redsocks fehl, ein direkter Weg existiert nicht | gering |
| Metadaten-Leak beim Aufloesen von `SSH_HOST` | IP in `.env` pinnen oder einmalige Aufloesung vor dem DROP | gering, bewusst akzeptiert |
| Container-Escape / Kernel-Exploit | ausserhalb des Modells | nicht adressiert |

---

## 7. Testplan (`tests/leak-test.sh`)

Jeder Test gibt PASS/FAIL aus; Exit-Code ungleich 0, sobald einer fehlschlaegt.

1. **Egress-IP** - `curl -s https://ifconfig.co` im Container liefert die
   oeffentliche IP des SSH-Servers, nicht die des Hosts. (Positivtest)
2. **DNS funktioniert** - `getent hosts example.com` liefert ein Ergebnis.
3. **DNS laeuft nicht per UDP hinaus** - `dig +notcp @8.8.8.8 example.com`
   muss in einen Timeout laufen.
4. **ICMP blockiert** - `ping -c1 -W2 1.1.1.1` muss fehlschlagen.
5. **IPv6 blockiert** - `curl -6 -m5 https://ipv6.google.com` muss fehlschlagen.
6. **Host-Dienste unerreichbar** - `nc -z -w2 ${GATEWAY_IP} 22` muss fehlschlagen.
7. **Fail-closed** - `pkill ssh` im Container; danach muss jeder
   `curl`-Aufruf fehlschlagen, nicht direkt hinausgehen.
8. **Host-Regel wirkt allein** - Container-Firewall leeren
   (`iptables -P OUTPUT ACCEPT` als root), danach darf `curl` zu einer
   beliebigen externen IP trotzdem nicht durchkommen. Das ist der
   entscheidende Test fuer die zweite Verteidigungslinie.

Test 8 laeuft in einem Wegwerf-Container, nicht in der produktiven Instanz.

---

## 8. Umsetzungsreihenfolge

| Meilenstein | Inhalt | Ergebnis |
|---|---|---|
| **M1** | Manueller PoC: Dockerfile + Entrypoint + redsocks + `ssh -D`, noch ohne Host-Regeln | "Traffic laeuft transparent durch den Tunnel" ist bewiesen |
| **M2** | DNS (unbound `tcp-upstream`), Container-Firewall, Fail-closed | Sandbox ist von innen dicht |
| **M3** | `apply-rules.sh`, `blocked-subnets.conf`, INPUT-Kette | zweite Verteidigungslinie steht |
| **M4** | `run.sh`, Healthcheck, `tests/leak-test.sh` | reproduzierbarer Betrieb, Nachweis per Test |
| **M5** | `README.md`, `.env.example`, `.gitignore` | uebergabefaehig |
| **M6** *(optional)* | Sidecar-Variante (`network_mode: service:`) | App ohne `NET_ADMIN` im eigenen Container |

---

## 9. Konventionen fuer die Skripte

Alle Skripte (`run.sh`, `apply-rules.sh`, `container/*.sh`,
`tests/leak-test.sh`) folgen deinen Skript-Konventionen:

* Header mit Name, Beschreibung/Zweck, Programmablaufplan (bei den laengeren
  Skripten), Usage-Hinweis, `Version: 1.0.0 (JJJJ-MM-TT)` nach SemVer.
  Kein Author-Feld.
* `-h`/`--help` mit vollstaendiger Parameterliste inklusive der jeweils
  zugehoerigen Umgebungsvariable.
* `-s`/`--silent` und `-v`/`--verbose` fuer `run.sh` und `apply-rules.sh`
  (beide klar ueber 50 Zeilen). Silent gewinnt, wenn beides gesetzt ist.
* Jeder Parameter auch per exportierter Umgebungsvariable mit Praefix
  `SANDBOX_` uebergebbar; Praezedenz: Standardwert < `.env` < Umgebung < CLI.
* Ausschliesslich ASCII, Kommentare und Ausgaben auf Englisch.
* Variablen durchgaengig als `"${var}"`.
* Aussagekraeftige Fehlermeldungen nach STDERR, kein pauschales Verwerfen von
  STDERR, Exit 2 bei Aufruffehlern.

**Offener Punkt Logging:** Die Konventionen sehen `logger`/syslog im
nicht-interaktiven Betrieb vor. Ich implementiere das bewusst nicht ungefragt.
Vorschlag: zunaechst reine STDOUT/STDERR-Ausgabe, Logging als To-do markiert -
sag mir, wie du es haben willst (syslog-Facility, Loglevel, Format).

---

## 10. Offene Punkte / Rueckfragen

1. **Variante A oder B?** Soll der `ssh -D`-Prozess im Container laufen
   (Empfehlung) oder auf dem Host? Davon haengen `apply-rules.sh` und das
   Key-Handling ab.
2. **Authentifizierung:** Key-Datei read-only einbinden oder
   `SSH_AUTH_SOCK`/Agent-Forwarding? Agent ist sicherer, macht `run.sh` aber
   abhaengig von einer laufenden Agent-Session.
3. **Zielanwendung:** Gibt es eine konkrete erste Anwendung? Davon haengt ab,
   ob `APP_PACKAGES` reicht oder ein `app/install.sh`-Hook noetig ist - und ob
   sie zwingend root braucht (dann direkt Ausbaustufe 2).
4. **DNS-Upstream:** Welcher Resolver soll hinter dem Tunnel angesprochen
   werden? Der Default `9.9.9.9` ist eine Setzung, keine Empfehlung.
5. **Konfigurationsdatei-Schema:** Deine Konventionen sehen fuer Skripte die
   organisationsbasierte Suche (`/etc/org.conf`, `/etc/${ORGANIZATION}/...`)
   vor. Fuer ein Repo-lokales Projekt wirkt `.env` im Projektverzeichnis
   passender. Soll `apply-rules.sh` das Org-Schema zusaetzlich unterstuetzen?
6. **Persistenz der Host-Regeln:** Reicht der Aufruf durch `run.sh`, oder soll
   eine systemd-Unit mitgeliefert werden, die die Regeln beim Boot setzt?
7. **`internal: true`:** In Variante B waere ein Docker-Netz mit
   `internal: true` naheliegend. Ob der Container dann noch das
   Bridge-Gateway (und damit den SOCKS-Port auf dem Host) erreicht, muss im
   PoC geprueft werden - die Compose-Spezifikation sagt dazu nur
   "externally isolated network", nicht, wie der Host selbst behandelt wird.

---

## 11. Verifizierte Grundlagen

Die folgenden Punkte wurden fuer diesen Plan gegen die Primaerquellen geprueft
und nicht aus dem Gedaechtnis angenommen:

* `ubuntu:26.04` existiert als offizieller Docker-Tag (identischer Digest wie
  `resolute-*`), abgefragt ueber die Docker-Hub-API am 2026-09-18.
* `redsocks` (universe), `unbound` (main), `autossh` (universe),
  `openssh-client` (main) und `iptables` sind in Ubuntu 26.04 "resolute"
  paketiert.
* redsocks-Konfigurationsoptionen (`base`, `redsocks`, `dnstc`, `dnsu2t`) und
  die empfohlenen iptables-Regeln stammen aus `redsocks.conf.example` und
  `README.md` des Projekts.
* `DOCKER-USER` wird vor `DOCKER-FORWARD`/`DOCKER` ausgewertet; an `FORWARD`
  angehaengte Regeln laufen zu spaet (Docker-Dokumentation "Docker with
  iptables").
* `--dns=127.0.0.1` bezieht sich auf die Loopback-Adresse des Containers;
  Docker betreibt bei benutzerdefinierten Netzen einen eingebetteten Resolver
  auf `127.0.0.11` (Docker-Netzwerkdokumentation).
* `-m owner` ist nur in `OUTPUT` und `POSTROUTING` gueltig
  (`iptables-extensions(8)`).
* `network_mode: "service:{name}"` und `internal: true` sind Bestandteil der
  Compose-Spezifikation.
* OpenSSH stellt mit `-D` einen SOCKS4/SOCKS5-Server bereit, der kein
  `UDP ASSOCIATE` unterstuetzt - bestaetigt auf der Mailingliste
  openssh-unix-dev.

**Nicht abschliessend verifiziert** (Doku-Seite war aus dieser Umgebung nicht
erreichbar, im PoC gegenzupruefen): die exakte Semantik von unbounds
`tcp-upstream: yes`. Die Option ist laut NLnet-Labs-Dokumentation dafuer
gedacht, Upstream-Anfragen ausschliesslich ueber TCP zu fuehren, was genau
unserem Tunnel-Szenario entspricht; das gehoert in M2 als Erstes auf den
Pruefstand.

### Quellen

- [Docker: Docker with iptables](https://docs.docker.com/engine/network/firewall-iptables/)
- [Docker: Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Docker: Networking overview (embedded DNS, --dns)](https://docs.docker.com/engine/network/)
- [Compose Specification](https://github.com/compose-spec/compose-spec/blob/main/spec.md)
- [redsocks (darkk/redsocks)](https://github.com/darkk/redsocks)
- [Unbound: unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [iptables-extensions(8)](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [openssh-unix-dev: SOCKS5 and UDP](https://openssh-unix-dev.mindrot.narkive.com/CtaC5QcY/socks5-and-udp)
- [Docker Hub: ubuntu (official image)](https://hub.docker.com/_/ubuntu)
- [Ubuntu Packages: redsocks](https://packages.ubuntu.com/resolute/redsocks)
