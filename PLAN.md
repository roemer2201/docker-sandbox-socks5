# PLAN.md - Netzwerk-Sandbox mit erzwungenem SOCKS5-Egress

Stand: 2026-09-19 (Revision 3)
Status: In Umsetzung - Zwei-Container-Setup

Revision 3 setzt die abgestimmte Architektur um:

* **Zwei Container.** Ein Router-Container buendelt alle Netzdienste
  (SSH-Tunnel, DNS-Proxy, transparente Umlenkung, Firewall). Ein
  App-Container fuehrt die zu kapselnde, nicht vertrauenswuerdige Anwendung aus
  und teilt sich den Netz-Namespace des Routers.
* **Der SSH-Tunnel laeuft im Router-Container**, nicht mehr auf dem Host.
  Damit ist die gesamte Loesung containerisiert und auf Ubuntu wie Rocky Linux
  gleichermassen einsetzbar (auf Rocky ist redsocks nicht ohne Weiteres
  paketiert - im Container spielt das keine Rolle).
* **DNS ueber TCP** durch einen cachenden unbound (Begruendung: Abschnitt 4).
* **Die Anwendung ist beliebig und wird ausschliesslich ueber `.env`
  konfiguriert.** In keiner Datei dieses Repos ist eine konkrete Anwendung fest
  verdrahtet.

---

## 1. Ziel

Nicht vertrauenswuerdige Anwendungen kapseln und ihren gesamten Netzverkehr
durch einen einzigen, kontrollierten Ausgang zwingen, sodass sie keine lokale
oder interne Infrastruktur erreichen koennen. Der Ausgang ist ein SOCKS5-Proxy,
den ein SSH-Tunnel bereitstellt.

Harte Anforderungen:

1. **Transparenz** - die Anwendung braucht keine Proxy-Konfiguration.
2. **Fail-closed** - kein Tunnel, kein Netz. Kein direkter Fallback.
3. **Default-Deny** - alles ausser dem Proxy-Pfad ist geblockt.
4. **Isolation der Anwendung** - die Anwendung kann die Netzkontrolle nicht
   aushebeln, auch wenn sie als root laeuft.
5. **Wiederverwendbar** - das Template gilt fuer beliebige Software; die
   Nutzlast wird ausgetauscht, nicht der Aufbau.

Ausserhalb des Zielbilds: GUI-Anwendungen (X11/Wayland), eingehende
Verbindungen in die Sandbox, Docker Desktop unter Windows/macOS (dort fehlt der
direkt kontrollierbare DOCKER-USER-Pfad), Schutz gegen Kernel-Exploits und
Container-Escapes.

---

## 2. Das bestimmende technische Problem

`ssh -D` stellt einen SOCKS-Server bereit, der **nur TCP** transportiert; der
SOCKS5-Befehl `UDP ASSOCIATE` wird von OpenSSH nicht unterstuetzt. Folgen:

| Konsequenz | Bedeutung |
|---|---|
| Kein UDP durch den Tunnel | QUIC (HTTP/3), NTP, WireGuard, klassisches DNS-over-UDP funktionieren nicht. |
| Kein ICMP | ping/traceroute aus der Sandbox schlagen fehl. Gewollt, dokumentiert. |
| DNS braucht eine Sonderloesung | Abschnitt 4. |

Deshalb: **iptables-REDIRECT + redsocks** statt eines TUN-Ansatzes. Ein
TUN-Device nimmt auch UDP an, das im Tunnel verloren geht - die Anwendung
bekaeme Timeouts statt sauberer Fehler. Mit REDIRECT wird ausschliesslich TCP
umgelenkt; alles Uebrige verwirft die Firewall hart und sofort.

`proxychains` (LD_PRELOAD) scheidet aus: es greift nicht bei statisch
gelinkten Programmen, nicht bei Sprachen mit eigener Syscall-Schicht und nicht
bei Kindprozessen ohne die Umgebungsvariable. Das ist Konvention, keine
Durchsetzung - fuer eine Sandbox ungeeignet.

---

## 3. Architektur

### 3.1 Rollen

```
+-------------------------------+     +-------------------------------------+
|  App-Container                |     |  Router-Container                   |
|  - fuehrt die Anwendung aus   |     |  - autossh: ssh -D (SOCKS5)         |
|  - root moeglich, cap_drop ALL|     |  - redsocks: transparenter TCP-Relay|
|  - keine Netz-Capabilities    |     |  - unbound: DNS ueber TCP, cachend  |
|  - network_mode: service:router     |  - iptables/ip6tables: Firewall     |
+---------------+---------------+     |  - CAP_NET_ADMIN nur hier           |
                |                     +------------------+------------------+
                |  gemeinsamer Netz-Namespace           |
                +---------------------------------------+
                                    |
                                    v
        nat/OUTPUT SANDBOX_REDIR:
          - UID tunnel      -> RETURN   (ssh + redsocks, keine Schleife)
          - 127.0.0.0/8     -> RETURN
          - SANDBOX_SUBNET  -> RETURN
          - sonst TCP       -> REDIRECT --to-ports REDSOCKS_PORT
                                    |
                                    v
        [redsocks] liest Originalziel via SO_ORIGINAL_DST, SOCKS5 CONNECT
                                    |
                                    v  127.0.0.1:SOCKS_PORT (loopback)
        [autossh/ssh -D]  --- filter/OUTPUT: nur UID tunnel -> SSH_HOST:PORT
                                    |
                                    v
        Bridge br-sandbox  ---> Host (Masquerade) ---> SSH-Server ---> Internet
```

Der Trick mit dem Netz-Namespace: `network_mode: "service:router"` (Teil der
Compose-Spezifikation, "Gives the service container access to the specified
service only") legt den App-Container in den Netz-Namespace des Routers. Die
Firewallregeln des Routers gelten damit auch fuer die Anwendung, obwohl der
App-Container sie weder sehen noch aendern kann - er hat kein `CAP_NET_ADMIN`.

### 3.2 Warum das die Root-Frage entschaerft

Die Anwendung darf als root laufen (Compute-Lasten profitieren von einzelnen
Rechten, siehe Abschnitt 6), bekommt aber `cap_drop: [ALL]`. Ohne
`CAP_NET_ADMIN` kann auch root keine iptables-Regel anfassen, und die Regeln
liegen ohnehin im vom Router kontrollierten Namespace. Dockers
Default-Capability-Set enthaelt `NET_ADMIN` gar nicht - der App-Container
verzichtet zusaetzlich auf den Rest.

### 3.3 Verteidigungslinien

| Linie | Ort | Wirkung |
|---|---|---|
| 1 | `filter/OUTPUT` im Router-Namespace, Policy DROP | Nur die UID des Tunnels erreicht `SSH_HOST:PORT`; alles andere TCP wird zu redsocks umgelenkt, der Rest verworfen. Faellt der Tunnel, gibt es keinen Weg hinaus. |
| 2 | `apply-rules.sh` auf dem Host: `DOCKER-USER` + `INPUT`, Match auf `-i BRIDGE` | Weitergeleiteter Verkehr des Sandbox-Netzes darf nur nach `SSH_HOST:PORT`; Host-Dienste sind fuer die Sandbox tabu. Greift auch, wenn Linie 1 fehlte. Optional, empfohlen. |

Beide Host-Ketten matchen auf das **Bridge-Interface**, nicht nur auf das
Quell-Subnetz: eine von innen geaenderte IP kann ein `-s`-Match umgehen, das
Interface nicht. Der Bridge-Name wird per
`com.docker.network.bridge.name` fest vergeben, damit er stabil bleibt.

### 3.4 Der Tunnel im Router-Container

* `autossh` haelt `ssh -N -D 127.0.0.1:${SOCKS_PORT}` am Leben, mit
  `-o ExitOnForwardFailure=yes -o ServerAliveInterval=15
  -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes`.
  `ExitOnForwardFailure=yes` ist wesentlich: sonst laeuft ssh weiter, obwohl der
  lokale Listener nicht zustande kam - der Tunnel waere scheinbar da und
  tatsaechlich tot.
* `StrictHostKeyChecking=yes` mit gepflegter `known_hosts`: ein Tunnel zu einem
  nicht verifizierten Host waere eine MITM-Einladung und wuerde die gesamte
  Schutzwirkung aufheben.
* `SSH_HOST` wird beim Start **einmal aufgeloest, bevor die Firewall auf DROP
  geht**, und in `/etc/hosts` gepinnt. Sonst entsteht ein Henne-Ei-Problem:
  ssh braucht DNS, DNS braucht den Tunnel. `DNS_UPSTREAM` muss eine IP sein.
* Faellt der Tunnel, scheitert redsocks beim Verbindungsaufbau und der
  Healthcheck des Routers schlaegt an. Die Anwendung bekommt Verbindungsfehler,
  nie aber einen direkten Weg.

---

## 4. DNS ueber TCP - Standard, keine Notloesung

DNS ueber TCP ist seit RFC 1035 Teil der Spezifikation. **RFC 7766** (2016)
macht TCP-Unterstuetzung fuer alle DNS-Implementierungen verpflichtend und
erlaubt Resolvern ausdruecklich, TCP zu verwenden, **ohne vorher UDP zu
versuchen**. **RFC 9210** (2022, BCP 235) macht das Zulassen von DNS ueber TCP
zur Best Current Practice. Quad9, Cloudflare und Google bedienen TCP/53.

Umsetzung: **unbound** mit `tcp-upstream: yes` und `forward-zone: name: "."`
auf `DNS_UPSTREAM`. Der so erzeugte TCP-Strom wird vom REDIRECT eingefangen und
laeuft durch den Tunnel. unbound **cacht** - das ist der Hebel gegen die durch
TCP-Handshake plus Tunnel entstehende Latenz: wiederholte Lookups kosten keinen
Netzverkehr mehr.

Die Anwendung im App-Container bekommt per Bind-Mount ein `/etc/resolv.conf`
mit `nameserver 127.0.0.1`. Dockers eingebetteter Resolver (`127.0.0.11`), der
sonst an die Host-Resolver weiterreichen und damit am Tunnel vorbeilaufen
wuerde, wird so umgangen. Der Router selbst braucht nach dem Aufloesen von
`SSH_HOST` kein DNS mehr (redsocks arbeitet mit IPs aus `SO_ORIGINAL_DST`, ssh
nutzt den `/etc/hosts`-Pin, unbound spricht `DNS_UPSTREAM` als IP an).

Fallback `DNS_MODE=dnstc`: redsocks' `dnstc` beantwortet UDP-Anfragen mit
gesetztem TC-Bit; die glibc wiederholt daraufhin ueber TCP (Default-Verhalten;
nur `RES_IGNTC` schaltet es ab). Kein Cache, aber ein Dienst weniger.

---

## 5. Dateien

```
.
|-- PLAN.md
|-- README.md
|-- docker-compose.yml
|-- .env.example              # (statt ".env" - Secrets bleiben aus dem Repo)
|-- .gitignore
|-- run.sh                    # Lifecycle: build / up / down / shell / status / test / logs
|-- apply-rules.sh            # optionale Host-Firewall (INPUT + DOCKER-USER)
|-- blocked-subnets.conf      # Ziel-Netze, die der Sandbox verboten sind
|-- secrets/                  # SSH-Key + known_hosts (nicht im Repo)
|   `-- .gitkeep
|-- router/
|   |-- Dockerfile
|   |-- entrypoint.sh         # Startreihenfolge + Supervision
|   |-- firewall.sh           # iptables/ip6tables im gemeinsamen Namespace
|   |-- healthcheck.sh        # Tunnel + Proxy + DNS lebendig?
|   |-- resolv.conf           # wird in den App-Container gemountet
|   |-- redsocks.conf.tmpl
|   `-- unbound.conf.tmpl
|-- app/
|   |-- Dockerfile            # Basis + optionale Pakete, sonst nichts
|   `-- entrypoint.sh         # fuehrt SANDBOX_APP_CMD aus
`-- tests/
    `-- leak-test.sh          # Nachweis, dass nichts vorbeilaeuft
```

Abweichungen von der urspruenglichen Wunschliste: `Dockerfile` gross
geschrieben (docker build sucht exakt danach); `.env.example` im Repo statt
`.env` (Secrets); Unterverzeichnisse `router/`, `app/`, `tests/` fuer
Uebersicht.

---

## 6. Root und CPU-Durchsatz

Kurz, weil es die Konfiguration bestimmt:

* **Root macht eine Anwendung nicht schneller.** Der Linux-Scheduler bevorzugt
  nicht nach UID. Was root real kann, sind Capabilities/Rlimits:
  `CAP_SYS_NICE` (Prioritaet, Pinning), `CAP_IPC_LOCK`/`RLIMIT_MEMLOCK`
  (mlock), hoehere `RLIMIT_NOFILE`/`RLIMIT_NPROC`. Der haeufigste Effekt:
  eine Anwendung versucht `sched_setscheduler()`, faengt `EPERM` ab und laeuft
  in einem langsameren Pfad weiter - das sieht aus wie "als root schneller",
  ist aber eine fehlende Capability.
* **Der groesste reale Bremsklotz im Container ist CFS-Bandwidth-Throttling.**
  Kernel-Dokumentation: ist das Kontingent einer Periode aufgebraucht, werden
  die Threads gedrosselt bis zur naechsten Periode. Deshalb: **kein `cpus:`
  bzw. `cpu_quota`**, stattdessen **`cpuset`** (Pinning ohne Drosselung, bessere
  Cache-/NUMA-Lokalitaet).
* `seccomp=unconfined` bringt nur bei syscall-lastigen Lasten etwas und
  schwaecht die Isolation - nur nach Messung setzen. Reine Rechenlast laeuft im
  Container nativ.
* redsocks ist ein Userspace-Relay und kostet CPU pro uebertragenem Byte -
  aber in einer **eigenen cgroup** (eigener Container), die der Anwendung nicht
  angerechnet wird. redsocks nutzt `splice(2)` (Option `splice = true`, auf
  modernen Kerneln Default), was Nutzdaten im Kernel haelt.

Konsequenz fuer den App-Container: `cpuset` konfigurierbar, `cpus` bewusst nicht
gesetzt, `shm_size` und `ulimits` (memlock, nofile) konfigurierbar,
`cap_add: [SYS_NICE]` optional per `.env`.

---

## 7. Konfiguration (.env)

Alle Parameter tragen den Praefix `SANDBOX_` und werden sowohl von
`docker compose` als auch von den Skripten gelesen. Wichtige Werte:

* Basis: `SANDBOX_BASE_IMAGE` (Default `ubuntu:26.04`).
* Netz: `SANDBOX_SUBNET`, `SANDBOX_BRIDGE`, `SANDBOX_SOCKS_PORT`,
  `SANDBOX_REDSOCKS_PORT`, `SANDBOX_TUNNEL_UID`.
* Tunnel: `SANDBOX_SSH_HOST`, `SANDBOX_SSH_PORT`, `SANDBOX_SSH_USER`,
  `SANDBOX_SSH_KEY`, `SANDBOX_SSH_KNOWN_HOSTS`.
* DNS: `SANDBOX_DNS_UPSTREAM` (IP), `SANDBOX_DNS_MODE` (unbound|dnstc).
* Anwendung: `SANDBOX_APP_PACKAGES`, `SANDBOX_APP_CMD`, `SANDBOX_APP_CPUSET`,
  `SANDBOX_APP_SHM_SIZE`, `SANDBOX_APP_CAP_SYS_NICE`.
* Host: `SANDBOX_APPLY_HOST_RULES`.

---

## 8. Testplan (`tests/leak-test.sh`)

Alle Tests laufen per `docker exec` im App-Container.

| # | Test | Erwartung |
|---|---|---|
| 1 | `curl -s https://ifconfig.co` | IP des SSH-Servers, nicht die des Hosts |
| 2 | `getent hosts example.com` | loest auf (DNS ueber Tunnel) |
| 3 | `dig +notcp @1.1.1.1 example.com` | Timeout (kein UDP-DNS nach draussen) |
| 4 | `ping -c1 -W2 1.1.1.1` | schlaegt fehl (ICMP blockiert) |
| 5 | `curl -6 -m5 https://[2606:4700:4700::1111]` | schlaegt fehl (kein IPv6) |
| 6 | direkter TCP-Connect zu einer externen IP an redsocks vorbei | wird zu redsocks umgelenkt; ohne Tunnel Fehler, kein Direktweg |
| 7 | Tunnel im Router stoppen, dann `curl` | schlaegt fehl, geht nicht direkt hinaus |

---

## 9. Leak-Analyse

| Bypass-Vektor | Gegenmassnahme | Restrisiko |
|---|---|---|
| Direkte TCP-Verbindung an redsocks vorbei | `nat/OUTPUT` faengt alles TCP; `filter/OUTPUT` Policy DROP | gering |
| UDP (QUIC, DNS, NTP) | Policy DROP - verworfen, nicht halb transportiert | gering; Anwendungen muessen TCP koennen |
| Dockers Resolver `127.0.0.11` | `/etc/resolv.conf` per Bind-Mount auf `127.0.0.1` | gering, im Betrieb zu verifizieren |
| IPv6 | kein IPv6 im Docker-Netz, `ip6tables` DROP | gering |
| Anwendung (root) raeumt die Firewall ab | App-Container ohne `CAP_NET_ADMIN`, `no-new-privileges` | gering |
| IP-Wechsel umgeht `-s`-Match auf dem Host | Host-Regeln matchen auf `-i ${BRIDGE}` | gering |
| Tunnel bricht weg, Direktfallback | fail-closed by design | gering |
| App nutzt zufaellig die Tunnel-UID | App laeuft als root (UID 0) != Tunnel-UID; dokumentierte Randbedingung | gering |
| Container-Escape / Kernel-Exploit | ausserhalb des Modells | nicht adressiert |

---

## 10. Meilensteine

| M | Inhalt | Ergebnis |
|---|---|---|
| M1 | Router-Container: autossh + redsocks + unbound, Firewall, Healthcheck | Egress laeuft transparent durch den Tunnel, fail-closed |
| M2 | App-Container, `network_mode: service:router`, `cap_drop: ALL` | Anwendung gekapselt, Netzkontrolle unantastbar |
| M3 | `docker-compose.yml`, `.env.example`, `run.sh` | reproduzierbarer Betrieb per einem Befehl |
| M4 | `apply-rules.sh`, `blocked-subnets.conf` | Host-seitige zweite Linie |
| M5 | `tests/leak-test.sh`, `README.md` | Dichtheit nachgewiesen, uebergabefaehig |

---

## 11. Skript-Konventionen

Alle Skripte folgen den vereinbarten Konventionen: Header mit
Beschreibung/Zweck, Programmablaufplan (laengere Skripte), Usage,
`Version: MAJOR.MINOR.PATCH (Datum)` nach SemVer, kein Author-Feld;
`-h/--help`; `-s/--silent` und `-v/--verbose` bei den Orchestrierungsskripten;
jeder Parameter zusaetzlich per Umgebungsvariable mit Praefix `SANDBOX_`
(Praezedenz Default < Env < CLI); ausschliesslich ASCII, Englisch; Variablen als
`"${var}"`; Fehlermeldungen nach STDERR, Exit 2 bei Aufruffehlern.

**Offener Punkt Logging:** Strukturiertes Logging ueber `logger`/syslog wird
nicht ungefragt eingebaut. Die Skripte geben nach STDOUT/STDERR aus; die
syslog-Anbindung ist als To-do markiert - Format, Facility und Loglevel legst
du fest.

---

## 12. Verifizierte Grundlagen

Gegen Primaerquellen geprueft:

* `ubuntu:26.04` existiert als offizieller Docker-Tag (Docker-Hub-API).
* `redsocks` (universe), `unbound` (main), `autossh` (universe),
  `openssh-client` (main), `iptables` sind in Ubuntu 26.04 "resolute"
  paketiert.
* `REDIRECT` ist "only valid in the nat table, in the PREROUTING and OUTPUT
  chains" und setzt bei lokal erzeugten Paketen das Ziel auf `127.0.0.1`
  (`iptables-extensions(8)`).
* `-m owner --uid-owner` ist "only valid in the OUTPUT and POSTROUTING chains"
  (`iptables-extensions(8)`).
* `DOCKER-USER` wird vor `DOCKER-FORWARD`/`DOCKER` ausgewertet
  (Docker-Dokumentation).
* Dockers Default-Capabilities enthalten `NET_ADMIN` nicht
  (moby `oci/caps/defaults.go`).
* CFS-Bandwidth-Throttling drosselt Threads bis zur naechsten Periode, sobald
  das Quota aufgebraucht ist (Kernel `sched-bwc.rst`).
* `network_mode: "service:{name}"`, `cpuset`, `shm_size`, `ulimits`, `init`
  und `com.docker.network.bridge.name` sind dokumentiert (Compose-Spec,
  Docker-Bridge-Treiberoptionen).
* RFC 7766 (TCP fuer DNS verpflichtend, TCP ohne vorherigen UDP-Versuch
  erlaubt) und RFC 9210 / BCP 235 (Zulassen von DNS ueber TCP als BCP).

**Im Betrieb zu verifizieren:** exakte Semantik von unbounds
`tcp-upstream: yes`; ob der resolv.conf-Bind-Mount zusammen mit
`network_mode: service:` wie erwartet wirkt.

### Quellen

- [Docker: Docker with iptables](https://docs.docker.com/engine/network/firewall-iptables/)
- [Docker: Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Docker: Bridge network driver options](https://docs.docker.com/engine/network/drivers/bridge/)
- [moby/moby: oci/caps/defaults.go](https://github.com/moby/moby/blob/master/oci/caps/defaults.go)
- [Compose Specification](https://github.com/compose-spec/compose-spec/blob/main/spec.md)
- [redsocks (darkk/redsocks)](https://github.com/darkk/redsocks)
- [Unbound: unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [iptables-extensions(8)](https://manpages.ubuntu.com/manpages/noble/man8/iptables-extensions.8.html)
- [Linux kernel: CFS Bandwidth Control](https://www.kernel.org/doc/html/latest/scheduler/sched-bwc.html)
- [RFC 7766: DNS Transport over TCP - Implementation Requirements](https://www.rfc-editor.org/info/rfc7766/)
- [RFC 9210: DNS Transport over TCP - Operational Requirements (BCP 235)](https://www.rfc-editor.org/info/rfc9210/)
- [openssh-unix-dev: SOCKS5 and UDP](https://openssh-unix-dev.mindrot.narkive.com/CtaC5QcY/socks5-and-udp)
- [Docker Hub: ubuntu (official image)](https://hub.docker.com/_/ubuntu)
