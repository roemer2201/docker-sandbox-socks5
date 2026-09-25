# docker-sandbox-socks5

Zwei-Container-Sandbox, die eine beliebige, nicht vertrauenswuerdige Anwendung
kapselt und ihren **gesamten** Netzverkehr zwingend durch einen SSH-Tunnel
(SOCKS5) leitet. Alles, was nicht durch den Tunnel geht, wird verworfen. Die
Umlenkung ist fuer die Anwendung transparent - sie braucht keine
Proxy-Konfiguration.

Ziel ist Containment: eine Software, der man nicht traut, soll weder lokale noch
interne Infrastruktur erreichen koennen, sondern ausschliesslich ueber einen
kontrollierten, entfernten Ausgang kommunizieren.

Der Aufbau ist bewusst anwendungsunabhaengig. Die konkrete Nutzlast wird nur
ueber `.env` gesetzt und ist an keiner Stelle fest verdrahtet, sodass sich das
Template fuer andere Software wiederverwenden laesst.

Die vollstaendige Entwurfsbegruendung steht in [PLAN.md](PLAN.md).

## Architektur

Zwei Container, die sich einen Netz-Namespace teilen:

* **router** - besitzt den Netz-Namespace und betreibt alle Netzdienste:
  * `autossh` haelt den `ssh -D`-SOCKS5-Tunnel am Leben,
  * `redsocks` lenkt TCP transparent in den Tunnel um,
  * `unbound` loest DNS ueber TCP auf (cachend), sodass die Aufloesung durch
    den Tunnel geht (der Tunnel transportiert kein UDP),
  * `iptables`/`ip6tables` erzwingen die Regeln.
* **app** - fuehrt die zu kapselnde Anwendung aus. Sie haengt per
  `network_mode: "service:router"` im Netz-Namespace des Routers und hat keine
  eigene Netzkontrolle. Sie darf als root laufen, bekommt aber `cap_drop: ALL`
  und kann die Firewall damit nicht anfassen.

```
[app: Workload] --+
                  |  gemeinsamer Netz-Namespace
[router] ---------+--> iptables REDIRECT --> redsocks --> ssh -D --> SSH-Server --> Internet
                                    ^
                        unbound (DNS ueber TCP)
```

## Voraussetzungen

* Docker Engine mit Compose-Plugin (`docker compose`).
* Ein erreichbarer SSH-Server, auf dem `ssh -D` erlaubt ist
  (`AllowTcpForwarding yes`).
* Auf dem Host geladene Netfilter-Module (`iptable_nat`, `iptable_filter`,
  `xt_owner`, `xt_REDIRECT`/`nf_nat_redirect`). Auf Standard-Kernels von Ubuntu
  und Rocky Linux sind sie vorhanden und werden bei Bedarf automatisch geladen.

## Schnellstart

1. Konfiguration anlegen und anpassen:
   ```
   cp .env.example .env
   ${EDITOR:-vi} .env
   ```
   Mindestens setzen: `SANDBOX_SSH_HOST`, `SANDBOX_SSH_USER`.

2. SSH-Material bereitstellen (wird read-only in den Router gemountet):
   ```
   cp /pfad/zum/privaten/key secrets/id_ed25519
   chmod 600 secrets/id_ed25519
   ssh-keyscan -p 22 ssh.example.com > secrets/known_hosts
   ```
   `known_hosts` muss gefuellt sein - strikte Host-Key-Pruefung ist aktiv.
   Pruefe den Fingerprint gegen eine vertrauenswuerdige Quelle.

3. Starten:
   ```
   ./run.sh up
   ```
   Der Router muss "healthy" werden, bevor der App-Container startet.

4. Dichtheit pruefen und arbeiten:
   ```
   ./run.sh test
   ./run.sh shell
   ```

5. Stoppen:
   ```
   ./run.sh down
   ```

## Die Anwendung festlegen

Die Nutzlast wird ausschliesslich ueber `.env` bestimmt:

* `SANDBOX_APP_PACKAGES` - optionale apt-Pakete, die beim Bauen des
  App-Images installiert werden (Leerzeichen-getrennt).
* `SANDBOX_APP_CMD` - der auszufuehrende Befehl. Bleibt er leer, idlet der
  Container, sodass man sich per `./run.sh shell` hineinverbinden kann.

Alternativ kann das App-Image erweitert werden (eigenes Binary per `COPY` in
`app/Dockerfile`), ohne den Router oder die Netzlogik zu aendern.

## Konfigurationsreferenz (.env)

| Variable | Bedeutung | Default |
|---|---|---|
| `SANDBOX_BASE_IMAGE` | Basis-Image beider Container | `ubuntu:26.04` |
| `SANDBOX_SUBNET` | festes Subnetz der Sandbox | `172.28.77.0/24` |
| `SANDBOX_BRIDGE` | fester Bridge-Interface-Name | `br-sandbox` |
| `SANDBOX_SOCKS_PORT` | lokaler SOCKS5-Port des Tunnels | `1080` |
| `SANDBOX_REDSOCKS_PORT` | lokaler redsocks-Port | `12345` |
| `SANDBOX_TUNNEL_UID` | UID von ssh/redsocks (darf nicht die der App sein) | `10002` |
| `SANDBOX_IPTABLES_BACKEND` | iptables-Backend im Router: `auto`, `nft`, `legacy` | `auto` |
| `SANDBOX_SSH_HOST` | SSH-Server (Host oder IP) | - |
| `SANDBOX_SSH_PORT` | SSH-Port | `22` |
| `SANDBOX_SSH_USER` | SSH-Benutzer | - |
| `SANDBOX_SSH_KEY` | privater Key (Pfad) | `./secrets/id_ed25519` |
| `SANDBOX_SSH_KNOWN_HOSTS` | known_hosts (Pfad) | `./secrets/known_hosts` |
| `SANDBOX_TUNNEL_WAIT` | Wartezeit auf den Tunnel beim Start (s) | `30` |
| `SANDBOX_DNS_UPSTREAM` | Upstream-Resolver (IP!) | `9.9.9.9` |
| `SANDBOX_APP_PACKAGES` | apt-Pakete fuer die App | - |
| `SANDBOX_APP_CMD` | Befehl der App | - |
| `SANDBOX_APP_CPUSET` | CPU-Pinning (z.B. `0-7`), leer = alle | - |
| `SANDBOX_APP_SHM_SIZE` | Shared-Memory-Groesse | `256m` |
| `SANDBOX_APPLY_HOST_RULES` | Host-Firewall zusaetzlich anwenden | `0` |

## Betrieb

`./run.sh <command>`:

| Befehl | Wirkung |
|---|---|
| `build` | beide Images bauen |
| `up` | bauen, starten, auf "healthy" warten (ggf. Host-Regeln anwenden) |
| `down` | stoppen und entfernen (ggf. Host-Regeln entfernen) |
| `shell` | Shell im App-Container oeffnen |
| `status` | Container- und Health-Status |
| `test` | Leak-Tests ausfuehren |
| `logs` | Router- und App-Logs folgen |

`-v/--verbose` und `-s/--silent` steuern die Ausfuehrlichkeit.

## Zweite Verteidigungslinie auf dem Host (optional)

`apply-rules.sh` haengt zusaetzliche Regeln in `DOCKER-USER` (weitergeleiteter
Verkehr) und `INPUT` (Verkehr an den Host selbst) ein, die am
Bridge-Interface matchen. Damit bleibt die Sandbox selbst dann eingesperrt,
wenn die Container-Firewall ausfaellt. Aktivierung:

```
# in .env:  SANDBOX_APPLY_HOST_RULES=1
sudo ./apply-rules.sh --apply     # oder automatisch ueber ./run.sh up
sudo ./apply-rules.sh --status
sudo ./apply-rules.sh --dry-run   # Regeln nur anzeigen
sudo ./apply-rules.sh --remove
```

Welche Netze verboten sind, steht in `blocked-subnets.conf`. Standard: alles
ausser dem SSH-Endpunkt und dem containerinternen Netz.

Hinweis zu `ufw`/`firewalld`: Docker greift im NAT-Pfad vor `INPUT`/`OUTPUT`
ein und umgeht `ufw`-Regeln. Verlasse dich zur Kontrolle nicht auf
`ufw status`, sondern auf `iptables -L`/`apply-rules.sh --status`.

## Root und CPU-Durchsatz

Die Anwendung darf als root laufen; das ist im Container ohnehin der Normalfall
und gefaehrdet die Firewall nicht (der App-Container hat kein `CAP_NET_ADMIN`).
Fuer maximalen Durchsatz gilt:

* **Kein CPU-Quota** (`cpus:`) setzen - das aktiviert CFS-Throttling, das
  Threads periodisch anhaelt. Stattdessen `SANDBOX_APP_CPUSET` zum Pinnen
  verwenden.
* Root beschleunigt eine Anwendung nicht per se. Was hilft, sind einzelne
  Rechte: Scheduling-Prioritaet/Pinning erfordert `CAP_SYS_NICE` (in
  `docker-compose.yml` beim App-Container einkommentierbar); `mlock` erfordert
  `RLIMIT_MEMLOCK` (ist auf unbegrenzt gesetzt).
* `seccomp=unconfined` nur nach Messung setzen - es schwaecht die Isolation und
  hilft nur bei syscall-lastigen, nicht bei rein rechengebundenen Lasten.

## Bekannte Einschraenkungen

* **Kein UDP** nach draussen (QUIC/HTTP3, NTP, DNS-over-UDP). Anwendungen
  muessen auf TCP zurueckfallen koennen. DNS laeuft ueber TCP via unbound.
* **Kein ICMP** (kein `ping`/`traceroute` aus der Sandbox).
* **Kein IPv6** (bewusst deaktiviert, sonst ein Bypass).
* Nur Linux-Hosts. Docker Desktop (Windows/macOS) bietet keinen direkt
  kontrollierbaren `DOCKER-USER`-Pfad.
* Kein Schutz gegen Kernel-Exploits oder Container-Escapes.

## Troubleshooting

* **Router wird nicht "healthy".** `./run.sh logs` ansehen. Haeufig: falscher
  `SANDBOX_SSH_HOST/USER`, leere/falsche `known_hosts`, `AllowTcpForwarding no`
  auf dem Server, oder `SANDBOX_DNS_UPSTREAM` ist ein Name statt einer IP.
* **`CHAIN_ADD failed (Device or resource busy): chain OUTPUT`.** Docker legt
  die NAT-Regeln seines eingebauten DNS mit dem Backend des Hosts
  (legacy/nft) im Container-Namespace an. Der Router muss dasselbe Backend
  verwenden; `SANDBOX_IPTABLES_BACKEND=auto` erkennt das. Nur bei Bedarf
  explizit auf `legacy` oder `nft` setzen.
* **DNS im Container geht nicht.** Pruefe, dass `/etc/resolv.conf` im
  App-Container `nameserver 127.0.0.1` enthaelt und der Router "healthy" ist.
* **`getent`/`curl` fehlen im App-Container.** Das App-Image ist minimal; setze
  `SANDBOX_APP_PACKAGES` (z.B. `curl dnsutils iputils-ping`) fuer Tests.
* **Nach einem Reboot fehlen die Host-Regeln.** `apply-rules.sh` persistiert
  nicht; `./run.sh up` setzt sie erneut, oder binde es in eine systemd-Unit ein.

## Deinstallation

```
./run.sh down
sudo ./apply-rules.sh --remove   # falls Host-Regeln aktiv waren
docker image rm sandbox-app:local sandbox-router:local
```

## Sicherheitshinweise

* Der private SSH-Key liegt zur Laufzeit im Router-Container. Nutze einen
  dedizierten, in seinen Rechten eingeschraenkten Tunnel-Account auf dem Server.
* Strikte Host-Key-Pruefung ist aktiv; pflege `known_hosts` bewusst.
* Die Isolation ist netzseitig. Fuer eine Anwendung, der du gar nicht traust,
  kombiniere sie mit den weiteren Docker-Haertungen (`no-new-privileges` ist
  gesetzt; erwaege read-only Root-FS, gezielte `ulimits`, ein seccomp-Profil).
