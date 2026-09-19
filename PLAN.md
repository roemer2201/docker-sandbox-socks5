# PLAN.md - Docker-Sandbox mit erzwungenem SOCKS5-Egress

Stand: 2026-09-19 (Revision 2)
Status: Entwurf zur Abstimmung - **noch keine Implementierung**

Revision 2 setzt drei Festlegungen um:

1. Der SSH-Tunnel laeuft **auf dem Host**, unabhaengig vom Container-Lebenszyklus.
   Kein Tunnel bedeutet kein Netz im Container.
2. DNS wird **ueber TCP** gefuehrt (Begruendung und Normbezug in Abschnitt 4).
3. Die Anwendung ist CPU-durchsatzkritisch und soll **als root** laufen.
   Das Design stellt das sicher, ohne die Schutzwirkung aufzugeben
   (Abschnitt 6).

---

## 1. Ziel

Ein reproduzierbar gebauter Container auf Basis von Ubuntu 26.04
("Resolute Raccoon"), in dem eine beliebige, rechenintensive Anwendung als root
laeuft und deren gesamter Netzwerkverkehr zwingend durch einen SOCKS5-Proxy
geht, der von einem SSH-Tunnel auf dem Host bereitgestellt wird.

Harte Anforderungen:

1. **Transparenz** - die Anwendung braucht keine Proxy-Konfiguration.
2. **Fail-closed** - kein Tunnel, kein Netz. Kein direkter Fallback.
3. **Default-Deny** - alles ausser dem Proxy-Pfad ist geblockt.
4. **Kein Performance-Eingriff** - die Sandbox darf den CPU-Durchsatz der
   Anwendung nicht messbar beeinflussen.
5. **Fallback** - Anwendungen, die einen Proxy explizit ansprechen wollen,
   finden ihn unter einer festen Adresse.

Ausserhalb des Zielbilds: GUI-Anwendungen, eingehende Verbindungen in den
Container, Docker Desktop unter Windows/macOS (dort gibt es keinen direkt
kontrollierbaren `DOCKER-USER`-Pfad).

---

## 2. Das bestimmende technische Problem

`ssh -D` implementiert einen SOCKS-Server, der **nur TCP** transportiert. Der
SOCKS5-Befehl `UDP ASSOCIATE` wird von OpenSSH nicht unterstuetzt. Daraus
folgt:

| Konsequenz | Bedeutung |
|---|---|
| Kein UDP durch den Tunnel | QUIC (HTTP/3), NTP, WireGuard, klassisches DNS-over-UDP funktionieren nicht. |
| Kein ICMP | `ping` und `traceroute` aus dem Container schlagen fehl. Gewollt, aber dokumentationspflichtig. |
| DNS braucht eine Sonderloesung | Siehe Abschnitt 4. |

Deshalb wird **iptables-REDIRECT + redsocks** verwendet und kein TUN-Ansatz:
ein TUN-Device nimmt auch UDP-Pakete an, die im Tunnel verloren gehen - die
Anwendung bekaeme Timeouts statt sauberer Fehler. Mit REDIRECT wird
ausschliesslich TCP umgelenkt; alles andere wird hart verworfen und
schlaegt sofort und eindeutig fehl.

---

## 3. Warum nicht einfach proxychains

Zur Vollstaendigkeit, weil es die naheliegendste Idee ist: `proxychains-ng`
haengt sich per `LD_PRELOAD` in `connect()` der libc. Das greift nicht bei
statisch gelinkten Programmen, nicht bei Sprachen mit eigener Syscall-Schicht
(Go), nicht bei `setuid`-Binaries und nicht bei Kindprozessen, die die
Umgebungsvariable verlieren. Es ist eine Konvention, keine Durchsetzung - und
damit fuer eine Sandbox ungeeignet.

---

## 4. DNS ueber TCP - ja, das gibt es, und ja, es ist die Loesung

**Kurzantwort: DNS over TCP ist kein Workaround, sondern Standard und seit
2016 verpflichtend.**

* DNS ueber TCP ist seit RFC 1035 (1987), Abschnitt 4.2.2, Teil der
  Spezifikation - urspruenglich vor allem fuer Zonentransfers und fuer
  Antworten, die nicht in ein UDP-Paket passen.
* **RFC 7766** (2016, "DNS Transport over TCP - Implementation Requirements")
  hebt das auf Pflichtniveau: alle allgemeinen DNS-Implementierungen MUESSEN
  sowohl UDP als auch TCP unterstuetzen; rekursive Server und Forwarder
  MUESSEN TCP unterstuetzen. Entscheidend fuer uns ist die Aussage zur
  Transportwahl: Stub- und rekursive Resolver DUERFEN wahlweise TCP oder UDP
  senden, und **TCP darf verwendet werden, ohne vorher UDP zu versuchen**.
  Was wir hier bauen, ist also ausdruecklich standardkonformes Verhalten und
  kein Trick.
* **RFC 9210** (2022, BCP 235, "DNS Transport over TCP - Operational
  Requirements") zieht die Betriebsseite nach: DNS ueber TCP zuzulassen ist
  Best Current Practice; RFC 1123 wird dahingehend aktualisiert, dass alle
  Resolver und rekursiven Server TCP- und UDP-Anfragen bedienen MUESSEN, und
  RFC 1536 wird um die Fehlvorstellung bereinigt, TCP sei nur fuer
  Zonentransfers da.
* Alle grossen oeffentlichen Resolver (Quad9, Cloudflare, Google) bedienen
  TCP/53.

**Nachteile, ehrlich benannt:** Jede Anfrage kostet einen TCP-Handshake, und
ueber einen SSH-Tunnel kommt dessen Latenz noch dazu. Ohne Gegenmassnahme
merkt man das bei vielen unterschiedlichen Namen deutlich. Deshalb:

* Ein **cachender** Resolver (unbound) im Pfad - wiederholte Lookups kosten
  dann gar keinen Netzverkehr mehr. Das ist bei einem tunnelbedingt langsamen
  Pfad kein Luxus, sondern der eigentliche Hebel.
* RFC 7766 empfiehlt ausdruecklich das Wiederverwenden offener
  TCP-Verbindungen; unbound tut das.

**Umsetzung:** unbound mit `tcp-upstream: yes` (die Option existiert laut
NLnet-Labs-Dokumentation genau fuer Tunnel-Szenarien) und
`forward-zone: name: "."` auf einen konfigurierbaren Upstream. Der so
erzeugte TCP-Strom wird vom REDIRECT eingefangen und laeuft damit automatisch
durch den Tunnel.

**Fallback, falls unbound ausfaellt oder unerwuenscht ist:** redsocks bringt
`dnstc` mit - einen Fake-DNS-Server, der jede UDP-Anfrage mit gesetztem
TC-Bit beantwortet. Die glibc wiederholt die Anfrage daraufhin ueber TCP
(dieses Verhalten ist der Default; nur die Resolver-Option `RES_IGNTC`
schaltet es ab). Kein Cache, aber ein Prozess weniger. Als
`DNS_MODE=unbound|dnstc|host` in `.env` waehlbar.

`DNS_MODE=host` leitet die Aufloesung stattdessen an den Resolver des Hosts -
schnell, aber dann sieht der lokale Resolver bzw. der Provider, welche Namen
die Sandbox aufloest. Das ist ein bewusster Bruch des Bedrohungsmodells und
darf nicht der Default sein.

---

## 5. Architektur

### 5.1 Grundentscheidung: Gateway-Sidecar

Da der Tunnel auf dem Host liegt, waere es naheliegend, auch redsocks und
unbound dort zu betreiben und den Container voellig unveraendert zu lassen
(Variante "alles auf dem Host", Abschnitt 5.5). Dagegen spricht ein
praktischer Punkt: `redsocks` ist in Ubuntu paketiert, in RHEL/Rocky aber
nicht ohne Weiteres verfuegbar. Ein Setup, das auf deinen Ubuntu-Arbeitsplaetzen
und auf Rocky-Hosts gleich funktionieren soll, sollte die Proxy-Schicht
deshalb **im Container** mitbringen, nicht auf dem Host voraussetzen.

Empfehlung daher: **zwei Container, ein gemeinsamer Network-Namespace.**

```yaml
services:
  gateway:            # redsocks + unbound + Regeln, CAP_NET_ADMIN
  app:
    network_mode: "service:gateway"   # teilt den Netz-Stack des Gateways
    cap_drop: [ALL]                   # root ja, Capabilities nein
```

`network_mode: "service:{name}"` ist Teil der Compose-Spezifikation
("Gives the service container access to the specified service only").

Das loest die Root-Frage sauber: Die Anwendung laeuft als root, aber ohne
`CAP_NET_ADMIN` - und ohne diese Capability kann auch root im Container keine
iptables-Regel anfassen. Die Regeln liegen im gemeinsamen Namespace, gesetzt
vom Gateway-Container, den die Anwendung nicht betreten kann.

### 5.2 Datenfluss

```
+-----------------------------+   +----------------------------------------+
|  Container "app"            |   |  Container "gateway"                   |
|  root, cap_drop: ALL        |   |  CAP_NET_ADMIN, unprivilegierte Dienste|
|                             |   |                                        |
|   [Anwendung]               |   |   [unbound]  127.0.0.1:53              |
|        |                    |   |      tcp-upstream: yes                 |
|        |                    |   |   [redsocks] 127.0.0.1:12345           |
+--------|--------------------+   +----------------------------------------+
         |                                        |
         +---------------+------------------------+
                         |   gemeinsamer Network-Namespace
                         v
        nat/OUTPUT -> SANDBOX_REDIR
          - UID von redsocks: RETURN (keine Schleife)
          - 127.0.0.0/8, eigenes Subnetz: RETURN
          - sonst TCP: REDIRECT --to-ports 12345
                         |
                         v
        [redsocks] liest Originalziel via SO_ORIGINAL_DST
                         |  SOCKS5 CONNECT
                         v
        filter/OUTPUT (Policy DROP)
          - einzige Ausnahme: UID redsocks -> ${GW_IP}:${SOCKS_PORT}
                         |
                         v
        Bridge br-sandbox  ---- Host: filter/INPUT -> SANDBOX_IN
                         |        nur Port ${SOCKS_PORT} erlaubt
                         v
        [ssh -D auf dem Host]  ----> externer SSH-Server ----> Internet

        Alles andere aus br-sandbox:
        FORWARD -> DOCKER-USER -> SANDBOX_EGRESS -> DROP
```

### 5.3 Drei Verteidigungslinien

| Linie | Ort | Wirkung |
|---|---|---|
| 1 | `filter/OUTPUT` im gemeinsamen Namespace, Policy `DROP` | Nur redsocks darf zum SOCKS-Port. Faellt redsocks aus, gibt es keinen Weg hinaus. |
| 2 | `filter/INPUT` auf dem Host, Kette `SANDBOX_IN` | Die Sandbox erreicht vom Host nur den SOCKS-Port - keine anderen Host-Dienste. |
| 3 | `DOCKER-USER` auf dem Host, Kette `SANDBOX_EGRESS` | Nichts aus dem Sandbox-Netz wird weitergeleitet. Haelt auch dann, wenn Linie 1 fehlt. |

**Wichtiges Detail zu Linie 2 und 3:** Beide Ketten matchen auf das
**Bridge-Interface** (`-i br-sandbox`), nicht nur auf das Quell-Subnetz. Ein
Prozess im Container koennte sich sonst - mit `CAP_NET_ADMIN`, das wir zwar
nicht vergeben, aber wir bauen hier eine Sandbox - eine IP ausserhalb des
Subnetzes geben und am `-s`-Match vorbeirutschen. Das Interface laesst sich von
innen nicht faelschen. Damit der Interface-Name stabil bleibt, wird er per
`com.docker.network.bridge.name` fest vergeben; ohne diese Option heisst die
Bridge `br-<hash>` und aendert sich beim Neuanlegen des Netzes.

Zusaetzlich wird `com.docker.network.bridge.enable_ip_masquerade: false`
gesetzt. Ohne Masquerading bekommen Pakete aus dem Sandbox-Netz gar kein SNAT
mehr - selbst ein Loch in den Filterregeln fuehrt dann nicht ins Internet.

**Wichtiges Detail zu Linie 2:** `DOCKER-USER` deckt nur **weitergeleiteten**
Verkehr ab. Pakete vom Container an den Host selbst (die Bridge-Gateway-IP)
laufen ueber `INPUT`, nicht ueber `FORWARD`. Ohne die `SANDBOX_IN`-Kette
erreicht die Sandbox jeden Dienst, der auf dem Host lauscht. Dieser Punkt
fehlt in den meisten Anleitungen im Netz.

### 5.4 Der SSH-Tunnel auf dem Host

* Eigene systemd-Unit (`host/sandbox-tunnel.service`), `Restart=always`,
  `RestartSec=5`, dazu `-N -o ExitOnForwardFailure=yes
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=yes`.
  `ExitOnForwardFailure=yes` ist hier wesentlich: ohne diese Option laeuft
  `ssh` weiter, obwohl der lokale Listener nicht zustande kam - der Tunnel
  waere dann scheinbar da und tatsaechlich tot.
* `StrictHostKeyChecking=yes` mit gepflegter `known_hosts`: ein SOCKS-Tunnel zu
  einem nicht verifizierten Host waere eine Einladung zum MITM und wuerde die
  gesamte Schutzwirkung aufheben.
* **Offener Punkt Binding:** Damit der Container den Tunnel erreicht, muss
  `ssh -D` auf einer fuer die Bridge erreichbaren Adresse lauschen. Drei
  Moeglichkeiten:
  1. `-D 0.0.0.0:1080` plus strikte `INPUT`-Regeln (nur `lo` und
     `br-sandbox` duerfen auf den Port). Einfach, Ordnungsunabhaengig,
     Sicherheit kommt aus der Firewall. **Vorschlag.**
  2. `-D ${GW_IP}:1080` - schmalstes Binding, aber die Unit haengt davon ab,
     dass das Docker-Netz schon existiert. Bootreihenfolge wird fragil.
  3. Ein Dummy-Interface mit fester IP auf dem Host, an das `ssh` bindet.
     Sauber und docker-unabhaengig, aber zusaetzlicher Host-Zustand.
* Der Container startet unabhaengig davon. Ist der Tunnel weg, scheitert
  redsocks beim Verbindungsaufbau und der Healthcheck des Gateways schlaegt an -
  die Anwendung bekommt Verbindungsfehler, nie aber einen direkten Weg.

### 5.5 Variante "alles auf dem Host" (dokumentiert, nicht Default)

Falls der Host ohnehin Ubuntu ist und kein zusaetzlicher Container gewuenscht
wird, kann die gesamte Proxy-Schicht auf den Host wandern. Der Container ist
dann voellig unveraendert - keine Capabilities, keine Zusatzpakete, kein
Entrypoint-Eingriff.

Technisch tragfaehig, weil `REDIRECT` laut `iptables-extensions(8)` nicht nur
in `OUTPUT`, sondern auch in **`PREROUTING`** gueltig ist: "This target is only
valid in the nat table, in the PREROUTING and OUTPUT chains". Und: "It
redirects the packet to the machine itself by changing the destination IP to
the primary address of the incoming interface". Fuer Pakete, die auf
`br-sandbox` ankommen, wird das Ziel also die Bridge-IP - redsocks muss dort
lauschen, nicht auf `127.0.0.1`.

```sh
iptables -t nat -A PREROUTING -i br-sandbox -d "${SUBNET}" -j RETURN
iptables -t nat -A PREROUTING -i br-sandbox -p tcp -j REDIRECT --to-ports 12345
```

Angenehmer Nebeneffekt: TCP erreicht `FORWARD` dann gar nicht mehr, weil es
vorher lokal zugestellt wird. `DOCKER-USER` wird zur reinen Rueckfallebene fuer
UDP, ICMP und alles Uebrige.

Preis: redsocks und unbound muessen auf dem Host installiert und per systemd
betrieben werden; auf Rocky ist redsocks nicht ohne Weiteres paketiert. Ausserdem
braucht unbound auf dem Host eine gezielte Regel, damit seine eigenen
Upstream-Anfragen im Tunnel landen - `-m owner --uid-owner` ist laut
`iptables-extensions(8)` nur in `OUTPUT` und `POSTROUTING` gueltig, was hier
genau passt:

```sh
iptables -t nat -A OUTPUT -m owner --uid-owner sandbox-dns -p tcp --dport 53 \
         -j REDIRECT --to-ports 12346
```

(Bei lokal erzeugten Paketen landet REDIRECT auf `127.0.0.1`, deshalb ein
zweiter redsocks-Listener auf der Loopback-Adresse.)

---

## 6. Root und CPU-Durchsatz

Das ist der Punkt, an dem ich deiner Annahme widersprechen muss, und zwar
aus zwei Richtungen.

### 6.1 Root macht eine Anwendung nicht schneller

Der Linux-Scheduler kennt keine Bevorzugung nach UID. Es gibt keinen
Codepfad, in dem UID 0 mehr CPU-Zeit bekommt als UID 1000. Was root
tatsaechlich kann und woher die Beobachtung stammt, sind **Capabilities und
Rlimits**, nicht der Scheduler:

| Beobachteter Effekt | Tatsaechliche Ursache | Gezielt gewaehrbar durch |
|---|---|---|
| Hoehere Prioritaet | negativer `nice`-Wert oder Echtzeit-Policy | `CAP_SYS_NICE` |
| Kein Swapping/Paging kritischer Puffer | `mlock()` ueber das Rlimit hinaus | `CAP_IPC_LOCK` bzw. `RLIMIT_MEMLOCK` |
| Mehr offene Dateien, mehr Threads | `RLIMIT_NOFILE`, `RLIMIT_NPROC` | `ulimits` |
| Zugriff auf Hugepages, MSRs, perf-Counter | eigene Rechte-/Sysctl-Pfade | Host-Konfiguration |
| Anwendung faellt nicht in einen langsamen Pfad zurueck | Programm versucht `sched_setscheduler()` und faengt den `EPERM` ab | `CAP_SYS_NICE` |

Der letzte Punkt ist erfahrungsgemaess der haeufigste: viele HPC- und
Laufzeitbibliotheken versuchen Prioritaet oder Pinning zu setzen und schalten
bei `EPERM` still auf ein konservativeres Verhalten um. Das sieht dann aus wie
"als root schneller", ist aber eine fehlende Capability.

### 6.2 In einem Container ist root ohnehin der Normalfall

Docker startet Container per Default als root - aber mit einem reduzierten
Capability-Set. Das Set ist im Docker-Quelltext definiert und enthaelt:
`CHOWN`, `DAC_OVERRIDE`, `FSETID`, `FOWNER`, `MKNOD`, `NET_RAW`, `SETGID`,
`SETUID`, `SETFCAP`, `SETPCAP`, `NET_BIND_SERVICE`, `SYS_CHROOT`, `KILL`,
`AUDIT_WRITE`.

Bemerkenswert ist, was **fehlt**: `NET_ADMIN`, `SYS_NICE`, `IPC_LOCK`,
`SYS_ADMIN`, `SYS_RESOURCE`. Daraus folgen zwei Dinge:

1. **Deine Anwendung kann als root laufen, ohne die Firewall zu gefaehrden** -
   ohne `CAP_NET_ADMIN` kann auch root keine iptables-Regel aendern. Der
   Zielkonflikt aus Revision 1 loest sich damit auf.
2. **Root allein bringt dir die erhofften Performance-Rechte gar nicht** -
   `CAP_SYS_NICE` und `CAP_IPC_LOCK` sind nicht dabei und muessen einzeln
   nachgereicht werden.

### 6.3 Was den CPU-Durchsatz im Container wirklich kostet

Reine Rechenlast laeuft im Container nativ - es gibt keine Instruktions-
Virtualisierung, nur Namespaces und cgroups. Messbare Effekte kommen aus
genau vier Ecken:

1. **CFS-Bandwidth-Throttling.** Das ist die mit Abstand haeufigste Ursache
   fuer unerwartet schlechten Durchsatz. Die Kernel-Dokumentation beschreibt
   den Mechanismus so: innerhalb jeder Periode bekommt eine Gruppe ein
   Kontingent an CPU-Mikrosekunden zugeteilt; ist es aufgebraucht, werden die
   Threads gedrosselt und koennen erst in der naechsten Periode wieder laufen.
   Bei vielen Threads ist das Kontingent oft vorzeitig weg und die Anwendung
   steht periodisch still.
   **Konsequenz fuer uns: kein `cpus:` und kein `cpu_quota` setzen.** Wer
   begrenzen will, nimmt `cpuset` (feste CPU-Liste) - das pinnt, ohne zu
   drosseln, und verbessert nebenbei die Cache- und NUMA-Lokalitaet.
2. **seccomp.** Docker filtert Syscalls per Default ueber ein seccomp-Profil.
   Fuer rechengebundene Lasten ist das bedeutungslos, fuer syscall-lastige
   Lasten messbar. `security_opt: ["seccomp=unconfined"]` schaltet es ab -
   das schwaecht die Isolation und gehoert nur hinein, wenn eine **Messung**
   den Gewinn zeigt. Nicht ungemessen setzen.
3. **Speicher- und NUMA-Platzierung.** `cpuset` plus passende
   `cpuset_mems`-Zuordnung auf dem Host, `shm_size` gross genug fuer
   Shared-Memory-Kommunikation, `ulimits: memlock` fuer gepinnte Seiten.
4. **Die Proxy-Schicht - aber nur fuer Netzverkehr.** redsocks ist ein
   Userspace-Relay; jedes uebertragene Byte kostet CPU. Fuer eine
   rechengebundene Anwendung mit wenig Netz-I/O ist das irrelevant. Fuer eine
   datenintensive Anwendung wird redsocks zum Flaschenhals.
   Gegenmassnahme: redsocks bietet `splice = true` - einen Datenpfad ueber
   `splice(2)`, der die Nutzdaten im Kernel haelt, statt sie durch den
   Userspace zu kopieren. Laut Konfigurationsbeispiel ist das auf modernen
   Kerneln ohnehin der Default. Zusaetzlich laeuft redsocks in einem
   **eigenen** Container und damit in einer eigenen cgroup - seine CPU-Zeit
   wird der Anwendung nicht angerechnet und stoert deren Messungen nicht.

### 6.4 Resultierende Compose-Einstellungen fuer den App-Container

```yaml
  app:
    network_mode: "service:gateway"
    cap_drop: [ALL]
    # cap_add: [SYS_NICE]        # nur, wenn die Anwendung Prioritaet/Pinning setzt
    init: true                    # sauberes PID 1 fuer Zombie-Reaping
    cpuset: "${APP_CPUSET:-}"     # Pinning statt Drosselung
    # cpus: NICHT setzen -> keine CFS-Drosselung
    shm_size: "${APP_SHM_SIZE:-1g}"
    ulimits:
      memlock: -1
      nofile: 1048576
    # security_opt: ["seccomp=unconfined"]   # nur nach Messung
```

Die auskommentierten Zeilen sind bewusst auskommentiert: jede davon tauscht
Isolation gegen Performance und gehoert nur aktiviert, wenn eine Messung den
Gewinn belegt. Der Testplan (Abschnitt 9) sieht dafuer einen Referenzlauf vor.

---

## 7. Dateien

```
.
|-- PLAN.md
|-- README.md
|-- docker-compose.yml
|-- Dockerfile                  # App-Container: Basis + Anwendung, sonst nichts
|-- .env.example                # (statt ".env", s. u.)
|-- .gitignore
|-- run.sh                      # Lifecycle: build / up / shell / test / down
|-- apply-rules.sh              # Host-Firewall (INPUT + DOCKER-USER)
|-- blocked-subnets.conf        # Ziel-Netze, die der Sandbox verboten sind
|-- gateway/
|   |-- Dockerfile              # redsocks + unbound + iptables
|   |-- entrypoint.sh
|   |-- firewall.sh             # Regeln im gemeinsamen Namespace
|   |-- healthcheck.sh
|   |-- resolv.conf             # wird in den App-Container gemountet
|   |-- redsocks.conf.tmpl
|   `-- unbound.conf.tmpl
|-- host/
|   |-- sandbox-tunnel.service  # systemd-Unit fuer ssh -D
|   `-- sandbox-tunnel.env
`-- tests/
    |-- leak-test.sh            # Nachweis, dass nichts vorbeilaeuft
    `-- perf-baseline.sh        # Durchsatz im Container vs. auf dem Host
```

Abweichungen von deiner urspruenglichen Liste:

1. **`Dockerfile` statt `dockerfile`** - `docker build` sucht per Default exakt
   nach `Dockerfile`; auf case-sensitiven Dateisystemen braeuchte die
   Kleinschreibung ein explizites `-f`.
2. **`.env.example` im Repo, `.env` in `.gitignore`** - die `.env` enthaelt
   Hostnamen, Benutzernamen und Schluesselpfade.
3. **`gateway/`, `host/`, `tests/`** - haelt das Wurzelverzeichnis
   uebersichtlich.

---

## 8. Umsetzung je Datei

### 8.1 `Dockerfile` (App-Container)

Bewusst minimal - hier laeuft die durchsatzkritische Anwendung, also kommt
nichts hinein, was sie stoeren koennte:

* `ARG BASE_IMAGE=ubuntu:26.04`, optional per Digest gepinnt.
* `ARG APP_PACKAGES=""` fuer apt-Pakete der Anwendung; optional
  `COPY app/ /opt/app` plus Aufruf von `/opt/app/install.sh`, falls vorhanden.
  Damit ist "beliebige Anwendung" ohne Aenderung am Dockerfile moeglich.
* **Kein** ssh, **kein** redsocks, **kein** unbound, **kein** iptables,
  **kein** Entrypoint-Eingriff ins Netz. Die Anwendung startet direkt als root.
* `/etc/resolv.conf` kommt per Bind-Mount aus `gateway/resolv.conf`
  (Inhalt: `nameserver 127.0.0.1`, `options timeout:2 attempts:2`).
  Begruendung siehe 8.5.

### 8.2 `gateway/Dockerfile`

`redsocks`, `unbound`, `iptables`, `iproute2`, `curl`, `netcat-openbsd`,
`gettext-base` (fuer `envsubst`). Alle in Ubuntu 26.04 vorhanden
(`redsocks` aus universe, `unbound` aus main). Zwei dedizierte
unprivilegierte Benutzer:

* `redsocks` (Default-UID 10002) - der einzige UID, dessen Pakete die
  Firewall passieren duerfen.
* `unbound` (Default-UID 10003) - dessen Upstream-Anfragen normal in den
  REDIRECT laufen.

### 8.3 `gateway/firewall.sh`

```sh
# --- NAT: TCP transparent in redsocks umlenken ---
iptables -t nat -N SANDBOX_REDIR
iptables -t nat -A SANDBOX_REDIR -m owner --uid-owner "${REDSOCKS_UID}" -j RETURN
iptables -t nat -A SANDBOX_REDIR -d 127.0.0.0/8          -j RETURN
iptables -t nat -A SANDBOX_REDIR -d "${SANDBOX_SUBNET}"  -j RETURN
iptables -t nat -A SANDBOX_REDIR -p tcp -j REDIRECT --to-ports "${REDSOCKS_PORT}"
iptables -t nat -A OUTPUT -p tcp -j SANDBOX_REDIR

# --- FILTER: alles zu, ausser Loopback und dem Weg zum SOCKS-Port ---
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -d "${GW_IP}" --dport "${SOCKS_PORT}" \
                   -m owner --uid-owner "${REDSOCKS_UID}" -j ACCEPT

# --- IPv6 vollstaendig zu ---
ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT; ip6tables -A OUTPUT -o lo -j ACCEPT
```

Details, die leicht uebersehen werden:

* Der `RETURN` fuer `REDSOCKS_UID` in der NAT-Kette verhindert die Schleife
  "redsocks -> REDIRECT -> redsocks".
* `-m owner` ist laut `iptables-extensions(8)` nur in `OUTPUT` und
  `POSTROUTING` gueltig - genau dort wird es eingesetzt. Fuer weitergeleitete
  Pakete gibt es keinen Socket-Owner, deshalb funktioniert derselbe Trick auf
  dem Host nicht und dort wird IP- und interface-basiert gefiltert.
* Nach dem REDIRECT hat das Paket das Ziel `127.0.0.1` und verlaesst den
  Stack ueber `lo` - `-A OUTPUT -o lo -j ACCEPT` deckt es also ab.
* Die Regeln liegen im **gemeinsamen** Namespace und gelten damit auch fuer
  den App-Container, obwohl der sie nicht sehen oder aendern kann.

### 8.4 `apply-rules.sh` (Host, root)

Zwei Ketten, beide interface-basiert:

```sh
# Linie 2: was die Sandbox vom Host selbst erreichen darf
iptables -N SANDBOX_IN 2>/dev/null || iptables -F SANDBOX_IN
iptables -A SANDBOX_IN -p tcp --dport "${SOCKS_PORT}" -j ACCEPT
iptables -A SANDBOX_IN -j DROP
iptables -C INPUT -i "${BRIDGE}" -j SANDBOX_IN 2>/dev/null \
  || iptables -I INPUT 1 -i "${BRIDGE}" -j SANDBOX_IN

# Linie 3: was weitergeleitet werden darf - naemlich nichts
iptables -N SANDBOX_EGRESS 2>/dev/null || iptables -F SANDBOX_EGRESS
iptables -A SANDBOX_EGRESS -d "${SANDBOX_SUBNET}" -j RETURN
# ... je Zeile aus blocked-subnets.conf ein DROP ...
iptables -A SANDBOX_EGRESS -j DROP
iptables -C DOCKER-USER -i "${BRIDGE}" -j SANDBOX_EGRESS 2>/dev/null \
  || iptables -I DOCKER-USER 1 -i "${BRIDGE}" -j SANDBOX_EGRESS
```

`DOCKER-USER` ist laut Docker-Dokumentation genau dafuer da: "A placeholder
for user-defined rules that will be processed before rules in the
`DOCKER-FORWARD` and `DOCKER` chains." An `FORWARD` angehaengte Regeln laufen
zu spaet.

Skript-Eigenschaften:

* Schalter: `--apply` (Default), `--remove`, `--status`, `--dry-run`.
* Idempotent: Ketten werden geleert und neu gefuellt, der Sprung nur bei
  Bedarf eingefuegt.
* Keine Persistenz ueber einen Reboot - `run.sh` ruft das Skript bei jedem
  Start auf; im README wird alternativ eine systemd-Unit beschrieben.
* Hinweis auf `ufw`/`firewalld`: Docker greift im NAT-Pfad vor `INPUT`/`OUTPUT`
  ein und umgeht `ufw`-Regeln; das gehoert ins README, damit niemand sich auf
  `ufw status` verlaesst.

### 8.5 DNS-Verdrahtung

`unbound` lauscht im Gateway auf `127.0.0.1:53`, der App-Container erreicht
das ueber den gemeinsamen Namespace. Der Weg ueber Dockers eingebetteten
Resolver (`127.0.0.11`) wird umgangen, indem `/etc/resolv.conf` im
App-Container per Bind-Mount fest auf `nameserver 127.0.0.1` gesetzt wird.

**Zu pruefen im PoC:** ob Compose `dns:` zusammen mit
`network_mode: "service:..."` ueberhaupt akzeptiert. Der Bind-Mount ist der
deterministische Weg und deshalb der Vorschlag; `dns:` waere nur die
elegantere Variante, falls sie funktioniert.

### 8.6 `.env.example`

```
# --- Basis ---
BASE_IMAGE=ubuntu:26.04
APP_CMD=/bin/bash
APP_PACKAGES=

# --- Netz ---
SANDBOX_SUBNET=172.28.77.0/24
GW_IP=172.28.77.1
BRIDGE=br-sandbox
SOCKS_PORT=1080
REDSOCKS_PORT=12345
REDSOCKS_UID=10002

# --- DNS ---
DNS_MODE=unbound          # unbound | dnstc | host
DNS_UPSTREAM=9.9.9.9

# --- Performance ---
APP_CPUSET=
APP_SHM_SIZE=1g
APP_CAP_SYS_NICE=0
APP_SECCOMP_UNCONFINED=0

# --- Host ---
APPLY_HOST_RULES=1
EGRESS_SELFTEST=1
```

### 8.7 `run.sh`

Unterbefehle `build`, `up`, `down`, `shell`, `status`, `test`, `logs`.
Bei `up`: Vorbedingungen pruefen (Docker, Compose, `.env`, Tunnel erreichbar)
-> `apply-rules.sh --apply` -> `docker compose up -d` -> auf `healthy` warten
-> bei `EGRESS_SELFTEST=1` den Leak-Test starten.

Wichtig: `run.sh` prueft **vor** dem Start, ob der Tunnel auf dem Host laeuft,
und meldet sonst klar, dass der Container ohne Netz hochkommt.

### 8.8 `README.md`

Zweck und Bedrohungsmodell / Voraussetzungen (inkl. Tunnel-Unit) /
Schnellstart / Konfigurationsreferenz / Betrieb / bekannte Einschraenkungen
(kein UDP, kein ICMP, kein QUIC, DNS-Latenz) / Performance-Hinweise
(Abschnitt 6) / Troubleshooting / Deinstallation.

---

## 9. Testplan

### 9.1 Leak-Tests (`tests/leak-test.sh`)

| # | Test | Erwartung |
|---|---|---|
| 1 | `curl -s https://ifconfig.co` im Container | liefert die IP des SSH-Servers, nicht die des Hosts |
| 2 | `getent hosts example.com` | loest auf |
| 3 | `dig +notcp @8.8.8.8 example.com` | Timeout (kein UDP-DNS nach draussen) |
| 4 | `dig +tcp @${DNS_UPSTREAM} example.com` | antwortet (DNS ueber TCP funktioniert) |
| 5 | `ping -c1 -W2 1.1.1.1` | schlaegt fehl |
| 6 | `curl -6 -m5 https://ipv6.google.com` | schlaegt fehl |
| 7 | `nc -z -w2 ${GW_IP} 22` | schlaegt fehl (nur SOCKS-Port erlaubt) |
| 8 | Tunnel-Unit auf dem Host stoppen, dann `curl` | schlaegt fehl, geht **nicht** direkt hinaus |
| 9 | Regeln im gemeinsamen Namespace leeren (Wegwerf-Instanz mit NET_ADMIN), dann `curl` | schlaegt trotzdem fehl - Nachweis fuer Linie 2 und 3 |
| 10 | Container-IP von innen auf eine Adresse ausserhalb des Subnetzes aendern (Wegwerf-Instanz mit NET_ADMIN), dann `curl` | schlaegt fehl - Nachweis fuer das Interface-Matching |

Tests 9 und 10 laufen bewusst in einer Wegwerf-Instanz mit `CAP_NET_ADMIN`,
nicht in der produktiven.

### 9.2 Performance-Referenz (`tests/perf-baseline.sh`)

Ziel: belegen, dass die Sandbox den CPU-Durchsatz nicht kostet, statt es zu
behaupten.

1. Referenzlauf der Anwendung (oder eines Stellvertreters wie `stress-ng
   --cpu N --metrics-brief` bzw. eines echten Benchmarks) **auf dem Host**.
2. Derselbe Lauf **im App-Container**, Default-Einstellungen.
3. Derselbe Lauf mit `cpuset`-Pinning.
4. Optional: mit `seccomp=unconfined`, mit `cap_add: SYS_NICE`.
5. Gegenprobe mit gesetztem `cpus:`-Limit, um die CFS-Drosselung sichtbar zu
   machen - der Unterschied ist das eigentliche Argument gegen diese Option.

Ergebnis gehoert als Tabelle ins README, damit spaetere Aenderungen sich daran
messen lassen.

---

## 10. Leak-Analyse

| Bypass-Vektor | Gegenmassnahme | Restrisiko |
|---|---|---|
| Direkte TCP-Verbindung an redsocks vorbei | `nat/OUTPUT` faengt alles TCP; `filter/OUTPUT` Policy DROP als zweite Linie | gering |
| UDP (QUIC, DNS, NTP) | Policy DROP - wird verworfen, nicht halb transportiert | gering; Anwendungen muessen TCP koennen |
| Dockers eingebetteter Resolver `127.0.0.11` | `/etc/resolv.conf` per Bind-Mount fest auf `127.0.0.1` | gering, **im PoC zu verifizieren** |
| IPv6 | kein IPv6 im Docker-Netz, `ip6tables` DROP | gering |
| Anwendung (als root) raeumt die Firewall ab | `cap_drop: ALL` im App-Container - ohne `CAP_NET_ADMIN` geht das nicht | gering |
| Anwendung aendert ihre IP und umgeht das `-s`-Match | Host-Regeln matchen auf `-i ${BRIDGE}` | gering |
| Zugriff auf Host-Dienste ueber die Gateway-IP | Kette `SANDBOX_IN` in `INPUT` | gering |
| Tunnel bricht weg, Fallback auf Direktverbindung | fail-closed by design; kein direkter Weg existiert | gering |
| SOCKS-Port auf `0.0.0.0` erreichbar fuer Dritte | `INPUT`-Regeln beschraenken auf `lo` und `${BRIDGE}` | gering, aber Bindungs-Entscheidung offen (5.4) |
| Container-Escape / Kernel-Exploit | ausserhalb des Modells | nicht adressiert |

---

## 11. Meilensteine

| Meilenstein | Inhalt | Ergebnis |
|---|---|---|
| **M1** | Tunnel-Unit auf dem Host, Gateway-Container mit redsocks, manueller Test | Traffic laeuft transparent durch den Tunnel |
| **M2** | DNS ueber TCP (unbound), resolv.conf-Verdrahtung, Fail-closed-Verhalten | Sandbox ist von innen dicht und nutzbar |
| **M3** | `apply-rules.sh`, `blocked-subnets.conf`, `SANDBOX_IN` + `SANDBOX_EGRESS` | zweite und dritte Verteidigungslinie stehen |
| **M4** | App-Container, `network_mode: service:`, `cap_drop: ALL`, root-Betrieb | Anwendung laeuft als root, Firewall bleibt unantastbar |
| **M5** | `run.sh`, Healthcheck, `tests/leak-test.sh` | reproduzierbarer Betrieb, Dichtheit nachgewiesen |
| **M6** | `tests/perf-baseline.sh`, Messtabelle | Durchsatz belegt statt behauptet |
| **M7** | `README.md`, `.env.example`, `.gitignore` | uebergabefaehig |

---

## 12. Konventionen fuer die Skripte

Alle Skripte folgen deinen Skript-Konventionen:

* Header mit Name, Beschreibung/Zweck, Programmablaufplan (bei den laengeren
  Skripten), Usage-Hinweis, `Version: 1.0.0 (JJJJ-MM-TT)` nach SemVer.
  Kein Author-Feld.
* `-h`/`--help` mit vollstaendiger Parameterliste inklusive der jeweils
  zugehoerigen Umgebungsvariable.
* `-s`/`--silent` und `-v`/`--verbose` fuer `run.sh` und `apply-rules.sh`.
  Silent gewinnt, wenn beides gesetzt ist.
* Jeder Parameter auch per exportierter Umgebungsvariable mit Praefix
  `SANDBOX_`; Praezedenz: Standardwert < `.env` < Umgebung < CLI.
* Ausschliesslich ASCII, Kommentare und Ausgaben auf Englisch.
* Variablen durchgaengig als `"${var}"`.
* Aussagekraeftige Fehlermeldungen nach STDERR, kein pauschales Verwerfen von
  STDERR, Exit 2 bei Aufruffehlern.

**Offener Punkt Logging:** Die Konventionen sehen `logger`/syslog im
nicht-interaktiven Betrieb vor. Ich implementiere das nicht ungefragt.
Vorschlag: zunaechst reine STDOUT/STDERR-Ausgabe, Logging als To-do markiert -
sag mir, wie du es haben willst (Facility, Loglevel, Format).

---

## 13. Offene Punkte

1. **Binding des SSH-Tunnels** (Abschnitt 5.4): `0.0.0.0` plus Firewall
   (Vorschlag), an die Bridge-IP, oder an ein Dummy-Interface?
2. **Zielanwendung:** Welche ist es konkret? Davon haengt ab, ob
   `APP_PACKAGES` reicht oder ein `app/install.sh`-Hook noetig ist - und ob
   sie tatsaechlich `CAP_SYS_NICE` braucht.
3. **Netz-Bedarf der Anwendung:** Wenig Netz-I/O (dann ist redsocks
   irrelevant) oder datenintensiv (dann wird redsocks zum Flaschenhals und
   wir sollten frueh messen)?
4. **DNS-Upstream:** Welcher Resolver soll hinter dem Tunnel angesprochen
   werden? `9.9.9.9` ist eine Setzung, keine Empfehlung.
5. **Persistenz der Host-Regeln:** Reicht der Aufruf durch `run.sh`, oder soll
   eine systemd-Unit mitgeliefert werden?
6. **Konfigurationsdatei-Schema:** Deine Konventionen sehen die
   organisationsbasierte Suche (`/etc/org.conf`, `/etc/${ORGANIZATION}/...`)
   vor. Fuer ein Repo-lokales Projekt wirkt `.env` passender. Soll
   `apply-rules.sh` das Org-Schema zusaetzlich unterstuetzen?
7. **Zielplattform des Hosts:** Ubuntu, Rocky oder beides? Bei "nur Ubuntu"
   waere die Variante aus 5.5 ("alles auf dem Host") die schlankere Loesung,
   weil der App-Container dann voellig unangetastet bleibt.

---

## 14. Verifizierte Grundlagen

Gegen Primaerquellen geprueft, nicht aus dem Gedaechtnis angenommen:

* `ubuntu:26.04` existiert als offizieller Docker-Tag (identischer Digest wie
  `resolute-*`), abgefragt ueber die Docker-Hub-API.
* `redsocks` (universe), `unbound` (main), `autossh` (universe),
  `openssh-client` (main) und `iptables` sind in Ubuntu 26.04 "resolute"
  paketiert.
* redsocks-Optionen inkl. `splice` ("Enable or disable faster data pump based
  on splice(2) syscall. Default value depends on your kernel version, true for
  2.6.27.13+") aus `redsocks.conf.example`; die Implementierung in
  `redsocks.c` nutzt `splice()` mit `SPLICE_F_MOVE`.
* `dnstc` beantwortet UDP-Anfragen mit gesetztem TC-Bit und erzwingt so den
  TCP-Retry (redsocks-README).
* `REDIRECT` ist "only valid in the nat table, in the PREROUTING and OUTPUT
  chains" und setzt das Ziel auf "the primary address of the incoming
  interface" (`iptables-extensions(8)`).
* `-m owner` ist "only valid in the OUTPUT and POSTROUTING chains. Forwarded
  packets do not have any socket associated with them."
  (`iptables-extensions(8)`).
* `DOCKER-USER` wird vor `DOCKER-FORWARD`/`DOCKER` ausgewertet; an `FORWARD`
  angehaengte Regeln laufen zu spaet (Docker-Dokumentation).
* Dockers Default-Capability-Set enthaelt `NET_ADMIN`, `SYS_NICE`, `IPC_LOCK`
  und `SYS_ADMIN` **nicht** (Docker-Quelltext `oci/caps/defaults.go`).
* CFS-Bandwidth-Throttling: "Once all quota has been assigned any additional
  requests for quota will result in those threads being throttled. Throttled
  threads will not be able to run again until the next period when the quota
  is replenished." (Kernel-Dokumentation `sched-bwc.rst`).
* `com.docker.network.bridge.name` ("Interface name to use when creating the
  Linux bridge") und `com.docker.network.bridge.enable_ip_masquerade` sind
  dokumentierte Treiberoptionen.
* `network_mode: "service:{name}"`, `cpuset`, `cpus`, `ulimits`, `shm_size`
  und `init` sind Bestandteil der Compose-Spezifikation.
* RFC 7766 macht TCP-Unterstuetzung fuer DNS verpflichtend und erlaubt
  ausdruecklich, TCP ohne vorherigen UDP-Versuch zu verwenden; RFC 9210
  (BCP 235) macht das Zulassen von DNS ueber TCP zur Best Current Practice.
* Die glibc wiederholt eine Anfrage bei gesetztem TC-Bit ueber TCP; nur
  `RES_IGNTC` schaltet das ab (`resolver(3)`).

**Nicht abschliessend verifiziert** (Doku aus dieser Umgebung nicht
erreichbar, im PoC gegenzupruefen):

* die exakte Semantik von unbounds `tcp-upstream: yes` - laut
  NLnet-Labs-Dokumentation fuehrt sie Upstream-Anfragen ausschliesslich ueber
  TCP, was genau unserem Szenario entspricht. Erster Pruefpunkt in M2.
* ob Compose `dns:` zusammen mit `network_mode: "service:..."` akzeptiert.
  Der Bind-Mount von `/etc/resolv.conf` ist deshalb der Vorschlag.
* ob `redsocks` auf Rocky Linux paketiert ist. Falls nein, ist das ein
  weiteres Argument fuer die Sidecar-Variante statt "alles auf dem Host".

### Quellen

- [Docker: Docker with iptables](https://docs.docker.com/engine/network/firewall-iptables/)
- [Docker: Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Docker: Bridge network driver options](https://docs.docker.com/engine/network/drivers/bridge/)
- [Docker: Networking overview (embedded DNS, --dns)](https://docs.docker.com/engine/network/)
- [moby/moby: oci/caps/defaults.go](https://github.com/moby/moby/blob/master/oci/caps/defaults.go)
- [Compose Specification](https://github.com/compose-spec/compose-spec/blob/main/spec.md)
- [redsocks (darkk/redsocks)](https://github.com/darkk/redsocks)
- [Unbound: unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [iptables-extensions(8)](https://manpages.ubuntu.com/manpages/noble/man8/iptables-extensions.8.html)
- [Linux kernel: CFS Bandwidth Control](https://www.kernel.org/doc/html/latest/scheduler/sched-bwc.html)
- [RFC 7766: DNS Transport over TCP - Implementation Requirements](https://www.rfc-editor.org/info/rfc7766/)
- [RFC 9210: DNS Transport over TCP - Operational Requirements (BCP 235)](https://www.rfc-editor.org/info/rfc9210/)
- [resolver(3)](https://manpages.ubuntu.com/manpages/noble/man3/resolver.3.html)
- [openssh-unix-dev: SOCKS5 and UDP](https://openssh-unix-dev.mindrot.narkive.com/CtaC5QcY/socks5-and-udp)
- [Docker Hub: ubuntu (official image)](https://hub.docker.com/_/ubuntu)
