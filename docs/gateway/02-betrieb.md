---
short: Betrieb
description: "Einbauen als Caddy-Distribution oder hinter nginx, beobachten und einschalten, aktualisieren, die Agent-API, Schalter und Regeln einstellen, den Server-Check einrichten, was bei einem Ausfall passiert, der Weg zurück in einer Minute, welche Daten wo bleiben, Befehle und bekannte Grenzen."
---

# Schild Gateway betreiben

**Status:** Alpha · Stand 21.11.2026 · technische Quelle: [gateway/README.md](../../gateway/README.md)

**Kurz:**

- Wie du Schild installierst, steht unter [Installieren](00-installieren.md). Diese Seite beginnt danach.
- Schild ist eine Caddy-Distribution: Caddy mit eingebautem WAF-Modul. Entweder wechselst du von deinem Caddy darauf, dann ist Schild selbst der Webserver, mit deinem Caddyfile und deinen Zertifikaten. Oder es läuft hinter deinem Webserver (nginx, Apache) oder Load Balancer.
- Jede Regelquelle, jedes Szenario und jedes Limit hat seinen eigenen Schalter. Ab Werk sperren das Core Rule Set, deine eigenen Regeln und vier der fünf Szenarien (nach 14 Tagen Lernzeit). Alles andere zählt nur mit.
- Hinter einem Webserver läuft deine Website bei einem Ausfall von Schild über den Webserver weiter. Nutzt du Schild als Caddy-Distribution, ist sie nicht erreichbar, bis Schild oder dein bisheriger Caddy wieder läuft. Der Weg zurück dauert in beiden Fällen eine Minute.
- Aus deinem Traffic verlässt nichts den Server. Das Gateway schickt nichts an Labs oder Relays.

## Zwei Arten, Schild einzubauen

| | Als Caddy-Distribution | Hinter deinem Webserver |
| --- | --- | --- |
| Aufbau | Internet → Schild mit deinem Caddyfile → Anwendung | Internet → nginx, Apache oder Load Balancer (TLS) → Schild → Anwendung |
| Zertifikate | macht Schild wie Caddy (ACME). Es startet mit einer Kopie von Caddys Zertifikaten, es wird nichts neu ausgestellt | macht dein Webserver |
| Ab wann Schild Traffic sieht | ab dem Wechsel, den ganzen | sobald dein Webserver an Schild weitergibt |
| Wenn Schild ausfällt | Websites nicht erreichbar, bis Schild oder Caddy wieder läuft | mit unserer [nginx-Vorlage](../../gateway/deploy/nginx-front.conf) schickt nginx direkt an die Anwendung, sonst antwortet dein Webserver mit 502 |
| Gut für | Server und Container-Setups mit Caddy, der Standardweg | bestehende Server mit nginx, Apache oder einem Load Balancer |

**Als Caddy-Distribution** lädt Schild dein Caddyfile und hört auf denselben Ports. Oben in die Datei kommt einmal das Snippet `(schild)`, in jede Website mit Backend die Zeile `import schild`. `schild init -caddyfile` und `schild ingress validate` nennen dir die Websites, in denen sie fehlt, und Schild startet nicht, solange eine Website mit Backend ohne Schild bleibt. Dein Caddyfile schreibt Schild nie selbst um. Die Zertifikate kopierst du vor dem Wechsel aus Caddys Speicher nach `/var/lib/schild/caddy`. Caddys eigener Speicher bleibt unverändert, damit der Weg zurück jederzeit geht. Die Schritte stehen unter [Du nutzt Caddy: Schild als Caddy-Distribution](00-installieren.md#du-nutzt-caddy-schild-als-caddy-distribution).

**Hinter deinem Webserver** leitet nginx, Apache oder ein Caddy, den du behalten willst, an Schild (Port 8080) weiter, Schild an deine Anwendung. Die kurzen Konfigurationen stehen unter [Traffic über Schild leiten](00-installieren.md#traffic-über-schild-leiten). Vollständige Vorlagen, die bei einem Ausfall von Schild direkt an die Anwendung weiterreichen, liegen im Repository: [nginx-front.conf](../../gateway/deploy/nginx-front.conf) und [Caddyfile.front](../../gateway/deploy/Caddyfile.front). `schild front` ist ein kleiner mitgelieferter Front-Proxy, falls du keinen hast.

### Echte Adresse der Besucher:innen

Steht etwas vor Schild, ein Webserver, ein Load Balancer oder Cloudflare, sieht Schild zuerst nur dessen Adresse. Die echte Adresse steht im Header `X-Forwarded-For`. Schild glaubt diesem Header nur, wenn die Anfrage von einer Adresse unter `ingress.trusted_proxies` kommt. Ab Werk sind das `127.0.0.1` und `::1`, also ein Webserver auf demselben Server ohne Docker.

Stimmt die Liste nicht, zählen alle Besucher:innen als eine Adresse: die deines Proxys. Statistiken zeigen dann nur diese eine Adresse, und Szenarien sperren niemanden, weil Schild private Adressen nie sperrt. Du merkst es an zwei Stellen: Unter „Zugriffe“ stehen fast alle Anfragen mit derselben Adresse, und unter „Einstellungen › Allgemein“ steht der Hinweis „Schild sieht nur die Adresse deines Proxys“.

| Was vor Schild steht | Was du einträgst |
| --- | --- |
| nginx oder Apache auf demselben Server, Schild ohne Docker | nichts, das ist der Standard |
| nginx oder Apache auf dem Server, Schild im Docker-Container | die Docker-Netze: `["127.0.0.1/32", "::1/128", "172.16.0.0/12", "192.168.0.0/16"]`, so steht es schon in der `schild.yaml` des Quickstarts. Veröffentliche Port 8080 dann nur auf `127.0.0.1` |
| ein Load Balancer oder Proxy auf einem anderen Rechner | dessen Adresse oder sein privates Netz, etwa `["10.0.1.0/24"]` |
| Cloudflare | zusätzlich die Adressbereiche von Cloudflare (<https://www.cloudflare.com/ips/>), und nginx hängt die Adresse an, statt sie zu ersetzen: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` |

```yaml
ingress:
  trusted_proxies: ["127.0.0.1/32", "::1/128", "172.16.0.0/12", "192.168.0.0/16"]
```

Trag nie ein ganzes Netz wie `0.0.0.0/0` ein: Dann könnte jede Anfrage eine beliebige Adresse behaupten, auch die eines Unbeteiligten, der dann gesperrt würde. Schild ignoriert so eine Liste und meldet das im Dashboard. Schild liest `X-Forwarded-For` von rechts: Was ein Client selbst in den Header schreibt, steht links und zählt nicht.

Läuft Schild als Caddy-Distribution hinter Cloudflare oder einem Load Balancer, braucht auch dein Caddyfile die Bereiche, damit deine Anwendung die echte Adresse bekommt: in den globalen Optionen `servers { trusted_proxies static … }` mit denselben Bereichen. `schild ingress validate` erinnert dich daran.

## Konfiguration und Dashboard

### Konfiguration ändern

Schild liest `schild.yaml` beim Start. Nach einer Änderung an der Datei startest du Schild neu (`sudo systemctl restart schild` oder `docker compose restart`). `schild preflight -config /etc/schild/schild.yaml` prüft die Datei vorher, ohne etwas zu starten. Was du im Dashboard einstellst, gilt sofort und braucht keinen Neustart. Eigene Regeln lädt `schild rules sync local` ohne Neustart neu, ein geändertes Caddyfile lädt `schild ingress reload`.

### Caddyfile ändern

Als Caddy-Distribution lädt Schild ein geändertes Caddyfile ohne Neustart:

```bash
schild ingress validate
schild ingress reload
```

Mit Docker Compose stellst du `docker compose exec schild` davor. Neue Websites, Backends, Header und TLS-Einstellungen gelten sofort. Laufende Anfragen enden mit dem Caddyfile, mit dem sie begonnen haben. Sperren, Zähler und der Lernstand bleiben.

Lehnt Schild das neue Caddyfile ab, läuft das alte weiter, und der Befehl nennt den Grund. Er prüft dasselbe wie ein Start. Drei Änderungen lehnt er außerdem ab:

- **Andere Ports oder Adressen** und ein anderer Speicher für Zertifikate. Dafür startest du Schild neu.
- **Eine Website mit Zugriffsschutz oder Wartungsmodus**, die danach ohne den Schutz erreichbar wäre. Das passiert, wenn der Block fehlt, ein anderer Host vorne steht oder ein Host in einen anderen Block wandert. Beende vorher den Schutz oder lass den Block, wie er ist.

Das solltest du wissen:

- Ein Reload dauert mindestens eine halbe Sekunde. So lange wartet Schild, bis das alte Caddyfile die Verbindungen gelesen hat, die es schon angenommen hatte.
- Ein Reload beendet offene WebSockets. Mit `stream_close_delay` in `reverse_proxy` laufen sie noch so lange weiter, wie du dort angibst.
- Im [Cluster](03-cluster.md#das-caddyfile-im-cluster-ändern) haben laufende Anfragen nach einem Reload noch `cluster.drain.grace_s` Zeit, in der Vorgabe 30 Sekunden. Was dann noch läuft, etwa ein großer Download, bricht ab. Ein `grace_period` im Caddyfile gilt stattdessen, auch ohne Cluster.
- `schild ingress reload -force` lädt auch ein unverändertes Caddyfile. Das brauchst du nach dem Tausch einer Zertifikats-, Schlüssel- oder Token-Datei, die das Caddyfile nennt.
- Schild liest bei einem Reload nur das Caddyfile neu, nicht `schild.yaml`.
- Bindest du das Caddyfile als einzelne Datei in einen Container ein, sieht der Container manche Änderung nicht. Viele Editoren schreiben eine neue Datei und benennen sie um. Binde deshalb den Ordner ein, wenn du ohne Neustart ändern willst.
- Schild führt für 32 Websites eigene Zahlen. Eine entfernte Website behält ihren Platz bis zum nächsten Start. Sind alle Plätze vergeben, zählt eine neue Website bis dahin unter „Weitere Websites“.

### Zertifikate über Hetzner DNS

Let's Encrypt prüft normalerweise über Port 80 oder 443, ob dir eine Domain gehört. Für ein Wildcard-Zertifikat wie `*.example.org` und für Namen, die von außen nicht erreichbar sind, geht das nur über einen DNS-Eintrag. Liegt die Zone bei Hetzner (Hetzner Console, Cloud-API), setzt Schild diesen Eintrag selbst und löscht ihn danach wieder. Das Modul ist eingebaut und tut nichts, solange es nicht im Caddyfile steht.

1. **Eigenes Projekt:** Leg in der Hetzner Console ein Projekt nur dafür an. Ein API-Token gilt für das ganze Projekt. Liegen dort auch Server, reicht das Token auch für sie.
2. **Eigene Zone:** Leg in diesem Projekt eine Zone nur für die Prüfungen an, zum Beispiel `acme.example.net`. In der Zone deiner Website verweist ein CNAME darauf. Die Website-Zone muss dann nicht bei Hetzner liegen:

   ```text
   _acme-challenge.example.org.  CNAME  _acme-challenge.acme.example.net.
   ```

3. **Token:** Erstell im Projekt ein API-Token mit Lesen und Schreiben. Leg es in eine Datei, die nur der Benutzer `schild` lesen kann:

   ```bash
   sudo install -o schild -g schild -m 0400 /dev/null /etc/schild/hetzner.token
   sudo nano /etc/schild/hetzner.token
   ```

4. **Caddyfile:**

   ```caddyfile
   *.example.org {
   	tls {
   		dns hetzner {file./etc/schild/hetzner.token}
   		dns_challenge_override_domain _acme-challenge.acme.example.net
   		propagation_delay 30s
   	}
   	import schild
   	reverse_proxy 127.0.0.1:3000
   }
   ```

5. **Prüfen:** `sudo -u schild schild ingress validate` lehnt ein fehlendes, leeres oder nicht lesbares Token ab. Ob Hetzner es annimmt, zeigt erst die erste Ausstellung.

Liegt die Zone deiner Website selbst in dem Projekt, lässt du den CNAME und die Zeile `dns_challenge_override_domain` weg. Wer das Token hat, kann dann aber alle Einträge dieser Zone ändern. Auch mit der eigenen Zone kann jemand mit dem Token Zertifikate für die Namen holen, die dorthin verweisen.

Fehlt das Token beim Start, startet Schild trotzdem, meldet den Fehler im Log und liefert die vorhandenen Zertifikate aus. Neue und erneuerte gibt es erst, wenn du das Token ergänzt und Schild neu gestartet oder `schild ingress reload -force` ausgeführt hast. Bei einem Reload ist ein fehlendes Token eine Warnung des Befehls, und das neue Caddyfile gilt trotzdem. Im [Cluster](03-cluster.md) braucht jeder Server die Token-Datei.

Getestet ist die Ausstellung gegen einen Nachbau der Hetzner-API und eine Test-Zertifizierungsstelle, noch nicht gegen Hetzner selbst.

### Dashboard von außen erreichen

Ab Werk hört das Dashboard auf `127.0.0.1:8788` und ist damit nur auf dem Server selbst erreichbar. Der einfachste Weg hinein ist der SSH-Tunnel aus den [ersten Schritten](00-installieren.md#erste-schritte). Ein VPN geht genauso.

Willst du das Dashboard unter einem eigenen Namen erreichen, stellst du einen eigenen Proxy mit TLS davor und beschränkst den Zugang dort, zum Beispiel auf dein VPN. Lass den Proxy nur HTTPS anbieten oder HTTP auf HTTPS umleiten, sonst geht dein Passwort im Klartext über die Leitung.

Das Dashboard prüft bei jeder Anfrage, unter welchem Namen es angesprochen wird (den `Host`-Header). Das schützt vor DNS-Rebinding: Eine fremde Webseite kann deinen Browser sonst dazu bringen, das Dashboard unter ihrem eigenen Namen abzufragen. Ohne Eintrag antwortet das Dashboard unter `localhost`, unter jeder IP-Adresse (`127.0.0.1`, die Adresse im VPN) und unter dem Host aus `listen.dashboard`. Für den SSH-Tunnel und den Aufruf über eine IP-Adresse musst du also nichts einstellen.

Einen DNS-Namen musst du in `schild.yaml` erlauben, egal ob er von deinem Proxy, aus dem VPN oder aus `/etc/hosts` kommt. Sonst antwortet das Dashboard mit 403 und nennt den fehlenden Eintrag:

```yaml
dashboard:
  allowed_hosts: ["schild.example.org"]
```

Die Namen stehen ohne Port, ohne `https://` und ohne Platzhalter (`*`), höchstens 32. Groß- und Kleinschreibung ist egal. Jeder Name gilt nur für sich, Subdomains trägst du einzeln ein. Nach der Änderung startest du Schild neu.

## Aktualisieren

Schild aktualisiert sich nie von allein. Was sich geändert hat, steht bei jedem [Release](https://github.com/deutschland-schild/schild/releases).

- **Docker Compose:** die Versionsnummer des Images in `compose.yaml` ändern, dann `docker compose pull && docker compose up -d`.
- **Paket:** `sudo apt update && sudo apt install schild`, dann `sudo systemctl restart schild`. apt tauscht nur die Dateien. Den Neustart machst du selbst, bis dahin läuft die alte Version weiter: Als Caddy-Distribution ist Schild dein Webserver, und ein Neustart ist ein kurzer Moment ohne Antwort auf Port 443. Auch `sudo apt upgrade` nimmt Schild mit. Die automatischen Sicherheitsupdates von Debian und Ubuntu (`unattended-upgrades`) fassen in ihrer Standardeinstellung nur Pakete der Distribution an, Schild also nicht.
- **Binary:** das neue Archiv laden und prüfen wie bei der Installation, dann `sudo install -m 0755 schild /usr/local/bin/schild`, die Geodaten (`sudo install -m 0644 geo/* /usr/share/schild/geo/`) und bei Änderungen die Unit-Dateien (`sudo install -m 0644 schild.service /etc/systemd/system/schild.service` und ggf. `schild-firewall.service`, danach `sudo systemctl daemon-reload`) aktualisieren und `sudo systemctl restart schild` ausführen.

Hast du mit Docker den [Server-Check eingerichtet](#server-check-einrichten), liegt eine Kopie des Binarys auf dem Server. Hol sie nach dem Update neu: `docker cp schild:/usr/local/bin/schild /tmp/schild && sudo /tmp/schild check install`. Bei Paket und Binary prüft der Check von selbst mit der neuen Version.

Läuft der Server in einem [Cluster](03-cluster.md), aktualisierst du die Server nacheinander. Ein Server nimmt sich mit `schild cluster drain` selbst aus dem Traffic, bevor er stoppt; `systemctl restart schild` und `docker compose up -d` tun dasselbe. Das dauert in der Vorgabe bis zu 45 Sekunden und das Herunterfahren dazu. Die mitgelieferte systemd-Unit wartet deshalb 90 Sekunden, unter Docker Compose setzt du beim Dienst `schild` die Zeile `stop_grace_period: 90s`. Die Schritte stehen unter [Einen Server geplant anhalten](03-cluster.md#einen-server-geplant-anhalten). Ein Cluster braucht außerdem gleiche Uhren auf allen Servern, also eine Zeitsynchronisation wie chrony oder systemd-timesyncd.

Passwort, freigeschaltete Adressen, Ausnahmen und Einstellungen liegen in `schild.db` im Datenverzeichnis und bleiben bei einem Update erhalten. Deine `schild.yaml` fasst Schild nicht an.

Braucht eine neue Version ein anderes Format der Datenbank, stellt Schild sie beim Start selbst um. Das macht nur `schild run`, also der Neustart des Dienstes oder Containers. Vorher legt Schild eine Sicherungskopie neben die Datenbank: `schild.db.backup-v<N>`, `<N>` ist die Nummer des alten Formats. Dafür muss ungefähr so viel Platz frei sein, wie die Datenbank groß ist. Klappt die Kopie oder die Umstellung nicht, bleibt die Datenbank unverändert, Schild startet nicht und nennt im Log den Grund. Es bleibt immer nur die Kopie des letzten Updates liegen.

In zwei Fällen startet Schild nicht und schreibt nichts:

- **Die Datenbank ist neuer als das Programm**, zum Beispiel nach dem Zurückwechseln auf eine ältere Version. Starte wieder die neuere Version. Willst du bei der älteren bleiben, halte Schild an und kopiere die Sicherung zurück (`schild.db.backup-v<N>` über `schild.db`). Was seit dem Update dazukam, fehlt dann.
- **Die Datenbank stammt aus einem Entwicklungsstand vor `0.1.0-alpha.1`.** Die Meldung nennt die Datei. Schieb sie weg, Schild legt beim nächsten Start eine neue an und zeigt einen neuen Einmal-Code.

Befehle wie `schild allow` oder `schild token` stellen die Datenbank nie um. Treffen sie nach einem Update auf eine Datenbank im alten Format, bitten sie dich, Schild erst neu zu starten.

Die Zugriffsliste und die Zahlen für die Diagramme (`metrics.db`) liegen in eigenen Dateien. Ändert sich ihr Format, beginnen sie leer. Einstellungen stehen dort keine.

## Agent-API einrichten

Über die [Agent-API](01-funktionen.md#agent-api-für-ki-agenten) arbeitet zum Beispiel der Coding-Agent deiner Website mit dem Gateway: Er liest, was die Firewall sieht, testet Anfragen gegen die Regeln und legt mit eigener Berechtigung Ausnahmen an. Sie ist ab Werk an, antwortet aber ohne Token auf nichts. Du brauchst zwei Schritte: ein Token anlegen und den Agenten verbinden.

### Ein- und ausschalten

Im Dashboard unter „Einstellungen“ steht die Karte „Agent-API“ mit dem Schalter, der Adresse und den Tokens. Der Schalter wirkt sofort, ohne Neustart, und gilt, bis du ihn mit „Wert aus schild.yaml einsetzen“ zurückgibst.

Willst du sie fest aus haben, trägst du das in `schild.yaml` ein und startest Schild neu. Dann lässt sie sich auch im Dashboard nicht einschalten, nur wieder in der Datei:

```yaml
agent_api:
  enabled: false
```

Ob die API läuft, siehst du auf dem Server so:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8789/agent/v0/status
```

`401` heißt: Sie läuft und wartet auf ein Token. Kommt keine Verbindung zustande, ist sie aus oder der Port 8789 war beim Start belegt. Dann zeigt die Karte „Nicht offen“, und du gibst ihr mit `agent_api.listen: 127.0.0.1:<port>` einen anderen. Läuft Schild in einem Container, lies [Agent-API mit Docker](#agent-api-mit-docker).

Ist die Agent-API aus, holt auch `schild firewall run` keine Sperren mehr ab ([Sperren in der Firewall](#sperren-in-der-firewall)). Das Dashboard fragt deshalb nach, bevor es sie ausschaltet, wenn es ein Token für die Firewall gibt.

### 1. Token anlegen

Tokens legst du auf dem Server an, mit dem Befehl, der zu deiner Installation passt:

```bash
# Paket oder Binary mit systemd
sudo schild token add --scope exceptions:write --label coding-agent

# Docker Compose
docker compose exec schild schild token add --scope exceptions:write --label coding-agent

# Docker
docker exec schild schild token add --scope exceptions:write --label coding-agent
```

Die erste Zeile der Ausgabe ist das Token, es beginnt mit `sat1_`. Schild zeigt es nur dieses eine Mal und speichert nur seinen Hash. Leg es dort ab, wo dein Agent seine Geheimnisse liest, zum Beispiel in einer Umgebungsvariable. In ein Repository gehört es nicht. Ist es weg, legst du ein neues an.

- **`--scope`** legt fest, was das Token darf. Ohne die Angabe gilt `agent:read`. Ein Token hat genau einen Scope, und der lässt sich später nicht erweitern. Braucht dein Agent zwei Schreibrechte, bekommt er zwei Tokens.
- **`--expires`** legt fest, wie lange das Token gilt: 1 bis 365 Tage (`1d` bis `365d`). Ohne die Angabe sind es 90 Tage. Danach lehnt Schild das Token ab.
- **`--label`** ist bei jedem Schreibrecht Pflicht. Der Name steht bei jeder Änderung im Verlauf.

| Scope | Erlaubt |
| --- | --- |
| `agent:read` (Standard) | alles lesen und Beispielanfragen gegen die Regeln testen |
| `exceptions:write` | dazu Ausnahmen anlegen und entfernen |
| `blocks:write` | dazu einzelne Sperren setzen und aufheben |
| `rules:write` | dazu die [Regel-Repositories](01-funktionen.md#regeln) schalten, neu laden oder zurücksetzen und einzelne Regeln ausschalten |
| `crawlers:write` | dazu die Crawler-Regeln ändern |
| `firewall:sync` | nur für `schild firewall run`: die gesperrten Adressen abholen, sonst nichts |
| `export:read` | nur den Export für ein zentrales Dashboard |

Zum Ausprobieren reicht `agent:read`. Soll dein Agent die Firewall an deine Anwendung anpassen, nimmst du `exceptions:write`.

`schild token list` zeigt alle Tokens mit ID, Scope, Ablaufdatum und Name. `schild token revoke tok_…` widerruft eines, es gilt ab der nächsten Anfrage nicht mehr. `schild token log` zeigt die letzten Aufrufe.

### 2. Agenten verbinden

Läuft dein Agent auf dem Server, spricht er direkt mit `http://127.0.0.1:8789/agent/v0`. Von einem anderen Rechner aus baust du einen SSH-Tunnel auf, auch durch ein VPN:

```bash
ssh -N -L 8789:127.0.0.1:8789 du@dein-server
```

Lass den Port im Tunnel bei 8789. Schild lehnt Anfragen ab, die einen anderen Host oder Port nennen (Schutz gegen DNS-Rebinding). Eine Adresse aus deinem Netz nimmt `agent_api.listen` nicht an, und einen direkten Zugang über die VPN-Adresse des Servers gibt es noch nicht.

Prüf den Zugang einmal von Hand:

```bash
export SCHILD_TOKEN=sat1_…
curl -s -H "Authorization: Bearer $SCHILD_TOKEN" http://127.0.0.1:8789/agent/v0/status
```

Dann gibst du deinem Agenten drei Dinge: die Adresse, die Variable mit dem Token und den Hinweis, zuerst `http://127.0.0.1:8789/agent/v0/openapi.json` zu lesen. Dort beschreibt sich die API selbst, mit den typischen Aufgaben und den Aufrufen dafür. Für Menschen steht dieselbe Beschreibung in der [API-Referenz](/api). Ein Auftrag kann so aussehen:

```text
Unter http://127.0.0.1:8789/agent/v0 läuft die Agent-API meines Schild Gateways.
Das Token steht in der Umgebungsvariable SCHILD_TOKEN. Lies zuerst /openapi.json.
Teste dann die Formulare unserer Anwendung gegen die Regeln und schlag mir
Ausnahmen vor, bevor du sie anlegst.
```

### Agent-API mit Docker

Im Container zeigt `127.0.0.1` auf den Container selbst. Damit du die Agent-API vom Server aus erreichst, hört sie im Container auf allen Schnittstellen, und Docker veröffentlicht den Port nur auf `127.0.0.1` des Servers. Die Vorlagen `schild.yaml` und `compose.yaml` aus der Installation bringen beides mit. In einer älteren Installation trägst du es nach:

```yaml
# schild.yaml
agent_api:
  listen: "0.0.0.0:8789"
```

```yaml
# compose.yaml, beim Dienst schild unter ports
      - "127.0.0.1:8789:8789"
```

Mit `docker run` ist es `-p 127.0.0.1:8789:8789`. Danach `docker compose up -d`, und der SSH-Tunnel von oben funktioniert.

- Das `127.0.0.1` vor dem Port muss bleiben. Ohne es wäre die Agent-API aus dem Internet erreichbar, und ein Token ginge im Klartext über die Leitung.
- Die Portnummer bleibt auf beiden Seiten gleich, sonst lehnt Schild die Aufrufe ab.
- `0.0.0.0` gilt nur im Container. Läuft Schild direkt auf dem Server, öffnet es die Agent-API mit dieser Adresse nicht, und die Karte im Dashboard nennt den Grund. Dort bleibt es bei `127.0.0.1`. Außer Loopback und „alle Schnittstellen“ nimmt `agent_api.listen` nichts an.
- Mit `network_mode: host` brauchst du nichts davon: Dann ist `127.0.0.1:8789` schon die Adresse auf dem Server.

### Wenn es nicht klappt

| Antwort | Ursache |
| --- | --- |
| keine Verbindung | Agent-API ausgeschaltet, Port 8789 beim Start belegt, Tunnel nicht aufgebaut, Schild läuft im Container und der Port ist nicht veröffentlicht, oder `0.0.0.0` steht in der Datei, obwohl Schild nicht im Container läuft |
| 401 `unauthenticated` | Token fehlt, ist abgelaufen oder widerrufen. `schild token list` zeigt den Stand |
| 403 `forbidden` | Die Anfrage nennt einen anderen Host oder Port als `127.0.0.1:8789`, oder sie kommt aus einem Browser |
| 403 `scope_required` | Das Token darf das nicht. Leg eines mit dem passenden Scope an |
| 429 `rate_limited` | mehr als 120 Anfragen pro Minute oder mehr als 2 gleichzeitig je Token (`agent_api.requests_per_minute`, `max_concurrent`) |

## Was sperrt

Was gesperrt wird, entscheiden die Schalter der einzelnen Quellen:

| Quelle | Schalter | ab Werk |
| --- | --- | --- |
| Core Rule Set (`rules.crs.state`) | aus, erkennen, sperren | sperren |
| CrowdSec Hub (`rules.crowdsec.state`) | aus, erkennen, sperren | erkennen |
| eigene Regeln (`rules.local.state`) | aus, erkennen, sperren | sperren |
| Szenarien | aus, beobachten, sperren (erst nach 14 Tagen Lernzeit) | die Empfehlung: sperren, nur „Aggressives Abrufen“ beobachtet |
| Limits | aus, beobachten, begrenzen, je Limit | die Empfehlung: Login, Passwort vergessen und `xmlrpc.php` begrenzen, die übrigen beobachten |
| Crawler-Regeln je Website | erlauben, sperren | erlauben |

Die [harten Grenzen](01-funktionen.md#harte-grenzen) gelten immer. Sperren, die du im Dashboard setzt oder ein Agent mit seinem Token, wirken auch immer. Das hat ja jemand bewusst entschieden, und mit „Sperre aufheben“ ist es wieder vorbei.

Eine Regel stoppt die einzelne Anfrage, auf die sie passt. Eine Adresse für eine Weile sperrt nur ein Szenario, ein Limit oder du selbst. Was eine Quelle auf „erkennen“ oder „beobachten“ findet, steht im Dashboard als „Erkannt“, mit dem Grund dazu. Bei einem Szenario kannst du es direkt dort auf „sperren“ stellen. Unter „Regeln“ → „Szenarien und Limits“ ist an jedem Schalter die empfohlene Stellung markiert. „Empfehlung übernehmen“ stellt alle abweichenden Schalter auf einmal um, über das Menü daneben auch alle Szenarien auf „sperren“ oder „beobachten“. Das ist kein eigener Modus: Danach stellst du jeden Schalter wieder einzeln.

**Erst zusehen:** Bei einer empfindlichen Anwendung stellst du das Core Rule Set für ein paar Tage auf „erkennen“ (`rules.crs.state: detect` oder im Dashboard unter „Regeln“). Dann siehst du, was gesperrt worden wäre, legst Ausnahmen an und schaltest auf „sperren“.

**Regeln aus Updates:** Neue oder geänderte Regeln aus dem CrowdSec Hub erkennen zuerst nur und sperren nach einer Wartezeit von selbst (`settling_s`, Standard 24 Stunden), wenn der Hub auf „sperren“ steht. Willst du eine Regel nicht, schaltest du sie einzeln aus.

**Testprofil:** Mit `profile: test` sperrt Schild gar nichts, egal wie die Schalter stehen, auch nicht von Hand. Das Profil ist für Testlabore gedacht, Release-Versionen lehnen es ab.

Eine Zeile `mode:` aus einer älteren `schild.yaml` stört nicht. Schild ignoriert sie und sagt beim Start, dass du sie löschen kannst. Bei `mode: observe` stellt Schild alle Regelquellen, die du unter `rules` nicht selbst einstellst, auf „erkennen“.

## Regeln einstellen

Die drei [Regel-Repositories](01-funktionen.md#regeln) stellst du in `schild.yaml` im Block `rules` ein. So sieht er mit den Werten ab Werk aus; was du nicht angibst, bleibt beim Standard:

```yaml
rules:
  crs:                            # OWASP Core Rule Set
    state: block                  # off, detect oder block
    paranoia_level: 1             # Strenge, 1 bis 4
    inbound_anomaly_threshold: 5  # Punkte, ab denen gesperrt wird
    disabled_rules: []            # Regelnummern, zum Beispiel "942100"
  crowdsec:                       # virtuelle Patches aus dem CrowdSec Hub
    state: detect
    auto_update: true             # false: keine Anfrage nach draußen
    interval_s: 3600              # Abstand der Update-Prüfungen
    settling_s: 86400             # Wartezeit, bis Regeln aus Updates sperren
    disabled_rules: []            # Namen, zum Beispiel crowdsecurity/vpatch-CVE-2026-1207
  local:                          # eigene Regeln
    state: block
    dir: /etc/schild/rules.d      # *.conf, gelesen in der Reihenfolge der Dateinamen
    disabled_rules: []            # Regelnummern
```

Den Schalter eines Repositorys und einzelne Regeln kannst du auch im Dashboard unter „Regeln“ oder über die Agent-API ändern. Ein Wert von dort gilt vor `schild.yaml`, bis du ihn zurücksetzt. Strenge und Schwelle des Core Rule Sets stellst du ebenfalls im Dashboard ein, unter „Regeln › OWASP CRS“ mit „Strenge und Schwelle anpassen“; die Agent-API liest beide Werte nur. Eine Regel in `disabled_rules` bleibt aus, egal was dort eingestellt wird. Mit `rules.crowdsec.pin` (ein Commit des Hubs, 40 Zeichen) nagelst du die CrowdSec-Regeln auf einen Stand fest; dann holt Schild genau diesen einen Stand und keine Updates mehr.

## Sperren in der Firewall

Eine Sperre von Schild gilt in Schild: Die gesperrte Adresse bekommt auf jeder Website die Sperrseite mit ihrer Vorfallnummer, bei deiner Anwendung kommt nichts an. Auf Wunsch trägt Schild seine Sperren zusätzlich in die Firewall des Servers ein. Dann kommen gesperrte Adressen gar nicht mehr an die Ports 80 und 443, und unter „Sperren“ steht bei jeder Adresse, ob die Firewall sie hält.

Das übernimmt `schild firewall run`: dasselbe Image wie das Gateway, als eigener kleiner Container mit genau einem Recht, `NET_ADMIN`. Er fragt die Agent-API des Gateways nach den laufenden Sperren und trägt sie in eine eigene nftables-Tabelle `inet schild` ein, jede mit ihrer Restlaufzeit. Kommt eine Sperre dazu oder gibst du eine frei, erfährt er es sofort und ändert die Tabelle innerhalb einer Sekunde. Das Gateway selbst bekommt keine Rechte an der Firewall. So arbeiten auch die Firewall-Bouncer von CrowdSec.

**Voraussetzungen:** Linux mit nftables im Kernel (Debian, Ubuntu, Alma, Rocky in aktuellen Versionen) und die [Agent-API](#agent-api-einrichten). Sie ist ab Werk an.

Dann einen Token für die Firewall anlegen. Er darf nur die Sperren abholen, sonst nichts:

```sh
schild token add --scope firewall:sync --expires 365d --label firewall
```

Der Token läuft nach höchstens einem Jahr ab. Dann zeigt „Sperren“ an, dass die Firewall nicht mehr abgleicht, und du legst einen neuen an.

### Mit Kamal

Ein zweites Accessory neben dem Gateway, mit **demselben Image** und dem Netz des Gateways. Läuft das Gateway mit `network: host`, dann so:

```yaml
accessories:
  ingress:
    image: ghcr.io/deutschland-schild/schild:<version>
    # ...wie bisher
  firewall:
    image: ghcr.io/deutschland-schild/schild:<version>   # immer dieselbe Version wie ingress
    host: <server>
    cmd: firewall run
    options:
      network: host
      user: "0:0"
      cap-add: NET_ADMIN
    env:
      secret:
        - SCHILD_FIREWALL_TOKEN
```

Den Token trägst du in `.kamal/secrets` als `SCHILD_FIREWALL_TOKEN` ein, dann `kamal accessory boot firewall`. Bei einem Update änderst du beide Image-Zeilen und startest beide Accessories neu.

### Mit Docker Compose

Die Vorlage [compose.yaml](../../gateway/deploy/quickstart/caddy/compose.yaml) enthält den Dienst `firewall`. Er teilt das Netz von `schild` (`network_mode: service:schild`) und startet nur auf Wunsch: Token in `.env` als `SCHILD_FIREWALL_TOKEN`, dann `docker compose --profile firewall up -d`.

### Ohne Docker

Die Unit `schild-firewall.service` aus dem Release-Archiv (oder `docs/ops/systemd/`) nach `/etc/systemd/system/` kopieren, den Token nach `/etc/schild/firewall.env` schreiben (`SCHILD_FIREWALL_TOKEN=sat1_…`, nur für root lesbar), dann `sudo systemctl daemon-reload && sudo systemctl enable --now schild-firewall`.

### Was du wissen solltest

- **Nur die Web-Ports.** Gesperrt wird der Zugang zu 80 und 443 (TCP und UDP). SSH und alle anderen Ports bleiben, wie sie sind. Du sperrst dich also nicht aus.
- **Sperren enden von selbst.** Jede Sperre hat im Kernel ihre Ablaufzeit. Fällt der Firewall-Container aus oder ist das Gateway kurz weg, läuft sie trotzdem pünktlich ab.
- **Von Hand sperren.** Unter „Sperren“ mit „Adresse sperren“, beim Ereignis oder beim Vorfall: eine IP-Adresse für 1 Stunde, 24 Stunden oder 7 Tage, mit Grund. Beim Ereignis reicht ein Klick: Adressen aus Rechenzentren sperrt Schild dann für 7 Tage, alle anderen für 24 Stunden. Als Grund steht das Ereignis da, und der Hinweis danach bietet „Rückgängig“ an. Eine andere Dauer und „Zu Eigene IPs hinzufügen“ stehen im Menü „…“ daneben. Dasselbe Menü hat jede Zeile in „Ereignisse“ und in den Anfragen einer Website. Sie landet wie jede andere Sperre innerhalb einer Sekunde in der Firewall. Eigene IPs, der Server selbst und private Adressen lassen sich nicht sperren. Adressen aus dem Mobilfunk, hinter CGNAT oder von Tor nur nach einer Bestätigung, weil sich viele Menschen eine solche Adresse teilen.
- **Aufheben geht im Dashboard.** Unter „Sperren“ und beim Vorfall mit „Sperre aufheben“ oder indem du die Adresse unter „Eigene IPs“ einträgst: Die Sperre endet sofort in Schild und innerhalb einer Sekunde in der Firewall.
- **Eigene Tabelle.** Schild ändert nur `inet schild`. Deine Regeln, ufw, firewalld und fail2ban bleiben unberührt. Läuft fail2ban auf denselben Ports, kann eine Adresse an zwei Stellen gesperrt sein. Das schadet nicht.
- **Docker und IPv6:** Im Bridge-Netz mit `network_mode: service:schild` filtert die Tabelle im Netzwerk-Namespace des Containers. Bei Dockers Standardeinstellung (`userland-proxy`) kommen IPv6-Verbindungen oft über die Bridge-Adresse (`172.x.0.1`) im Container an statt mit der echten IPv6-Adresse der Besucher:innen. Dann greifen weder `blocked6` noch die IP-Zuordnung im WAF. Für echte IPv6-Filterung nutze `network_mode: host` (wie im Kamal-Beispiel oben) oder natives Docker-IPv6-Routing ohne `userland-proxy`.
- **Nachsehen und ausschalten:** `schild firewall status` zeigt, was die Tabelle hält. Stoppst du den Firewall-Container, entfernt er die Tabelle. `schild firewall off` entfernt sie sofort.

## Server-Check einrichten

Der [Server-Check](01-funktionen.md#server-check) läuft als eigener Prozess direkt auf dem Server, weil er nur dort SSH, Firewall, Updates und Logs lesen kann. Einmal am Tag schreibt er einen Bericht in ein Verzeichnis, und das Gateway zeigt ihn im Dashboard unter „Server“. Ein Befehl richtet das ein: `schild check install` legt die systemd-Units an, schaltet den täglichen Lauf ein und startet die erste Prüfung.

### Mit Docker

Das Binary steckt im Image. Kopier es aus dem laufenden Container auf den Server und führ es einmal aus. `schild` ist in der ersten Zeile der Name deines Containers, `docker ps` zeigt ihn:

```sh
docker cp schild:/usr/local/bin/schild /tmp/schild
sudo /tmp/schild check install
```

Der Befehl legt das Binary nach `/usr/local/bin/schild`. Danach gibst du dem Container zwei Verzeichnisse und eine Variable mit und startest ihn damit neu:

```sh
  -v /var/lib/schild/host-check:/var/lib/schild/host-check:ro \
  -v /run/schild-check:/run/schild-check \
  -e SCHILD_HOST_CHECK_TRIGGER=/run/schild-check/request \
```

In den `compose.yaml` aus `gateway/deploy/quickstart/` stehen diese Zeilen schon, mit einem `#` davor. Nimm es weg und führ `docker compose up -d` aus.

In der `schild.yaml` braucht Schild die Zeile `host_check: {}`. Die Start-Konfiguration enthält sie. Fehlt sie in deiner Datei, trägst du sie nach und startest den Container neu.

Im ersten Verzeichnis liegen die Berichte, der Container darf sie nur lesen. Über das zweite fordert „Jetzt prüfen“ im Dashboard einen Lauf an. Lässt du es weg, läuft der Check trotzdem einmal am Tag.

Zwei Dinge gehören bei Docker dazu:

- **Zertifikate.** Schilds Zertifikate liegen im Docker-Volume, dort sucht der Check nicht von selbst. Findet der Befehl ein solches Volume, nennt er dir die passende Zeile, zum Beispiel `sudo /tmp/schild check install -cert '/var/lib/docker/volumes/schild-data/_data/caddy/certificates/*/*/*.crt'`.
- **Updates.** Nach einem Update des Images wiederholst du die beiden Befehle oben. Dann hat der Check auf dem Server dieselbe Version wie das Gateway.

### Mit Paket oder Binary

```sh
sudo schild check install
```

Danach startest du Schild neu (`sudo systemctl restart schild`). Schild braucht dafür die Zeile `host_check: {}` in `/etc/schild/schild.yaml`. `schild init` schreibt sie hinein. Fehlt sie in deiner Datei, trägst du sie vorher nach. Der Befehl erkennt den Dienst `schild`, gibt dessen Gruppe Leserecht auf die Berichte und erlaubt dem Dienst, „Jetzt prüfen“ anzufordern. Schild startet er nicht neu, den Moment bestimmst du.

### Was du wissen solltest

- **Der Check liest nur.** Er ändert nichts am Server. Seine Unit lässt ihm dafür auch keine Rechte: Schreiben darf er nur in das Verzeichnis der Berichte. Was er nicht lesen kann, meldet er als „nicht lesbar“. `schild check -privileges` zeigt, was jede Prüfung liest.
- **Anwendungen nennst du selbst.** WordPress, TYPO3, Laravel und Nextcloud sucht der Check nur unter Pfaden, die du angibst: `sudo schild check install -app /var/www/shop`, mehrere Pfade mit mehreren `-app`.
- **Berichte bleiben auf dem Server.** Sie liegen in `/var/lib/schild/host-check`, aufbewahrt werden die letzten 30.
- **Von Hand starten:** `sudo systemctl start schild-check.service`. Wann der nächste Lauf ansteht, zeigt `systemctl list-timers schild-check.timer`.
- **Vorher ansehen:** `schild check install -dry-run` zeigt alle Dateien und Befehle und ändert nichts.
- **Wieder entfernen:** `sudo schild check uninstall` nimmt die Units heraus. Berichte und Binary bleiben liegen.
- **Ohne systemd** rufst du `schild check` aus deinem eigenen Zeitplaner auf, zum Beispiel per cron.

## Wenn Schild ausfällt

- **Schild läuft nicht, hinter deinem Webserver** (Prozess beendet, Verbindung abgelehnt): Dein Webserver davor schickt die Anfragen direkt an die Anwendung. Die Website bleibt erreichbar, nur ohne Prüfung.
- **Schild läuft nicht, als Caddy-Distribution:** Es gibt keinen Webserver davor, deine Websites sind nicht erreichbar. systemd und Docker starten Schild nach einem Absturz von selbst neu. Startet es nicht wieder, nimmst du den [Weg zurück zu Caddy](#in-einer-minute-wieder-raus).
- **Schild antwortet zu langsam** oder die Prüfung bricht ab: 503, nie ungeprüft durch. Sonst könnte ein Angreifer Schild absichtlich überlasten, um vorbeizukommen.
- **Zugriffsschutz aktiv:** Dann gibt es keinen Weg an Schild vorbei, auch nicht bei einem Ausfall. Sonst wäre die geschützte Seite plötzlich offen. Dafür muss dein Webserver davor Schilds Datenverzeichnis lesen können (nur lesend einbinden). Sieht er den Zustand nicht, reicht er gar nicht durch und zeigt die Wartungsseite.

## In einer Minute wieder raus

**Schild als Caddy-Distribution:**

1. Setz im Caddyfile im Snippet `(schild)` ein `#` vor die Zeile `schild`. Caddy kennt sie nicht und startet sonst nicht. Die Zeilen `import schild` können bleiben.
2. Hast du für Schild einen Log-Ordner umgestellt, gib ihn wieder Caddy: `sudo chown -R caddy /var/log/caddy`.
3. Zurück zu deinem bisherigen Caddy wechseln: `sudo systemctl disable --now schild && sudo systemctl enable --now caddy`, `docker rm -f schild && docker start caddy` oder `docker compose down && docker start caddy`.
4. Nachsehen, ob Caddy läuft: `systemctl is-active caddy` oder `docker ps --filter name=caddy`. `docker start` meldet keinen Fehler, wenn Caddy sich wegen des fehlenden `#` gleich wieder beendet.

Caddy startet mit seinen eigenen Zertifikaten. Schild hat mit einer Kopie gearbeitet und Caddys Speicher nie angefasst.

**Schild hinter deinem Webserver:**

1. Schild stoppen: `sudo systemctl disable --now schild`, `docker rm -f schild` oder `docker compose down`. Schickt dein Webserver bei abgelehnter Verbindung direkt an die Anwendung, geht der Traffic sofort dorthin.
2. Dauerhaft: im Webserver `proxy_pass` oder `reverse_proxy` wieder auf die Anwendung zeigen lassen und neu laden.

Deine Anwendung hängt von nichts ab, was Schild speichert. Wer auch die Daten loswerden will, löscht `/var/lib/schild` und `/etc/schild` oder nimmt `docker compose down -v`.

## Welche Daten wo bleiben

**Was den Server verlässt:** nichts aus deinem Traffic. Schild ruft nur öffentliche Daten ab, und jede dieser Verbindungen lässt sich abschalten:

| Abruf | Wohin | Abschalten |
| --- | --- | --- |
| Index der CrowdSec-Hub-Regeln, stündlich | GitHub | `rules.crowdsec.auto_update: false` oder `rules.crowdsec.state: off` |
| Adresslisten echter Crawler, täglich | die Betreiber der Crawler (Google, OpenAI …) | `bots.ranges_fetch: false` |
| Geodaten, nur wenn du IPinfo oder MaxMind einrichtest | der jeweilige Anbieter | Anbieter nicht einrichten |

Dabei wird keine Besucheradresse übertragen.

**Offline- / Air-Gap-Betrieb:** Soll Schild gar keine Verbindungen nach draußen aufbauen, schalte beide Abrufe in `schild.yaml` ab:

```yaml
rules:
  crowdsec:
    auto_update: false
bots:
  ranges_fetch: false
```

Die mitgelieferten Regeln und der Bot-Katalog aus dem Binary bleiben dann aktiv, ohne regelmäßige Abrufe. Ist zusätzlich `geo.provider: ipinfo` oder `maxmind` gesetzt, lädt Schild auch die Geodatenbank nach – für den Offline-Betrieb lässt du `geo.provider` weg und nutzt nur die mitgelieferte DB-IP-Lite-Datei.

**Was auf dem Server bleibt:**

- Ereignisse mit IP-Adresse und Land. Nach 14 Tagen wird die IP gekürzt (IPv4 auf /24, IPv6 auf /48) und das Ereignis gelöscht; höchstens 100 MB. Alles einstellbar unter `retention`.
- Einzelne Anfragen für die Ansicht „Zugriffe“, mit IP-Adresse und Browserkennung, ohne Query-String und Cookies. Sie bleiben so lange wie die vollen IP-Adressen der Ereignisse, ab Werk 14 Tage (`retention.raw_ip_days`), und zusammen höchstens 512 MB; darüber gehen die ältesten zuerst. Einstellen kannst du das mit `monitoring.requests.keep_hours` und `monitoring.requests.max_size_mb`, ganz aus mit `monitoring.requests.enabled: false`.
- Zahlen ohne IP-Adressen für Diagramme, Zusammenfassungen 90 Tage.
- Inhalte von Anfragen speichert Schild nie, Passwörter und Tokens werden geschwärzt.

Im Dashboard unter „Datenschutz“ suchst, exportierst und löschst du alles zu einer IP-Adresse. Mehr im [Datenschutzkonzept](../concept/24-datenschutz.md).

## Backup und Wiederherstellung

Für einen schnellen Wiederaufbau reichen diese Dateien:

- `/etc/schild/schild.yaml` und eigene Regeln unter `/etc/schild/rules.d/`
- `/var/lib/schild/schild.db` (Dashboard-Passwort, Einstellungen, Ausnahmen, eigene IPs, API-Tokens sowie gespeicherte Ereignisse mit IP-Adressen – beachte das bei der Aufbewahrungsdauer deiner Backups)
- `/var/lib/schild/caddy/` (Zertifikate und ACME-Konto, wenn Schild als Caddy-Distribution läuft)

`metrics.db` enthält nur historische Diagrammdaten und muss nicht gesichert werden. Kopiere `schild.db` im laufenden Betrieb nicht einfach mit `cp` (SQLite nutzt WAL-Dateien): Nutze entweder `sqlite3 /var/lib/schild/schild.db ".backup /pfad/zum/backup/schild.db"` oder stoppe Schild kurz für die Kopie. Beim Zurückspielen gehören die Dateien wieder dem Benutzer `schild` (bzw. UID/GID `65532:65532` im Container).

## Monitoring und Alarme

Schild stellt auf `127.0.0.1:9101` einen Health-Endpunkt (`/readyz`) und Prometheus-Metriken (`/metrics`) bereit (`listen.metrics` in `schild.yaml`). Die Metriken enthalten keine Besucheradressen, Pfade oder User-Agents.

Für Alarme im Alltag sind besonders diese Metriken nützlich:

| Metrik | Bedeutung / Alarm-Auslöser |
| --- | --- |
| `schild_baseline_protection_active` | `1`, wenn Grundschutz aktiv (WAF + CRS laufen); alarmieren bei `== 0` |
| `schild_memory_pressure` | `0` normal, `1` Bodies werden abgewiesen, `2` alle Anfragen werden abgewiesen; alarmieren bei `> 0` |
| `schild_events_dropped_total` | Verlorene Ereignisse bei voller Writer-Queue; alarmieren bei Anstieg |
| `schild_hard_limit_rejects_total` | Abweisungen durch harte Grenzen (nach `code`) |
| `schild_requests_total` | Anfragen nach Ergebnis (`outcome`) |
| `schild_waf_seconds` | WAF-Latenz pro Anfrage (Histogramm) |

## Befehle

| Befehl | Wofür |
| --- | --- |
| `schild init -caddyfile <datei>` | eine Start-Konfiguration schreiben: Schild als Caddy-Distribution mit deinem Caddyfile. Nennt die Zeilen, die das Caddyfile noch braucht, und die Schritte bis zum Wechsel |
| `schild init -upstream <url>` | eine Start-Konfiguration schreiben: Schild hinter einem Webserver vor einer Anwendung |
| `schild run` | starten (prüft vorher die Konfiguration) |
| `schild preflight` | Konfiguration und Speicherplatz prüfen, ohne zu starten |
| `schild ingress validate` | Prüfen, bevor Schild der Webserver wird: das Caddyfile, ob Schild in sein Datenverzeichnis schreiben kann, ob es die Kopie der Zertifikate lesen und schreiben kann und ob es in die Logdateien des Caddyfiles schreiben darf, unter systemd auch nach den Regeln der Unit. Läuft als der Benutzer, als der Schild läuft, auch im Container mit schreibgeschütztem Dateisystem. Mit `-adapt-only` nur das Caddyfile |
| `schild ingress reload` | das geänderte Caddyfile ohne Neustart laden (siehe [Caddyfile ändern](#caddyfile-ändern)) |
| `schild status` | Profil, Backend, eigene IPs, ob Dashboard und Metriken antworten |
| `schild allow …` | eigene IPs freischalten, auflisten, entfernen |
| `schild lock on/off/status` | Zugriffsschutz für Website oder Pfade |
| `schild rules sync local` | eigene Regeln ohne Neustart neu laden (ein `SIGHUP` macht dasselbe) |
| `schild rules sync crowdsec` | jetzt nach Updates im CrowdSec Hub schauen |
| `schild rules reset crowdsec` | CrowdSec-Hub-Regeln auf den Stand des Programms zurücksetzen |
| `schild check` | Server-Check auf diesem Server |
| `schild check install`, `uninstall` | den täglichen Server-Check als systemd-Units einrichten oder wieder entfernen (siehe [Server-Check einrichten](#server-check-einrichten)) |
| `schild firewall run`, `status`, `off` | Sperren von Schild in der Firewall halten, ansehen oder alle wieder herausnehmen (siehe [Sperren in der Firewall](#sperren-in-der-firewall)) |
| `schild token add`, `list`, `revoke`, `log` | Tokens der [Agent-API](#agent-api-einrichten) anlegen, auflisten, widerrufen, Protokoll ansehen |
| `schild dashboard setup-code` | den Einmal-Code für die erste Anmeldung noch einmal anzeigen, solange kein Passwort gesetzt ist |
| `schild dashboard reset-password` | Dashboard-Zugang zurücksetzen, neuer Einmal-Code |
| `schild front` | kleiner Front-Proxy vor Schild, falls du keinen Webserver davor hast: reicht nur bei abgelehnter Verbindung direkt an die Anwendung durch, nie bei aktivem Zugriffsschutz |
| `schild health` | Health-Check für Container (fragt `/readyz` ab) |
| `schild version` | Versionen von Schild, Caddy, Coraza und Core Rule Set |

Die Prüfung von Access-Logs (`schild logcheck`) und alle Flags stehen in [gateway/README.md](../../gateway/README.md#commands), `schild help` zeigt sie auf dem Server.

## Bekannte Grenzen

- Schild ist in der Alpha. Befehle, Konfiguration und Dashboard können sich noch ändern.
- Pakete gibt es für Debian und Ubuntu (apt), für dnf noch nicht. Windows und Shared Hosting ohne Root gehen nicht.
- Eine Browserprüfung (Zwischenseite mit Rechenaufgabe) gibt es noch nicht. Ein altes `mode: challenge` in `schild.yaml` liest Schild als `observe` und warnt beim Start.
- Sperren bis 24 Stunden liegen im Arbeitsspeicher, auch die von Hand gesetzten. Ein Neustart beendet sie früher, nie später. Sperren über 24 Stunden (7 Tage) überstehen einen Neustart.
- Antworten deiner Anwendung prüft Schild nicht.
- Hinter einem Webserver sieht Schild den TLS-Handshake nicht und kann daraus keinen Fingerabdruck bilden.
- Eine Upstream-Adresse mit Pfad (`http://app:8081/unterordner`) geht nicht.
- Im Dashboard gibt es eine Rolle: Admin.
