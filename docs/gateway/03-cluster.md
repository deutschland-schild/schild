---
short: Cluster
description: "Mehrere Schild Gateways als Cluster betreiben: was sie teilen, wie du ihn mit einer Konfigurationsdatei oder von Hand einrichtest, was der Loadbalancer davor braucht, wie Sperren schon auf den Balancer-VMs greifen, was beim Ausfall eines Servers passiert und wo die Grenzen liegen."
---

# Mehrere Gateways als Cluster betreiben

**Status:** experimentell, noch in keinem Release enthalten · Stand 22.11.2026 · technische Quelle: [contracts/cluster.md](../../contracts/cluster.md)

**Gemessen** von Mess-Agenten, die das Gateway nicht gebaut haben, am 21. und 22.11.2026:

- Drei Gateways auf einem Rechner, Grundfunktionen und feindliche Datensätze: [Bericht](../../tests/results/MVP-27-group-measurement.md). Der letzte Lauf bestand alle 92 bewerteten Prüfungen.
- Störungen zwischen den Servern, Abstürze, Last, zwei und sechzehn Gateways, lange Abwesenheit, Uhren und ein Update Server für Server, auf einem Rechner: [Bericht](../../tests/results/MVP-27-hardening.md). Im letzten Lauf bestanden 225 von 236 Prüfungen. Was durchfiel, steht unter [Grenzen](#grenzen).
- Sechzehn Gateways, ein HAProxy, eine Balancer-VM mit Firewall und eine Test-Zertifizierungsstelle auf einem Rechner mit virtuellen Linux-Servern: [erster Lauf](../../tests/results/MVP-27-lab.md), [zweiter Lauf](../../tests/results/MVP-27-lab-run2.md), [dritter Lauf](../../tests/results/MVP-27-lab-run3.md). Im dritten Lauf bestanden 294 von 361 Prüfungen, 11 fielen durch, 56 sind Zahlen ohne Bewertung. Neu gemessen wurden dabei die Zähler beim Start eines Servers, die Regel für falsche Uhren, das Teilen jeder Einstellung, der Vergleich des Stands, der Aufwand im Leerlauf und ein Update Server für Server. Zwei der elf Fehlschläge waren neu und sind danach behoben worden (falsche Anzeige „weicht ab“ unter laufenden Änderungen, doppelt geschriebene erste Schlüssel der Browser-Prüfung). Diese beiden Korrekturen sind noch nicht unabhängig nachgemessen. Die übrigen Fehlschläge stehen unter [Grenzen](#grenzen).

Nicht gemessen ist der Betrieb auf echten Servern mit echten Besucher:innen.

**Kurz:**

- Ein Cluster sind zwei bis sechzehn Gateways eines Betreibers, zum Beispiel hinter einem Loadbalancer. Sie teilen ihren Stand direkt untereinander. Du betreibst keine Datenbank, keinen Cache und keine Queue daneben.
- Zwei Server reichen. Fällt einer aus, arbeitet der andere mit allem weiter, was der Cluster wusste.
- Geteilt wird alles, was du im Dashboard oder über die Agent-API einstellst, dazu Sperren, Logins, Zertifikate, die Zähler von Limits und Szenarien sowie Ereignisse und Anfragen.
- Keine Anfrage wartet auf einen anderen Server. Erreicht ein Server den Cluster nicht, entscheidet er mit seinem letzten Stand.
- Ohne `cluster.enabled` ändert sich nichts. Ein einzelnes Gateway bleibt, wie es ist.

## Wofür ein Cluster gut ist

Mit einem Gateway hängt deine Website an einem Server. Mit zwei oder mehr kannst du einen Server aktualisieren oder verlieren, ohne dass die Website ausfällt. Ein Hoster kann viele Websites hinter eine Reihe von Gateways stellen und Server dazunehmen, wenn der Traffic wächst.

Ohne Cluster wäre jedes Gateway für sich: Eine Sperre gälte nur auf einem Server, ein Limit zählte pro Server, und Besucher:innen müssten die Browser-Prüfung auf jedem Server neu bestehen.

## Was der Cluster teilt

| Was | Wie es sich verhält |
| --- | --- |
| Gesperrte Adressen | Eine Sperre aus einem Szenario, aus dem Dashboard oder von einem Agenten gilt nach etwa einer Sekunde auf jedem Server. „Freigeben“ hebt sie überall auf. Das gilt auf jedem Server, auch wenn du klickst, bevor die Sperre dort angekommen ist. |
| Einstellungen | Alles, was du im Dashboard oder über die Agent-API einstellst, gilt auf jedem Server: Schalter der Regelquellen, Schwellen, Limits, Crawler-Regeln, Zugriffssperre, Browser-Prüfung, Ausnahmen. Das gilt auch für Einstellungen künftiger Funktionen, ohne dass sie dafür etwas tun müssen. |
| Eigene Adressen und Freigaben | Die Liste eigener Adressen und freigegebene Absender gelten überall. Die eigene Liste eines Servers aus seiner `schild.yaml` gewinnt immer gegen eine Sperre aus dem Cluster. |
| Logins | Ein Passwort und eine Anmeldung gelten für das Dashboard jedes Servers. Agent-Tokens gelten auf allen. |
| Besucher:innen | Wer die Browser-Prüfung bestanden oder sich an der Zugriffssperre angemeldet hat, bleibt das auf dem nächsten Server. |
| Zertifikate | Es gibt ein Zertifikat pro Name, solange sich die Server erreichen. Ein Server, der startet, bestellt erst, wenn er weiß, was der Cluster schon hat. Die Prüfung der Zertifizierungsstelle über HTTP landet auf einem beliebigen Server, deshalb liegt ihr Prüfwert vorher auf jedem. |
| Regeln aus dem CrowdSec Hub | Lädt ein Server einen neuen Stand, übernehmen ihn die anderen von ihm, nach denselben Prüfungen wie bei einem eigenen Download. Neue Regeln sperren auf allen Servern ab demselben Zeitpunkt. Setzt du die Hub-Regeln auf einem Server zurück, folgen die anderen: Jeder verwirft seinen heruntergeladenen Stand und läuft mit dem Stand aus seinem Image, bis ein Server neu heruntergeladen hat. |
| Limits und Szenarien | Jeder Server meldet den anderen einmal pro Sekunde, was er gezählt hat. Ein Limit gilt damit für den Cluster und nicht pro Server. |
| Verteilte Angriffe (Wellen) | Auch die Erkennung verteilter Angriffe zählt für den Cluster. Eine Welle ist auf jedem Server dieselbe, ihre Reaktion greift überall, und „Beenden“ im Dashboard beendet sie auf allen. |
| Ereignisse und Anfragen | Jeder Server hält auch die Ereignisse, Vorfälle und einzelnen Anfragen der anderen. Jedes Dashboard zeigt den ganzen Cluster. |
| Messwerte | Jeder Server hält auch die Messwerte der anderen. Zähler und Diagramme zeigen die Summe aller Server oder einen einzelnen (siehe [Zahlen und Diagramme im Cluster](#zahlen-und-diagramme-im-cluster)). |
| Löschung nach Art. 17 DSGVO | Eine gelöschte Adresse wird auf jedem Server gelöscht, auch auf einem, der gerade aus war und später zurückkommt. |

### Was bei einem Server bleibt

Ein paar Dinge beschreiben einen einzelnen Server und werden deshalb nicht geteilt:

- `schild.yaml`, `rules.d` und dein Caddyfile bleiben Dateien deines Deployments. Du verteilst sie wie bisher auf jeden Server.
- Jeder Server prüft sich im Server-Check selbst und hat eigene Befunde. Nimmst du einen Befund hin, gilt das für diesen Server.
- Das Protokoll der Agent-Aufrufe und die Angabe, wann ein Token zuletzt benutzt wurde, zeigen nur die Aufrufe, die dieser Server bedient hat. Was ein Agent geändert hat, steht als Ereignis auf jedem Server.
- Die Grenze für fehlgeschlagene Anmeldungen am Dashboard zählt pro Server.
- Was `schild firewall run` über die Firewall seines Hosts meldet, kennt nur das Gateway, das es gefragt hat. In der Liste der Sperren steht der Zustand der Firewall deshalb nur auf diesem Server.
- Die Werte von diesem Moment auf der Seite „Auslastung“ (Prozesse, Festplatten, Verbindungen), die Live-Ansicht im Sekundentakt und die Zähler unter „Schutzstatus“ zeigen den Server, dessen Dashboard du geöffnet hast.

## So ist ein Cluster aufgebaut

**Zwei Server.** Davor steht der Loadbalancer deines Hosters oder eine Floating-IP, die zum jeweils aktiven Server zeigt. Beide Server halten den vollen Stand. Eine dritte Maschine brauchst du nicht.

**Viele Server.** Davor stehen zwei oder mehr Balancer-VMs, zum Beispiel mit HAProxy im TCP-Modus. Sie verteilen die Verbindungen auf die Gateways. TLS endet auf den Gateways. Ein Cluster nimmt höchstens 16 Gateways und 8 Balancer-VMs auf.

Schild verschiebt selbst keine IP-Adresse und ist kein Loadbalancer. Das übernimmt dein Hoster, keepalived oder HAProxy.

Die Server sprechen über einen eigenen Port miteinander (`cluster.listen`), verschlüsselt mit TLS 1.3. Jeder Server hat einen eigenen Schlüssel, der den Server nie verlässt. Lege diesen Port in ein privates Netz. Schild lehnt eine öffentliche Adresse dafür ab, solange du sie nicht ausdrücklich erlaubst (`cluster.allow_public_listen`).

**Uhren.** Im Cluster gilt bei zwei Änderungen am selben Eintrag die spätere. Dafür brauchen die Server gleiche Uhren. Richte auf jedem Server eine Zeitsynchronisation ein, etwa chrony oder systemd-timesyncd.

## Einrichten mit einer Konfigurationsdatei

Das ist der Weg für ein Deployment, das dieselben Dateien auf jeden Server schreibt. Du rufst auf keinem Server einen Befehl auf.

1. Erzeuge einmal ein Cluster-Secret und lege es dort ab, wo dein Deployment Secrets hält:

   ```bash
   schild cluster secret
   ```

2. Lege das Secret auf jedem Server in eine Datei, die nur der Dienst lesen darf (Modus 0600).

3. Ergänze `schild.yaml` auf jedem Server:

   ```yaml
   cluster:
     enabled: true
     listen: "10.0.0.2:8790"                  # die private Adresse dieses Servers
     secret_file: /etc/schild/cluster.secret
     peers: ["10.0.0.1:8790", "10.0.0.2:8790", "10.0.0.3:8790"]
     name_from_host: true                     # jeder Server heißt wie sein Host
   ```

   Nur `listen` unterscheidet sich von Server zu Server. `peers` nennt alle Server und darf die eigene Adresse enthalten.

   Mit `name_from_host: true` heißt jeder Server im Cluster nach seinem Hostnamen (der Teil vor dem ersten Punkt). So unterscheidest du die Server im Dashboard, auch wenn `node_name` in der Datei überall gleich ist. Ohne diese Zeile heißt ein Server wie sein `node_name`. Dann muss dein Deployment jedem Server einen eigenen geben. Einen festen Namen setzt du mit `cluster.name`. Der Name gilt ab der Aufnahme in den Cluster. Um ihn später zu ändern, nimmst du den Server aus dem Cluster und lässt ihn neu hinein.

4. Starte Schild neu. Jeder Server nimmt sich beim Start selbst in den Cluster auf und findet die anderen. Die Reihenfolge ist egal. Beim ersten Aufbau startest du mindestens zwei Server: Ein neuer Server, der den Cluster noch nie erreicht hat, nimmt keine Anfragen an.

Das Secret lässt einen Server in den Cluster und kann sonst nichts. Wer es hat, kann einen Server aufnehmen. Behandle es deshalb wie ein Passwort.

## Einrichten von Hand

Ohne Secret-Datei läuft der Beitritt über Codes, die einmal gelten und nach einer Stunde verfallen.

```bash
# auf dem ersten Server
schild cluster init
sudo systemctl restart schild
schild cluster invite

# auf jedem weiteren Server, mit Adresse und Code aus der Ausgabe
schild cluster join 10.0.0.1:8790 CODE
sudo systemctl restart schild
```

## Server mit unterschiedlichen Einstellungen zusammenführen

Tritt ein Server einem Cluster bei, bringt er mit, was er hat. Seine eigenen Adressen, Freigaben, Limits und Einstellungen kommen zum Cluster dazu, und er übernimmt, was der Cluster hat.

Nur wenn beide Seiten denselben Eintrag haben, etwa denselben Schalter mit verschiedenen Werten, gilt der Wert des Clusters. Was der Server dazu selbst hatte, bewahrt Schild auf dem Server auf und nennt es in `schild cluster status`.

## Was der Loadbalancer braucht

**Prüfung, ob ein Server bereit ist.** Lass den Balancer `/.schild/readyz` auf den Web-Ports abfragen. Ein Server antwortet mit 503, solange er den Stand des Clusters noch nicht übernommen hat und während er anhält. Erreicht er zehn Sekunden lang keinen anderen Server, bedient er mit dem Stand, den er hat. Das gilt nur für einen Server, der schon einmal im Cluster abgeglichen war. Ein neuer Server, der den Cluster noch nie erreicht hat, bleibt auf 503, bis er einen anderen Server erreicht.

**Echte Adresse der Besucher:innen.** Hinter einem Balancer im TCP-Modus kommt die Adresse über das PROXY-Protokoll. In einem Cluster verlangt Schild dafür eine Liste erlaubter Absender im Caddyfile:

```caddyfile
{
	servers {
		listener_wrappers {
			proxy_protocol {
				allow 10.0.0.0/24
			}
			tls
		}
	}
}
```

Ohne diese Liste startet Schild in einem Cluster nicht. Sonst könnte jeder, der einen Server direkt erreicht, eine beliebige Adresse als seine ausgeben, und eine Sperre dieser Adresse gälte dann auf jedem Server.

**Die Prüfung muss sprechen wie der Traffic.** Schickt der Balancer den Traffic mit PROXY-Protokoll, muss auch seine Prüfung es senden. Sonst lehnt der Server die Prüfung ab und gilt als ausgefallen.

**Beispiel für HAProxy, Website ohne TLS auf den Gateways.** So lief der Balancer in der Messung mit zwei und mit sechzehn Servern:

```haproxy
defaults
  mode tcp
  timeout connect 2s
  timeout client 60s
  timeout server 60s

frontend web80
  bind :80
  default_backend gateways80

backend gateways80
  balance roundrobin
  option httpchk
  http-check send meth GET uri /.schild/readyz ver HTTP/1.1 hdr Host www.example.org
  http-check expect status 200
  default-server send-proxy-v2 check inter 2s fall 2 rise 2
  server web-1 10.0.0.1:80
  server web-2 10.0.0.2:80
```

Fällt ein Server hart aus, schickt HAProxy ihm noch Verbindungen, bis die Prüfung ihn herausnimmt, in der Messung gut drei Sekunden lang. Mit `option redispatch` im Backend versucht HAProxy eine abgelehnte Verbindung auf einem anderen Server. Das war in der Messung nicht gesetzt und ist deshalb nicht gemessen.

**Wenn TLS auf den Gateways endet.** Dann verhalten sich die beiden Ports verschieden:

- Port 80 leitet nur auf HTTPS um und beantwortet die Prüfung der Zertifizierungsstelle. Er nimmt kein PROXY-Protokoll an, und `/.schild/readyz` beantwortet er mit einer Umleitung. Schick den Traffic dorthin ohne PROXY-Protokoll und prüfe nur, ob der Port offen ist.
- Port 443 nimmt das PROXY-Protokoll an. Die Bereitschaft gibt es nur hier, über TLS und mit dem Namen der Website. Ein neuer Server besteht diese Prüfung erst, wenn er sein Zertifikat hat. Im Cluster bekommt er es beim ersten Abgleich von den anderen.

```haproxy
backend gateways80
  balance roundrobin
  default-server check inter 1s fall 2 rise 1
  server web-1 10.0.0.1:80
  server web-2 10.0.0.2:80

backend gateways443
  balance roundrobin
  option httpchk
  http-check send meth GET uri /.schild/readyz ver HTTP/1.1 hdr Host www.example.org
  http-check expect status 200
  default-server send-proxy-v2 check check-ssl verify none check-sni www.example.org check-alpn http/1.1 inter 1s fall 2 rise 1
  server web-1 10.0.0.1:443
  server web-2 10.0.0.2:443
```

Die Zertifizierungsstelle kann einen Namen über Port 443 oder über Port 80 prüfen. Die Prüfung über Port 443 kommt hinter einem Balancer mit PROXY-Protokoll nicht an. In der Messung scheiterte sie, und der Server bestellte danach ein zweites Mal über Port 80. Schalte sie deshalb im Caddyfile der Website ab, dann bleibt es bei einer Bestellung über Port 80. In der Messung mit dieser Einstellung gab es in fünf von fünf Läufen genau eine Bestellung, auch wenn zwei Server gleichzeitig starteten:

```caddyfile
www.example.org {
	tls {
		issuer acme {
			disable_tlsalpn_challenge
		}
	}
	# ... der Rest der Website wie bisher
}
```

**Verteilung.** Verteilt der Balancer nach der Adresse der Besucher:innen, landet ein Client immer auf demselben Server. Dann zählen Limits genau. Mit reihum verteilten Verbindungen zählen sie mit etwa einer Sekunde Verzug.

## Sperren schon vor den Gateways

Hinter einem Balancer mit PROXY-Protokoll kommen alle Pakete vom Balancer. Die Firewall auf dem Gateway selbst (`schild firewall run`) kann gesperrte Adressen dort nicht erkennen. Der richtige Ort ist die Balancer-VM. Das geht nur mit einer eigenen VM, auf der du Programme starten kannst, nicht mit dem fertigen Loadbalancer eines Hosters.

Eine Balancer-VM tritt dem Cluster als Edge bei. Sie bekommt nur die Liste gesperrter Adressen mit ihrem Ende. Ereignisse, Einstellungen, Logins, Zertifikate und Schlüssel erreichen sie nie.

```bash
# auf einem Gateway
schild cluster invite -role edge

# auf der Balancer-VM, mit Adresse und Code aus der Ausgabe
schild cluster join 10.0.0.1:8790 CODE -edge -name lb-1 -data /var/lib/schild-edge
schild firewall run -group -data /var/lib/schild-edge
```

Jede Sperre endet in der Firewall von selbst, auch wenn die VM kein Gateway mehr erreicht. Wie bei der Firewall auf einem Gateway betrifft sie nur die Ports 80 und 443.

Eine Edge lässt sich nur mit einem Code aufnehmen, nie mit dem Cluster-Secret. Das Secret gehört nicht auf eine Balancer-VM.

## Den Stand prüfen

```bash
schild cluster status
```

Die Ausgabe nennt jedes Mitglied mit Rolle, Adresse, Zustand und letztem Kontakt, dazu die Zahl laufender Sperren und geteilter Einstellungen. Sie zeigt, was der laufende Server in den letzten fünf Sekunden festgehalten hat.

Dasselbe zeigt das Dashboard. Oben auf jeder Seite steht, ob der Server allein läuft („Einzelner Server“) oder Teil eines Clusters ist („Cluster · 3 Server“). Ein Klick darauf öffnet die Seite „Cluster“.

### Die Seite „Cluster“

Oben stehen die Summen: wie viele Server bereit sind, wie viele Anfragen der Cluster pro Sekunde bedient, wie viele Sperren laufen und wie viele Balancer-VMs dazugehören.

Darunter zeigt eine Karte das Internet und alle Gateways nebeneinander, jedes mit dem Internet verbunden. Kein Gateway steht über einem anderen, weil der Cluster keinen Hauptserver hat. Ab neun Gateways sind die Kästen schmal und hochkant beschriftet, damit auch 16 in eine Reihe passen. Die Linie eines Gateways ist grün, wenn es Anfragen annimmt, und orange gestrichelt, wenn es gerade keine annimmt oder von diesem Server aus nicht erreichbar ist. Ein Klick auf einen Server öffnet seine Details.

Unter der Karte steht jedes Gateway als eigene Karte, ab sieben Gateways als Zeile einer Tabelle. Die Details eines Servers nennen:

- ob er Anfragen annimmt, angehalten wird oder noch nicht bereit ist. Das ist die Antwort, die er dem Loadbalancer auf `/.schild/readyz` gibt.
- Anfragen pro Sekunde, den Anteil gestoppter Anfragen und die Antwortzeit der letzten Minute.
- CPU, Arbeitsspeicher und Festplatte. Ab 80 % wird der Balken orange, ab 95 % rot.
- Start, letzten Kontakt, Rückstand, Version, Uhr, Stand und Konfiguration.

Balancer-VMs stehen darunter für sich, mit ihrer letzten Abfrage und der Zahl der Adressen in ihrer Firewall.

Jeder Server meldet diese Zahlen alle fünf Sekunden an die anderen. Die Seite zeigt, was dieser Server zuletzt gehört hat, und fragt dafür keinen anderen. Erreicht er einen Server nicht, steht dort „Nicht erreichbar“ ohne Zahlen. Ob jener Server trotzdem Besucher:innen bedient, ist von hier aus nicht zu sehen. Die Zahlen dienen nur der Anzeige, kein Server entscheidet danach.

| Anzeige | Bedeutung |
| --- | --- |
| Abgleich aktiv | Der Server erreicht alle anderen Gateways. |
| Abgleich eingeschränkt | Mindestens ein Gateway ist nicht erreichbar. Mit den übrigen läuft der Abgleich weiter. |
| Abgleich unterbrochen | Der Server erreicht kein anderes Gateway und arbeitet mit dem letzten Stand weiter. |
| Abgleich pausiert | Auf dem Server wurde `schild cluster pause` aufgerufen. |
| Aus dem Cluster entfernt | Ein Mitglied hat dem Server gemeldet, dass er entfernt wurde. |

### Hinweise

Erreicht ein Server einen anderen nicht, weicht eine Konfiguration oder ein Stand ab oder geht eine Uhr auseinander, zeigt das Dashboard jedes Servers das unter „Einstellungen“ an, mit einem Link zur Seite „Cluster“. Die Startseite zeigt dann „Grundschutz aktiv“ mit dem Zusatz „Eingeschränkt“.

**Gleicher Stand.** Die Server prüfen gegenseitig, ob bei ihnen dasselbe gilt. Jedes Gateway bildet eine Prüfsumme über seine Sperren, seine Einstellungen, seine Freigaben und seine Logins und nennt sie den anderen alle fünf Sekunden. Aus der Prüfsumme lässt sich nichts über den Inhalt lesen. Zu jeder Prüfsumme nennt das Gateway, auf welchem Stand der Einträge es sie gebildet hat. Zwei Server vergleichen ihre Prüfsummen nur, wenn beide auf demselben Stand waren. Eine Änderung, die gerade unterwegs ist, gilt deshalb nie als Abweichung, auch nicht, wenn laufend Änderungen kommen, etwa viele Sperren während eines Angriffs. Auf der Seite „Cluster“ steht bei jedem Server unter „Stand“, ob er gleich ist oder in welchem Bereich er abweicht. „Weicht ab“ heißt: Beide Server halten dieselben Einträge, und trotzdem gilt bei ihnen nicht dasselbe. Konnten zwei Server eine Minute lang nicht verglichen werden, weil ohne Pause Änderungen kamen oder einer zurückliegt, steht dort „unbekannt“. Bleibt eine Abweichung 30 Sekunden stehen, erscheint ein Hinweis, und der Server gleicht von selbst neu ab: Er fragt den anderen Server noch einmal nach allem und wendet den Stand des Clusters erneut an. Das geschieht höchstens einmal pro Minute. Bleibt der Hinweis stehen, nennt das Server-Log den Grund, zum Beispiel eine Einstellung, die nicht zur `schild.yaml` dieses Servers passt.

**Unterschiedliche Konfiguration.** Jedes Gateway nennt den anderen alle fünf Sekunden eine Prüfsumme seiner Konfiguration: `schild.yaml` ohne `node_name`, `cluster.name`, `cluster.listen` und `cluster.advertise`, dazu `rules.d`. Weicht ein Server ab, steht das in seiner Karte und als Hinweis. Schild verteilt keine Konfiguration, das bleibt Aufgabe deines Deployments. Das Caddyfile geht in die Prüfsumme noch nicht ein.

**Uhren.** Jedes Gateway nennt den anderen alle fünf Sekunden seine Uhrzeit. Auf der Seite „Cluster“ steht bei jedem Server, wie weit seine Uhr von der dieses Servers abweicht. `schild cluster status` nennt einen Server ab fünf Sekunden Abstand, und ein Server schreibt in sein Log, wenn er einen Eintrag wegen der Uhr zurückstellt. Ab zehn Sekunden erscheint ein Hinweis. Einen Eintrag, dessen Uhrzeit mehr als 60 Sekunden voraus liegt, nimmt kein Server an.

**Ein Server mit falscher Uhr nimmt keine Anfragen mehr an.** Erreicht ein Server mindestens zwei andere, die sich über die Uhrzeit einig sind, und weicht seine eigene Uhr um eine Minute oder mehr davon ab, meldet er sich als nicht bereit. In der Messung mit drei Servern dauerte das etwa vier Sekunden. Der Loadbalancer schickt ihm dann nichts mehr. Das steht als Hinweis in seinem Dashboard, in `schild cluster status` und im Log. Sobald die Uhr stimmt, nimmt er von selbst wieder Anfragen an. Bei nur zwei Servern kann keiner wissen, wessen Uhr falsch geht. Dann bedienen beide weiter, und das Dashboard nennt den Abstand.

In der Liste gesperrter Adressen steht bei jeder Sperre, welcher Server sie entschieden hat. Löschst du unter „Datenschutz“ eine Adresse, nennt das Dashboard die Server, die die Löschung schon erreicht hat, und die, bei denen sie noch aussteht.

## Zahlen und Diagramme im Cluster

Jeder Server hält auch die Messwerte der anderen. Deshalb zeigen Zähler und Diagramme auf jedem Dashboard die Summe aller Server: Anfragen, gestoppte Anfragen, Antwortzeiten, die Ranglisten nach Pfad, Land oder Netz.

Oben auf jeder Seite steht der Filter „Zahlen von“. „Alle Server“ ist die Vorgabe. Wählst du einen Server, zeigen Zähler und Diagramme nur ihn. Das geht auch für einen Server, der gerade aus ist: Seine Werte bis zum Ausfall liegen auf den anderen. Die Listen der Ereignisse und Anfragen zeigen immer alle Server.

Liegt von einem Server seit 30 Sekunden nichts vor, fehlen seine Werte ab diesem Zeitpunkt. Das Dashboard nennt den Server und die Uhrzeit: „Daten von web-3 fehlen seit …“. Die Summen sind ab da ohne diesen Server.

Die Messwerte der anderen Server liegen unter `metrics-nodes` im Datenverzeichnis, eine Datei je Server, mit denselben Fristen wie die eigenen Messwerte (`monitoring.keep`). Jede dieser Dateien kann so groß werden wie die eigene `metrics.db`. In der Messung mit sechzehn Servern belegten die Messwerte der fünfzehn anderen nach zehn Minuten zusammen 28,5 MiB. Nimmst du einen Server aus dem Cluster, löschen die anderen seine Messwerte.

## Was ein Server beim Start übernimmt

Ein Server, der startet oder zurückkommt, holt zuerst Sperren, Einstellungen, eigene Adressen, Logins und Löschungen. Danach übernimmt er von einem anderen Server die laufenden Zähler: wie viel jeder Client von einem Limit verbraucht hat, was die Szenarien in ihren Zeitfenstern gezählt haben und was die Erkennung verteilter Angriffe gelernt hat. Erst dann meldet er sich beim Balancer als bereit. So gilt ein Client, dem ein Fehlversuch bis zur Sperre fehlt, auch auf dem frisch gestarteten Server als kurz vor der Sperre. In der Messung mit einem Limit von 60 Anfragen und einem Neustart mittendrin griff das Limit hinter dem Balancer bei 57 bis 61 Anfragen, ohne Neustart bei 60 bis 62.

Gelingt die Übernahme der Zähler nach drei Versuchen nicht, bedient der Server trotzdem. Seine Zähler beginnen dann bei null, und sein Dashboard zeigt einen Hinweis. Sperren, Einstellungen und Logins hat er in jedem Fall.

Ereignisse und Vorfälle der anderen folgen in den Sekunden nach dem Start. Die einzelnen Anfragen, die die anderen inzwischen bedient haben, holt der Server im Hintergrund nach. Das geschieht von selbst, egal wie lange er weg war. Du musst nichts anstoßen.

## Wenn ein Server ausfällt

- Verbindungen, die auf dem ausgefallenen Server endeten, brechen ab. Anfragen, die dort gerade liefen, schlagen fehl. Kein Loadbalancer und kein Proxy kann eine laufende TLS-Verbindung auf einen anderen Server umziehen.
- Neue Verbindungen gehen an die anderen Server, sobald der Balancer den Ausfall bemerkt.
- Die anderen Server bemerken einen Ausfall sofort, einen hängenden Server nach etwa drei Sekunden.
- Sperren, Einstellungen, Logins und Zertifikate liegen auf jedem Server. Es geht nichts verloren.
- Was der ausgefallene Server an Ereignissen und Vorfällen geschrieben hat, zeigen die anderen weiter an, bis auf die letzte Sekunde vor dem Ausfall.

## Einen Server geplant anhalten

Für ein Update oder eine Wartung:

```bash
schild cluster drain
```

Der Server antwortet dem Balancer sofort mit 503 und bedient noch 15 Sekunden lang, was ankommt. So schickt der Balancer neue Verbindungen woanders hin, bevor eine einzige abgewiesen wird. Ein Balancer im TCP-Modus lässt offene Verbindungen aber auf ihrem Server. Deshalb bittet der Server in diesen 15 Sekunden mit jeder Antwort darum, die Verbindung zu schließen (`Connection: close`, bei HTTP/2 ein GOAWAY). Ein Client, der danach eine neue Verbindung öffnet, landet auf einem anderen Server. Ein Client, der die Bitte übergeht, verliert seine nächste Anfrage auf dieser Verbindung. Eine Verbindung, auf der in dieser Zeit keine Anfrage kommt, endet mit dem Server. Dann hält Schild an und gibt laufenden Anfragen 30 Sekunden, um fertig zu werden. `systemctl stop schild` macht dasselbe. Nach der Wartung startest du den Server mit `systemctl start schild` wieder.

Beide Zeiten stellst du unter `cluster.drain` ein (`delay_s`, `grace_s`). `delay_s` sollte länger sein als das Prüfintervall deines Balancers mal die Zahl der Fehlversuche, nach denen er einen Server herausnimmt.

## Einen Server aus dem Cluster nehmen

```bash
schild cluster remove web-3
```

Danach spricht kein Mitglied mehr mit diesem Server, und keines nimmt an, was er noch schickt. Das gilt auch, wenn der Server das Cluster-Secret hat. Der entfernte Server erfährt es und schreibt es in sein Log. Er bedient mit seinem letzten Stand weiter, bis du bei ihm `cluster.enabled: false` setzt oder ihn abschaltest. Tragen zwei Server denselben Namen, nennst du statt des Namens die Kennung aus `schild cluster status`.

## Das Cluster-Secret wechseln

Ist das Cluster-Secret bekannt geworden, ersetzt du es. Wer das alte Secret hat, kommt danach nicht mehr in den Cluster.

1. Erzeuge ein neues Secret mit `schild cluster secret`.
2. Schreibe es auf jedem Server in die Datei aus `cluster.secret_file`.
3. Starte die Server nacheinander neu.

Mehr ist nicht zu tun, du löschst kein Verzeichnis. Ein Server, der mit dem neuen Secret startet, wechselt von selbst in den neuen Cluster. Er behält seinen Schlüssel und nimmt mit, was er im alten Cluster hielt: laufende Sperren und Freigaben, Einstellungen, eigene Adressen, Logins, Löschungen nach Art. 17, Zertifikate und den Stand der Aufgaben. Das alte Verzeichnis legt er daneben ab (`cluster.replaced-<Zeit>`). Die zwei neuesten bleiben liegen, ältere räumt er weg.

Während des Wechsels gibt es zwei Cluster nebeneinander: Die Server, die schon neu gestartet sind, bilden den neuen, die übrigen den alten. Die beiden tauschen nichts aus. Das hat vier Folgen:

- Eine Sperre oder Einstellung, die du in dieser Zeit auf einem Server des alten Clusters setzt, gilt im neuen erst, wenn dieser Server folgt. Er bringt sie dann mit.
- Ändern beide Seiten denselben Eintrag, gilt am Ende die spätere Änderung. Eine Freigabe schlägt die ältere Sperre, eine Löschung bleibt eine Löschung.
- Limits und Szenarien zählen in dieser Zeit je Cluster, nicht über alle Server.
- Der erste Server im neuen Cluster wartet bis zu zehn Sekunden auf die anderen, bevor er sich als bereit meldet. Die Dashboards zeigen die Server des jeweils anderen Clusters als nicht erreichbar.

Halte den Wechsel deshalb kurz, am besten wenige Minuten.

Zwei Arten von Mitgliedern wechseln nicht von selbst:

- Balancer-VMs und von Hand aufgenommene Server haben kein Secret. Nimm sie mit einem neuen Code in den neuen Cluster auf (`schild cluster invite`). Eine Balancer-VM hält ihre alte Mitgliedschaft in ihrem Datenverzeichnis und lehnt den Beitritt sonst ab („this node belongs to a group already“). Halte dort zuerst `schild firewall run` an, leere das Datenverzeichnis, tritt mit dem neuen Code bei und starte die Firewall wieder.
- Wer im alten Cluster entfernt war und das neue Secret bekommt, ist im neuen Cluster wieder Mitglied, bringt aber nichts mit. Gib einem Server, der draußen bleiben soll, das neue Secret nicht.

Ein Secret, das fehlt, zu kurz ist oder von anderen lesbar ist, ändert nichts. Der Server bleibt Mitglied seines Clusters, läuft aber allein, bis die Datei stimmt, und schreibt den Grund ins Log.

## Wenn im Cluster etwas Falsches unterwegs ist

Eine Änderung erreicht jeden Server in etwa einer Sekunde, eine falsche auch. Für diesen Fall gibt es eine Notbremse:

```bash
schild cluster pause
```

Der Server bedient weiter mit dem Stand, den er hat. Er nimmt nichts mehr aus dem Cluster an und gibt nichts weiter. Was du währenddessen auf ihm änderst, wartet. Mit `schild cluster resume` nimmt er wieder teil und holt nach, was er verpasst hat.

## Aufgaben, die nur einmal laufen dürfen

Manche Aufgaben sollen im Cluster einmal laufen und nicht einmal pro Server, zum Beispiel das Erneuern der Schlüssel der Browser-Prüfung oder später eine Zusammenfassung per E-Mail. Dafür gibt es keinen Haupt-Server. Die Aufgabe übernimmt jeweils der erreichbare Server mit der kleinsten Kennung. Fällt er aus, übernimmt der nächste von selbst.

Was eine Aufgabe schon erledigt hat, weiß jeder Server: wann sie zuletzt gestartet ist, für welchen Zeitraum sie läuft, ob sie fertig wurde und welche einzelnen Schritte erledigt sind. Daraus folgt:

- Ein Server, der übernimmt oder neu startet, führt eine fertige Aufgabe nicht noch einmal aus.
- Bricht eine Aufgabe mittendrin ab, weil der Server ausfällt oder ein Schritt fehlschlägt, nimmt der zuständige Server sie nach einer Wartezeit wieder auf. Er erledigt dann nur die Schritte, die noch fehlen. Die Wartezeit beträgt zwei Minuten, wenn die Aufgabe nichts anderes festlegt.
- Eine Aufgabe mit fester Uhrzeit läuft in der Zeitzone, die du einstellst, auch über die Zeitumstellung hinweg. Eine Uhrzeit, die es an einem Tag nicht gibt, fällt auf die nächste Minute, die es gibt. Eine Uhrzeit, die es zweimal gibt, zählt einmal.
- War zur fälligen Zeit kein Server in Betrieb, läuft die Aufgabe einmal nach, sobald wieder einer läuft und der Zeitraum noch der aktuelle ist. Ältere Zeiträume werden nicht nachgeholt.
- Änderst du die Uhrzeit einer Aufgabe, läuft sie für einen Tag, an dem sie schon gelaufen ist, kein zweites Mal.

Eine Grenze bleibt: Eine Aufgabe läuft mindestens einmal, aber nicht garantiert genau einmal. Erreichen sich die Server nicht, kann sie auf beiden Seiten laufen. Fällt ein Server genau zwischen einem Schritt und dessen Vermerk aus, wiederholt der nächste Server diesen einen Schritt. Eine E-Mail kann in diesen Fällen doppelt ankommen. Für die Schlüssel der Browser-Prüfung ist das unkritisch.

Die ersten Schlüssel der Browser-Prüfung in einem neuen Cluster sind ein Sonderfall. Jeder Server erzeugt beim ersten Start eigene Schlüssel und arbeitet zunächst damit. Für den Cluster gibt nur ein Server seine Schlüssel weiter, nämlich der erreichbare Server mit der kleinsten Kennung, nachdem er das drei Sekunden lang war. Die anderen übernehmen sie. Sieht ein Server zehn Sekunden lang keine Schlüssel des Clusters, gibt er seine eigenen weiter. In einem neuen Cluster ist die Browser-Prüfung noch für keine Website eingeschaltet, deshalb bemerkt in diesen Sekunden niemand etwas.

Ein einzelnes Gateway führt dieselben Aufgaben nach denselben Regeln aus. Es erneuert die Schlüssel der Browser-Prüfung deshalb jetzt auch im laufenden Betrieb und nicht mehr nur beim Start.

## Daten und Datenschutz

Ein Cluster ist ein Betreiber. In einem Cluster hält jeder Server auch die Ereignisse und Anfragen der anderen, mit den Adressen der Besucher:innen. Sie reisen nur zwischen deinen eigenen Servern, über die verschlüsselte Verbindung des Clusters. Nenne in deiner Datenschutzerklärung jeden Server als Ort der Verarbeitung.

Jeder Server wendet seine eigenen Aufbewahrungsfristen und Größengrenzen auf alles an, was er hält. Eine Löschung nach Art. 17 gilt auf jedem Server.

Jeder Server speichert damit, was der ganze Cluster aufzeichnet. Das lässt sich nicht abschalten: Alle Server sollen denselben Stand haben. Plane den Speicherplatz jedes Servers für die Daten des ganzen Clusters. Eine Obergrenze, die einem einzelnen Gateway für zwei Tage reicht, ist bei zehn Servern mit gleichem Traffic nach etwa fünf Stunden erreicht.

## Grenzen

- **Gemessen, nicht im Betrieb erprobt.** Alle Messungen liefen mit Prozessen oder virtuellen Servern auf einem Rechner. Gemessen sind dort ein HAProxy mit PROXY-Protokoll vor zwei und vor sechzehn Gateways, Zertifikate hinter dem Balancer mit einer Test-Zertifizierungsstelle, ein Update Server für Server, Störungen im Netz und falsche Uhren. Echte Server in einem echten Netz, der fertige Loadbalancer eines Hosters, eine echte Zertifizierungsstelle, 2 000 Zertifikate und tagelange Last sind nicht gemessen. Sechzehn Gateways ohne Besucher:innen brauchten in der Messung je etwa 7 % eines Prozessorkerns.
- **Dieselbe Einstellung auf zwei Servern geändert.** Änderst du denselben Schalter oder denselben Eintrag gleichzeitig auf zwei Servern, gilt überall die spätere Änderung. Verschiedene Einträge derselben Liste bleiben beide erhalten, auch wenn sich die Server zwischendurch nicht erreicht haben.
- **Limits mit Verzug.** Ein Client, der seine Anfragen über die Server verteilt, kommt um das hinaus, was die Server in einer Sekunde annehmen.
- **Wellen mit Verzug.** Wie bei den Limits vergeht bis zu einer Sekunde, bis die Server voneinander wissen. Eine Welle wird deshalb erkannt, sobald die Summe über der Schwelle liegt und die nächste passende Anfrage einen Server erreicht. Wie viele Anfragen eine Reaktion gestoppt hat, zählt jeder Server für sich.
- **Zähler beim Start.** Übernimmt ein startender Server die Zähler der anderen, kann er etwa eine Sekunde doppelt zählen. Ein Limit greift dann eher einen Moment zu früh als zu spät. In der Messung griff ein Limit nach einem Neustart zwischen drei Anfragen zu früh und einer zu spät.
- **Zahlen der anderen Server mit Verzug.** Diagramme und Zähler zeigen die anderen Server mit etwa 10 bis 20 Sekunden Verzug, bei Minutenwerten bis zu einer Minute mehr. Besucherzahlen aus mehreren Servern sind eine Untergrenze („mindestens“), weil dieselbe Person mehrere Server erreicht haben kann.
- **Einzelne Anfragen nach einem langen Ausfall.** Ein Server, der aus war, holt alle Anfragen nach, die die anderen inzwischen bedient haben, auch wenn einer von ihnen selbst neu gestartet ist. Die Grenze ist die Aufbewahrung der anderen Server: Was dort schon gelöscht ist (`monitoring.requests.keep_hours`, `monitoring.requests.max_size_mb`), kommt nicht mehr. Der Server schreibt dann in sein Log, dass ihm Anfragen fehlen.
- **Harter Absturz.** Stürzt ein Server ab, ohne sich zu beenden (Stromausfall, `kill -9`), fehlen ihm selbst die Anfragen seiner letzten Sekunde. Die anderen Server halten sie.
- **Sehr hohe Last.** Ein Server, der so ausgelastet ist, dass er mit dem Aufzeichnen nicht nachkommt, verwirft einen Teil der Anfragen, die er selbst bedient hat. Die anderen Server halten sie, ihm selbst fehlen sie danach. In den Messungen mit drei Servern auf einem Rechner trat das erst auf, wenn der Rechner die Last nicht mehr schaffte und einzelne Anfragen mit 503 beantwortete, zwischen 6 000 und 9 000 Anfragen pro Sekunde. Betroffen waren dann je nach Lauf zwischen 0,01 und 4 % der Anfragen eines Servers. Keine Anfrage der Besucher:innen scheiterte am Aufzeichnen, und Sperren und Limits griffen weiter.
- **Uhr mehr als eine Minute daneben.** Einträge eines Servers, dessen Uhr mehr als 60 Sekunden vorgeht, nehmen die anderen erst an, wenn ihre eigene Uhr so weit ist. Seine Anfragen zeichnen sie nicht auf. Ein Server, dessen Uhr so weit nachgeht, bleibt nach einem Neustart auf 503, bis er den Stand der anderen halten kann. Hat ein Server mit einer so weit vorgehenden Uhr etwas geschrieben, tragen die Einträge der anderen bis zu einer Minute lang eine Zeit, die ihrer eigenen Uhr voraus ist. In dieser Minute nimmt auch ein Server, dessen Uhr nur eine halbe Minute nachgeht, nichts an. In einem Cluster aus zwei Servern bleibt ein Server mit falscher Uhr im Traffic, weil keiner wissen kann, wessen Uhr falsch geht.
- **Sperre und Freigabeliste.** Steht eine Adresse schon auf der geteilten Liste eigener Adressen, bevor eine Sperre für sie ankommt, sperren die Gateways sie nicht. Für den Cluster aufgehoben wird die Sperre dadurch aber nicht. Eine Balancer-VM hält sie weiter in ihrer Firewall.
- **Zertifikate bei Netztrennung.** Erreichen sich die Server nicht, kann jede Seite dasselbe Zertifikat bestellen. Das ist eine Bestellung zu viel, beide Zertifikate sind gültig.
- **Aufgaben mindestens einmal.** Eine Aufgabe, die nur einmal laufen soll, kann bei einer Netztrennung oder einem Ausfall im falschen Moment zweimal laufen (siehe „Aufgaben, die nur einmal laufen dürfen“).
- **Wechsel des Secrets.** Solange nicht alle Server mit dem neuen Secret neu gestartet sind, laufen zwei Cluster nebeneinander (siehe „Das Cluster-Secret wechseln“). Balancer-VMs und von Hand aufgenommene Server nimmst du danach neu auf.
- **Höchstens 16 Gateways und 8 Balancer-VMs.** Mehr lehnt der Cluster ab. Ein abgelehnter Server nimmt keine Anfragen an.

## Befehle

| Befehl | Was er tut |
| --- | --- |
| `schild cluster secret` | Gibt ein neues Cluster-Secret aus. |
| `schild cluster status` | Zeigt Mitglieder, letzten Kontakt und den geteilten Stand. |
| `schild cluster drain` | Nimmt diesen Server aus dem Traffic und hält ihn an. |
| `schild cluster pause` und `resume` | Der Server bedient weiter, nimmt aber nichts aus dem Cluster an und gibt nichts weiter, bis du `resume` aufrufst. |
| `schild cluster remove NODE` | Beendet die Mitgliedschaft eines Servers, genannt mit Name oder Kennung. |
| `schild cluster init` | Macht diesen Server zum ersten eines neuen Clusters (von Hand). |
| `schild cluster invite [-role edge]` | Gibt einen Beitrittscode aus, einmal gültig, eine Stunde lang. |
| `schild cluster join ADRESSE CODE` | Tritt dem Cluster bei (von Hand). |
| `schild cluster join ADRESSE CODE -edge -name NAME -data DIR` | Eine Balancer-VM tritt als Edge bei. |
| `schild firewall run -group -data DIR` | Hält die Sperren des Clusters in der Firewall der Balancer-VM. |
