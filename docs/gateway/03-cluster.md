---
short: Cluster
description: "Mehrere Schild Gateways als Cluster betreiben: was sie teilen, wie du ihn mit einer Konfigurationsdatei oder von Hand einrichtest, was der Loadbalancer davor braucht, wie Sperren schon auf den Balancer-VMs greifen, was beim Ausfall eines Servers passiert und wo die Grenzen liegen."
---

# Mehrere Gateways als Cluster betreiben

**Status:** experimentell, noch in keinem Release enthalten · Stand 22.11.2026 · technische Quelle: [contracts/cluster.md](../../contracts/cluster.md) · unabhängig gemessen am 21.11.2026 mit drei Servern auf einem Rechner ([Bericht](../../tests/results/MVP-27-group-measurement.md)); was dort durchfiel, ist behoben, und der letzte Lauf desselben Messprogramms am 22.11.2026 bestand alle 92 bewerteten Prüfungen

**Kurz:**

- Ein Cluster sind mehrere Gateways eines Betreibers hinter einem Loadbalancer. Sie teilen ihren Stand direkt untereinander. Du betreibst keine Datenbank, keinen Cache und keine Queue daneben.
- Zwei Server reichen. Fällt einer aus, arbeitet der andere mit allem weiter, was der Cluster wusste.
- Geteilt werden Sperren, Einstellungen aus dem Dashboard, eigene Adressen, Logins, Zertifikate, die Zähler von Limits und Szenarien sowie Ereignisse und Anfragen.
- Keine Anfrage wartet auf einen anderen Server. Erreicht ein Server den Cluster nicht, entscheidet er mit seinem letzten Stand.
- Ohne `cluster.enabled` ändert sich nichts. Ein einzelnes Gateway bleibt, wie es ist.

## Wofür ein Cluster gut ist

Mit einem Gateway hängt deine Website an einem Server. Mit zwei oder mehr kannst du einen Server aktualisieren oder verlieren, ohne dass die Website ausfällt. Ein Hoster kann viele Websites hinter eine Reihe von Gateways stellen und Server dazunehmen, wenn der Traffic wächst.

Ohne Cluster wäre jedes Gateway für sich: Eine Sperre gälte nur auf einem Server, ein Limit zählte pro Server, und Besucher:innen müssten die Browser-Prüfung auf jedem Server neu bestehen.

## Was der Cluster teilt

| Was | Wie es sich verhält |
| --- | --- |
| Gesperrte Adressen | Eine Sperre aus einem Szenario, aus dem Dashboard oder von einem Agenten gilt nach etwa einer Sekunde auf jedem Server. „Freigeben“ hebt sie überall auf, auf jedem Server, sobald er die Sperre zeigt. |
| Einstellungen | Alles, was du im Dashboard oder über die Agent-API einstellst, gilt auf jedem Server: Schalter der Regelquellen, Schwellen, Limits, Crawler-Regeln, Zugriffssperre, Browser-Prüfung, Ausnahmen. Das gilt auch für Einstellungen künftiger Funktionen, ohne dass sie dafür etwas tun müssen. |
| Eigene Adressen und Freigaben | Die Liste eigener Adressen und freigegebene Absender gelten überall. Die eigene Liste eines Servers gewinnt immer gegen eine Sperre aus dem Cluster. |
| Logins | Ein Passwort und eine Anmeldung für das Dashboard jedes Servers. Agent-Tokens gelten auf allen. |
| Besucher:innen | Wer die Browser-Prüfung bestanden oder sich an der Zugriffssperre angemeldet hat, bleibt das auf dem nächsten Server. |
| Zertifikate | Eine Bestellung pro Zertifikat, solange sich die Server erreichen. Ein Server, der startet, bestellt erst, wenn er weiß, was der Cluster schon hat. Die Prüfung der Zertifizierungsstelle über HTTP landet auf einem beliebigen Server, deshalb liegt ihr Prüfwert vorher auf jedem. Mit einer echten Zertifizierungsstelle ist das bisher nur vor diesen Korrekturen gemessen. |
| Regeln aus dem CrowdSec Hub | Lädt ein Server einen neuen Stand, übernehmen ihn die anderen von ihm, nach denselben Prüfungen wie bei einem eigenen Download. Neue Regeln sperren auf allen Servern ab demselben Zeitpunkt. |
| Limits und Szenarien | Jeder Server meldet den anderen einmal pro Sekunde, was er gezählt hat. Ein Limit gilt damit für den Cluster und nicht pro Server. |
| Verteilte Angriffe (Wellen) | Auch die Erkennung verteilter Angriffe zählt für den Cluster. Eine Welle ist auf jedem Server dieselbe, ihre Reaktion greift überall, und „Beenden“ im Dashboard beendet sie auf allen. |
| Ereignisse und Anfragen | Jeder Server hält auch die Ereignisse, Vorfälle und einzelnen Anfragen der anderen. Jedes Dashboard zeigt den ganzen Cluster. |
| Löschung nach Art. 17 DSGVO | Eine gelöschte Adresse wird auf jedem Server gelöscht, auch auf einem, der gerade aus war und später zurückkommt. |

Nicht geteilt werden `schild.yaml`, `rules.d` und dein Caddyfile. Die verteilst du wie bisher mit deinem Deployment auf jeden Server.

## So ist ein Cluster aufgebaut

**Zwei Server.** Davor steht der Loadbalancer deines Hosters oder eine Floating-IP, die zum jeweils aktiven Server zeigt. Beide Server halten den vollen Stand. Eine dritte Maschine brauchst du nicht.

**Viele Server.** Davor stehen zwei oder mehr Balancer-VMs, zum Beispiel mit HAProxy im TCP-Modus. Sie verteilen die Verbindungen auf die Gateways. TLS endet auf den Gateways.

Schild verschiebt selbst keine IP-Adresse und ist kein Loadbalancer. Das übernimmt dein Hoster, keepalived oder HAProxy.

Die Server sprechen über einen eigenen Port miteinander (`cluster.listen`), verschlüsselt mit TLS 1.3. Jeder Server hat einen eigenen Schlüssel, der den Server nie verlässt. Lege diesen Port in ein privates Netz. Schild lehnt eine öffentliche Adresse dafür ab, solange du sie nicht ausdrücklich erlaubst.

## Einrichten mit einer Konfigurationsdatei

Das ist der Weg für ein Deployment, das dieselben Dateien auf jeden Server schreibt. Du rufst auf keinem Server einen Befehl auf.

1. Erzeuge einmal ein Cluster-Geheimnis und lege es dort ab, wo dein Deployment Geheimnisse hält:

   ```bash
   schild cluster secret
   ```

2. Lege das Geheimnis auf jedem Server in eine Datei, die nur der Dienst lesen darf (Modus 0600).

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

   Mit `name_from_host: true` heißt jeder Server im Cluster nach seinem Hostnamen (der Teil vor dem ersten Punkt). So unterscheidest du die Server im Dashboard, auch wenn `node_name` in der Datei überall gleich ist. Ohne diese Zeile heißt ein Server wie sein `node_name`; dann muss dein Deployment jedem Server einen eigenen geben. Einen festen Namen setzt du mit `cluster.name`. Der Name gilt ab der Aufnahme in den Cluster. Um ihn später zu ändern, nimmst du den Server aus dem Cluster und lässt ihn neu hinein.

4. Starte Schild neu. Jeder Server nimmt sich beim Start selbst in den Cluster auf und findet die anderen. Die Reihenfolge ist egal.

Das Geheimnis lässt einen Server in den Cluster und kann sonst nichts. Wer es hat, kann einen Server aufnehmen. Behandle es deshalb wie ein Passwort.

## Einrichten von Hand

Ohne Geheimnis-Datei läuft der Beitritt über Codes, die einmal gelten und nach einer Stunde verfallen.

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

**Prüfung, ob ein Server bereit ist.** Lass den Balancer `/.schild/readyz` auf den Web-Ports abfragen. Ein Server antwortet mit 503, solange er den Stand des Clusters noch nicht übernommen hat und während er anhält. Erreicht er zehn Sekunden lang keinen anderen Server, bedient er mit dem Stand, den er hat. Das gilt nur für einen Server, der schon einmal im Cluster abgeglichen war. Ein neuer Server, der den Cluster noch nie erreicht hat, bleibt auf 503, bis er einen anderen Server erreicht. Beim ersten Aufbau startest du deshalb mindestens zwei Server.

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

**Die Prüfung muss sprechen wie der Verkehr.** Schickt der Balancer den Verkehr mit PROXY-Protokoll, muss auch seine Prüfung es senden. Sonst lehnt der Server die Prüfung ab und gilt als ausgefallen.

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

- **Port 80** leitet nur auf HTTPS um und beantwortet die Prüfung der Zertifizierungsstelle. Er nimmt kein PROXY-Protokoll an, und `/.schild/readyz` beantwortet er mit einer Umleitung. Schick dorthin ohne PROXY-Protokoll und prüfe nur, ob der Port offen ist.
- **Port 443** nimmt das PROXY-Protokoll an. Die Bereitschaft gibt es nur hier, über TLS und mit dem Namen der Website. Ein neuer Server besteht diese Prüfung erst, wenn er sein Zertifikat hat. Im Cluster bekommt er es beim ersten Abgleich von den anderen.

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

**Verteilung.** Verteilt der Balancer nach der Adresse der Besucher:innen, landet ein Client immer auf demselben Server. Dann zählen Limits genau. Mit reihum verteilten Verbindungen zählen sie mit etwa einer Sekunde Verzug.

## Sperren schon vor den Gateways

Hinter einem Balancer mit PROXY-Protokoll kommen alle Pakete vom Balancer. Die Firewall auf dem Gateway selbst (`schild firewall run`) kann gesperrte Adressen dort nicht erkennen. Der richtige Ort ist die Balancer-VM.

Eine Balancer-VM tritt dem Cluster als Edge bei. Sie bekommt nur die Liste gesperrter Adressen mit ihrem Ende. Ereignisse, Einstellungen, Logins, Zertifikate und Schlüssel erreichen sie nie.

```bash
# auf einem Gateway
schild cluster invite -role edge

# auf der Balancer-VM, mit Adresse und Code aus der Ausgabe
schild cluster join 10.0.0.1:8790 CODE -edge -name lb-1 -data /var/lib/schild-edge
schild firewall run -group -data /var/lib/schild-edge
```

Jede Sperre endet in der Firewall von selbst, auch wenn die VM kein Gateway mehr erreicht. Wie bei der Firewall auf einem Gateway betrifft sie nur die Ports 80 und 443.

Eine Edge lässt sich nur mit einem Code aufnehmen, nie mit dem Cluster-Geheimnis. Das Geheimnis gehört nicht auf eine Balancer-VM.

## Aufgaben, die nur einmal laufen dürfen

Manche Aufgaben sollen im Cluster einmal laufen und nicht einmal pro Server, zum Beispiel das Erneuern der Schlüssel der Browser-Prüfung. Dafür gibt es keinen Haupt-Server. Die Aufgabe übernimmt jeweils der erreichbare Server mit der kleinsten Kennung. Fällt er aus, übernimmt der nächste von selbst.

Wann eine Aufgabe zuletzt lief, weiß jeder Server. Ein Server, der übernimmt oder neu startet, führt sie deshalb nicht noch einmal aus, bevor sie wieder fällig ist.

Erreichen sich die Server nicht, kann eine Aufgabe auf beiden Seiten laufen. Für die Schlüssel der Browser-Prüfung ist das unkritisch.

## Wenn ein Server ausfällt

- Verbindungen, die auf dem ausgefallenen Server endeten, brechen ab. Anfragen, die dort gerade liefen, schlagen fehl. Kein Loadbalancer und kein Proxy kann eine laufende TLS-Verbindung auf einen anderen Server umziehen.
- Neue Verbindungen gehen an die anderen Server, sobald der Balancer den Ausfall bemerkt.
- Die anderen Server bemerken einen Ausfall sofort, einen hängenden Server nach etwa drei Sekunden.
- Sperren, Einstellungen, Logins und Zertifikate liegen auf jedem Server. Es geht nichts verloren.
- Was der ausgefallene Server an Ereignissen und Vorfällen geschrieben hat, zeigen die anderen weiter an, bis auf die letzte Sekunde vor dem Ausfall.

Kommt der Server zurück, holt er Sperren, Einstellungen, eigene Adressen, Logins und Löschungen nach. Erst danach meldet er sich beim Balancer als bereit. Ereignisse und Vorfälle der anderen folgen in den Sekunden danach. Die einzelnen Anfragen, die die anderen inzwischen bedient haben, holt er im Hintergrund nach. Das geschieht von selbst, egal wie lange er weg war. Du musst nichts anstoßen.

## Was ein Server beim Start übernimmt

Ein Server, der startet, holt zuerst Sperren, Einstellungen, eigene Adressen, Logins und Löschungen. Danach übernimmt er von einem anderen Server die laufenden Zähler: wie viel jeder Client von einem Limit verbraucht hat, was die Szenarien in ihren Zeitfenstern gezählt haben und was die Erkennung verteilter Angriffe gelernt hat. Erst dann meldet er sich als bereit. So gilt ein Client, dem ein Fehlversuch bis zur Sperre fehlt, auch auf dem frisch gestarteten Server als kurz vor der Sperre.

Gelingt die Übernahme nach drei Versuchen nicht, bedient der Server trotzdem. Seine Zähler beginnen dann bei null, und die Startseite seines Dashboards sagt das. Sperren, Einstellungen und Logins hat er in jedem Fall.

## Einen Server geplant anhalten

Für ein Update oder eine Wartung:

```bash
schild cluster drain
```

Der Server antwortet dem Balancer sofort mit 503 und bedient noch 15 Sekunden lang, was ankommt. So schickt der Balancer neue Verbindungen woanders hin, bevor eine einzige abgewiesen wird. Ein Balancer im TCP-Modus lässt offene Verbindungen aber auf ihrem Server. Deshalb bittet der Server in diesen 15 Sekunden mit jeder Antwort darum, die Verbindung zu schließen (`Connection: close`, bei HTTP/2 ein GOAWAY). Ein Client, der danach eine neue Verbindung öffnet, landet auf einem anderen Server. Eine Verbindung, auf der in dieser Zeit keine Anfrage kommt, endet mit dem Server. Dann hält Schild an und gibt laufenden Anfragen 30 Sekunden, um fertig zu werden. `systemctl stop schild` macht dasselbe. Nach der Wartung startest du den Server mit `systemctl start schild` wieder.

Beide Zeiten stellst du unter `cluster.drain` ein. `delay_s` sollte länger sein als das Prüfintervall deines Balancers mal die Zahl der Fehlversuche, nach denen er einen Server herausnimmt.

## Einen Server aus dem Cluster nehmen

```bash
schild cluster remove web-3
```

Danach spricht kein Mitglied mehr mit diesem Server, und keines nimmt an, was er noch schickt. Das gilt auch, wenn der Server das Cluster-Geheimnis hat. Der entfernte Server erfährt es und schreibt es in sein Log. Er bedient mit seinem letzten Stand weiter, bis du bei ihm `cluster.enabled: false` setzt oder ihn abschaltest.

## Das Cluster-Geheimnis wechseln

Ist das Cluster-Geheimnis bekannt geworden, ersetzt du es. Wer das alte Geheimnis hat, kommt danach nicht mehr in den Cluster.

1. Erzeuge ein neues Geheimnis mit `schild cluster secret`.
2. Schreibe es auf jedem Server in die Datei aus `cluster.secret_file`.
3. Starte die Server nacheinander neu.

Mehr ist nicht zu tun, du löschst kein Verzeichnis. Ein Server, der mit dem neuen Geheimnis startet, wechselt von selbst in den neuen Cluster. Er behält seinen Schlüssel und nimmt mit, was er im alten Cluster hielt: laufende Sperren und Freigaben, Einstellungen, eigene Adressen, Logins, Löschungen nach Art. 17, Zertifikate und den Stand der Aufgaben. Das alte Verzeichnis legt er daneben ab (`cluster.replaced-<Zeit>`). Die zwei neuesten bleiben liegen, ältere räumt er weg.

Während des Wechsels gibt es zwei Cluster nebeneinander: Die Server, die schon neu gestartet sind, bilden den neuen, die übrigen den alten. Die beiden tauschen nichts aus. Das heißt:

- Eine Sperre oder Einstellung, die du in dieser Zeit auf einem Server des alten Clusters setzt, gilt im neuen erst, wenn dieser Server folgt. Er bringt sie dann mit.
- Ändern beide Seiten denselben Eintrag, gilt am Ende die spätere Änderung. Eine Freigabe schlägt die ältere Sperre, eine Löschung bleibt eine Löschung.
- Limits und Szenarien zählen in dieser Zeit je Cluster, nicht über alle Server.
- Der erste Server im neuen Cluster wartet bis zu zehn Sekunden auf die anderen, bevor er sich als bereit meldet. Die Dashboards zeigen die Server des jeweils anderen Clusters als nicht erreichbar.

Halte den Wechsel deshalb kurz, am besten wenige Minuten.

Nicht von selbst wechseln:

- **Balancer-VMs** und **von Hand aufgenommene Server**. Sie haben kein Geheimnis. Nimm sie mit einem neuen Code in den neuen Cluster auf (`schild cluster invite`).
- **Entfernte Server.** Wer im alten Cluster entfernt war und das neue Geheimnis bekommt, ist im neuen Cluster wieder Mitglied, bringt aber nichts mit. Gib einem Server, der draußen bleiben soll, das neue Geheimnis nicht.

Ein Geheimnis, das fehlt, zu kurz ist oder von anderen lesbar ist, ändert nichts. Der Server bleibt Mitglied seines Clusters, läuft aber allein, bis die Datei stimmt, und schreibt den Grund ins Log.

## Wenn im Cluster etwas Falsches unterwegs ist

Eine Änderung erreicht jeden Server in etwa einer Sekunde, eine falsche auch. Für diesen Fall gibt es eine Notbremse:

```bash
schild cluster pause
```

Der Server bedient weiter mit dem Stand, den er hat. Er nimmt nichts mehr aus dem Cluster an und gibt nichts weiter. Was du währenddessen auf ihm änderst, wartet. Mit `schild cluster resume` nimmt er wieder teil und holt nach, was er verpasst hat.

## Den Stand prüfen

```bash
schild cluster status
```

Die Ausgabe nennt jedes Mitglied mit Rolle, Adresse, Zustand und letztem Kontakt, dazu die Zahl laufender Sperren und geteilter Einstellungen.

Dasselbe zeigt das Dashboard. Oben auf jeder Seite steht, ob der Server allein läuft („Einzelner Server“) oder Teil eines Clusters ist („Cluster · 3 Server“). Die Karte „Cluster“ auf der Server-Seite nennt den Zustand des Abgleichs und jedes Gateway mit letztem Kontakt, Rückstand, Version und Konfiguration. Balancer-VMs stehen darunter für sich.

Ein Klick auf diese Anzeige öffnet die Seite „Cluster“. Oben zeigt eine Karte des Clusters das Internet und darunter alle Gateways nebeneinander, jedes mit dem Internet verbunden. Kein Gateway steht über einem anderen, weil der Cluster keinen Hauptserver hat. Ab neun Gateways sind die Kästen schmal und hochkant beschriftet, damit auch 16 in eine Reihe passen. Die Linie eines Gateways ist grün, wenn es Anfragen annimmt, und orange gestrichelt, wenn es gerade keine annimmt oder von diesem Server aus nicht erreichbar ist. Ein Klick auf einen Server öffnet seine Details.

Darunter steht jedes Gateway als Karte, ab sieben Gateways als Zeile einer Tabelle. Die Details nennen:

- **Nimmt Anfragen an, wird angehalten oder ist noch nicht bereit.** Das ist die Antwort, die der Server dem Loadbalancer auf `/.schild/readyz` gibt.
- **Anfragen pro Sekunde, Anteil gestoppter Anfragen und Antwortzeit** der letzten Minute.
- **CPU, Arbeitsspeicher und Festplatte.** Ab 80 % wird der Balken orange, ab 95 % rot.
- **Start, letzter Kontakt, Rückstand, Version und Konfiguration.**

Darüber stehen die Summen: wie viele Server bereit sind, wie viele Anfragen der Cluster pro Sekunde bedient, wie viele Sperren laufen und wie viele Balancer-VMs dazugehören.

Jeder Server meldet diese Zahlen alle fünf Sekunden an die anderen. Die Seite zeigt, was dieser Server zuletzt gehört hat, und fragt dafür keinen anderen. Erreicht er einen Server nicht, steht dort „Nicht erreichbar“ ohne Zahlen. Ob jener Server trotzdem Besucher:innen bedient, ist von hier aus nicht zu sehen. Die Zahlen dienen nur der Anzeige, kein Server entscheidet danach.

| Anzeige | Bedeutung |
| --- | --- |
| Abgleich aktiv | Der Server erreicht alle anderen Gateways. |
| Abgleich eingeschränkt | Mindestens ein Gateway ist nicht erreichbar. Mit den übrigen läuft der Abgleich weiter. |
| Abgleich unterbrochen | Der Server erreicht kein anderes Gateway und arbeitet mit dem letzten Stand weiter. |
| Abgleich pausiert | Auf dem Server wurde `schild cluster pause` aufgerufen. |
| Aus dem Cluster entfernt | Ein Mitglied hat dem Server gemeldet, dass er entfernt wurde. |

**Uhren.** Im Cluster gilt bei zwei Änderungen am selben Eintrag die spätere. Dafür brauchen die Server gleiche Uhren. Jedes Gateway nennt den anderen alle fünf Sekunden seine Uhrzeit. Auf der Seite „Cluster“ steht bei jedem Server, wie weit seine Uhr von der dieses Servers abweicht. `schild cluster status` nennt einen Server ab fünf Sekunden Abstand, und ein Server schreibt in sein Log, wenn er einen Eintrag wegen der Uhr zurückstellt. Ab zehn Sekunden steht ein Hinweis auf der Startseite. Richte auf jedem Server eine Zeitsynchronisation ein, etwa chrony oder systemd-timesyncd. Einen Eintrag, dessen Uhrzeit mehr als 60 Sekunden voraus liegt, nimmt kein Server an.

**Ein Server mit falscher Uhr nimmt sich selbst aus dem Verkehr.** Erreicht ein Server mindestens zwei andere, die sich über die Uhrzeit einig sind, und weicht seine eigene Uhr um eine Minute oder mehr davon ab, meldet er sich als nicht bereit. Der Loadbalancer schickt ihm dann nichts mehr. Das steht auf der Startseite seines Dashboards, in `schild cluster status` und im Log. Sobald die Uhr stimmt, nimmt er von selbst wieder Anfragen an. Bei nur zwei Servern kann keiner wissen, wessen Uhr falsch geht. Dann bedienen beide weiter, und das Dashboard nennt den Abstand.

**Hinweise auf der Startseite.** Erreicht ein Server einen anderen nicht, weicht eine Konfiguration ab oder geht eine Uhr auseinander, steht das auch auf der Startseite jedes Dashboards, mit einem Link zur Seite „Cluster“.

**Gleicher Stand.** Die Server prüfen gegenseitig, ob bei ihnen dasselbe gilt. Jedes Gateway bildet alle fünf Sekunden eine Prüfsumme über seine Sperren, seine Einstellungen, seine Freigaben und seine Logins und nennt sie den anderen. Aus der Prüfsumme lässt sich nichts über den Inhalt lesen. Auf der Seite „Cluster“ steht bei jedem Server unter „Stand“, ob er gleich ist oder in welchem Bereich er abweicht. Eine Abweichung von wenigen Sekunden ist eine Änderung, die gerade unterwegs ist, und wird nicht angezeigt. Weicht ein Server länger als 30 Sekunden ab, steht ein Hinweis auf der Startseite, und der Server gleicht von selbst neu ab: Er fragt den anderen Server noch einmal nach allem und wendet den Stand des Clusters erneut an. Das geschieht höchstens einmal pro Minute. Bleibt der Hinweis stehen, nennt das Server-Log den Grund, zum Beispiel eine Einstellung, die nicht zur `schild.yaml` dieses Servers passt.

**Unterschiedliche Konfiguration.** Jedes Gateway nennt den anderen alle fünf Sekunden eine Prüfsumme seiner Konfiguration: `schild.yaml` ohne `node_name`, `cluster.name`, `cluster.listen` und `cluster.advertise`, dazu `rules.d`. Weicht ein Server ab, steht das in der Karte. Das ist ein Hinweis. Schild verteilt keine Konfiguration, das bleibt Aufgabe deines Deployments. Das Caddyfile geht in die Prüfsumme noch nicht ein.

In der Liste gesperrter Adressen steht bei jeder Sperre, welcher Server sie entschieden hat. Löschst du unter „Datenschutz“ eine Adresse, nennt das Dashboard die Server, die die Löschung schon erreicht hat, und die, bei denen sie noch aussteht.

## Zahlen und Diagramme im Cluster

Jeder Server hält auch die Messwerte der anderen. Deshalb zeigen Zähler und Diagramme auf jedem Dashboard die Summe aller Server: Anfragen, gestoppte Anfragen, Antwortzeiten, die Ranglisten nach Pfad, Land oder Netz.

Oben auf jeder Seite steht der Filter „Zahlen von“. „Alle Server“ ist die Vorgabe. Wählst du einen Server, zeigen Zähler und Diagramme nur ihn. Das geht auch für einen Server, der gerade aus ist: Seine Werte bis zum Ausfall liegen auf den anderen. Die Listen der Ereignisse und Anfragen zeigen immer alle Server.

Erreicht ein Server einen anderen nicht, fehlen dessen Werte ab diesem Zeitpunkt. Das Dashboard nennt den Server und die Uhrzeit: „Daten von web-3 fehlen seit …“. Die Summen sind ab da ohne diesen Server.

Die Messwerte der anderen Server liegen unter `metrics-nodes` im Datenverzeichnis, eine Datei je Server, mit denselben Fristen wie die eigenen Messwerte (`monitoring.keep`). Plane den Platz dafür ein: bei zehn Servern das Zehnfache der eigenen `metrics.db`. Nimmst du einen Server aus dem Cluster, löschen die anderen seine Messwerte.

## Daten und Datenschutz

Ein Cluster ist ein Betreiber. In einem Cluster hält jeder Server auch die Ereignisse und Anfragen der anderen, mit den Adressen der Besucher:innen. Sie reisen nur zwischen deinen eigenen Servern, über die verschlüsselte Verbindung des Clusters. Nenne in deiner Datenschutzerklärung jeden Server als Ort der Verarbeitung.

Jeder Server wendet seine eigenen Aufbewahrungsfristen und Größengrenzen auf alles an, was er hält. Eine Löschung nach Art. 17 gilt auf jedem Server.

Jeder Server speichert damit, was der ganze Cluster aufzeichnet. Das lässt sich nicht abschalten: Alle Server sollen denselben Stand haben. Plane den Speicherplatz jedes Servers für die Daten des ganzen Clusters.

## Grenzen

- **Nur im Kleinen gemessen.** Eine unabhängige Messung lief mit drei Servern auf einem Rechner. Ein echter Loadbalancer, zehn Server, Zertifikate, gemischte Versionen und Lastspitzen sind nicht gemessen.
- **Dieselbe Einstellung auf zwei Servern geändert.** Änderst du denselben Schalter oder denselben Eintrag gleichzeitig auf zwei Servern, gilt überall die spätere Änderung. Verschiedene Einträge derselben Liste bleiben beide erhalten, auch wenn sich die Server zwischendurch nicht erreicht haben.
- **Limits mit Verzug.** Ein Client, der seine Anfragen über die Server verteilt, kommt um das hinaus, was die Server in einer Sekunde annehmen.
- **Einzelne Anfragen nach einem langen Ausfall.** Ein Server, der aus war, holt alle Anfragen nach, die die anderen inzwischen bedient haben, auch wenn einer von ihnen selbst neu gestartet ist. Die Grenze ist die Aufbewahrung der anderen Server: Was dort schon gelöscht ist (`monitoring.requests.keep_hours`, `monitoring.requests.max_size_mb`), kommt nicht mehr. Der Server schreibt dann in sein Log, dass ihm Anfragen fehlen. Unter hoher Last speichert ein Server nur einen Teil der Anfragen. Was er nicht gespeichert hat, kann er später auch nicht nachliefern.
- **Zahlen der anderen Server mit Verzug.** Diagramme und Zähler zeigen die anderen Server mit etwa 10 bis 20 Sekunden Verzug, bei Minutenwerten bis zu einer Minute mehr. Besucherzahlen aus mehreren Servern sind eine Untergrenze („mindestens“), weil dieselbe Person mehrere Server erreicht haben kann.
- **Was nicht geteilt wird.** Ein paar Dinge beschreiben einen einzelnen Server und bleiben deshalb bei ihm. Jeder Server prüft sich im Server-Check selbst und hat eigene Befunde. Nimmst du einen Befund hin, gilt das für diesen Server. Das Protokoll der Agent-Aufrufe und die Angabe, wann ein Token zuletzt benutzt wurde, zeigen nur die Aufrufe, die dieser Server bedient hat. Was ein Agent geändert hat, steht als Ereignis auf jedem Server. Die Grenze für fehlgeschlagene Anmeldungen am Dashboard zählt pro Server. `schild.yaml`, `rules.d` und das Caddyfile bleiben Dateien deines Deployments.
- **Regeln zurücksetzen.** Setzt du die CrowdSec-Hub-Regeln auf einem Server zurück, folgen die anderen Server: Jeder verwirft seinen heruntergeladenen Stand und läuft mit dem Stand aus seinem Image, bis ein Server neu heruntergeladen hat.
- **Pro Server bleiben** die Werte von diesem Moment auf der Seite „Auslastung“ (Prozesse, Festplatten, Verbindungen), die Live-Ansicht im Sekundentakt und die Zähler unter „Schutzstatus“. Sie zeigen den Server, dessen Dashboard du geöffnet hast.
- **Wellen mit Verzug.** Wie bei den Limits vergeht bis zu einer Sekunde, bis die Server voneinander wissen. Eine Welle wird deshalb erkannt, sobald die Summe über der Schwelle liegt und die nächste passende Anfrage einen Server erreicht. Wie viele Anfragen eine Reaktion gestoppt hat, zählt jeder Server für sich.
- **Zertifikate bei Netztrennung.** Erreichen sich die Server nicht, kann jede Seite dasselbe Zertifikat bestellen. Das ist eine Bestellung zu viel, beide Zertifikate sind gültig.
- **Wechsel des Geheimnisses.** Solange nicht alle Server mit dem neuen Geheimnis neu gestartet sind, laufen zwei Cluster nebeneinander (siehe „Das Cluster-Geheimnis wechseln“). Balancer-VMs und von Hand aufgenommene Server nimmst du danach neu auf.
- **Harter Absturz.** Stürzt ein Server ab, ohne sich zu beenden (Stromausfall, `kill -9`), fehlen ihm selbst die Anfragen seiner letzten Sekunde. Die anderen Server halten sie.
- **Sehr hohe Last.** In einer Messung mit drei Servern auf einem Rechner hielten alle Server bis 6 000 Anfragen pro Sekunde dieselben Anfragen. Darüber, mit ausgelastetem Rechner, fehlten jedem Server 3 bis 4 %. Keine Anfrage der Besucher:innen scheiterte daran, und Sperren und Limits griffen weiter.
- **Uhr mehr als eine Minute daneben.** Einträge eines Servers, dessen Uhr mehr als 60 Sekunden vorgeht, nehmen die anderen erst an, wenn ihre eigene Uhr so weit ist. Seine Anfragen zeichnen sie nicht auf. Ein Server, dessen Uhr so weit nachgeht, bleibt nach einem Neustart auf 503, bis er den Stand der anderen halten kann. Das Dashboard zeigt den Abstand ab zehn Sekunden an.
- **Höchstens 16 Gateways und 8 Balancer-VMs.** Mehr lehnt der Cluster ab. Im laufenden Betrieb erprobt sind bisher nur zwei und drei Gateways.

## Befehle

| Befehl | Was er tut |
| --- | --- |
| `schild cluster secret` | gibt ein neues Cluster-Geheimnis aus |
| `schild cluster status` | Mitglieder, letzter Kontakt, geteilter Stand |
| `schild cluster drain` | nimmt diesen Server aus dem Traffic und hält ihn an |
| `schild cluster pause` und `resume` | der Server bedient weiter, nimmt aber nichts aus dem Cluster an und gibt nichts weiter, bis du `resume` aufrufst |
| `schild cluster remove NODE` | beendet die Mitgliedschaft eines Servers |
| `schild cluster init` | macht diesen Server zum ersten eines neuen Clusters (von Hand) |
| `schild cluster invite [-role edge]` | gibt einen Beitrittscode aus, einmal gültig, eine Stunde lang |
| `schild cluster join ADRESSE CODE` | tritt dem Cluster bei (von Hand) |
| `schild cluster join ADRESSE CODE -edge -name NAME -data DIR` | Balancer-VM tritt als Edge bei |
| `schild firewall run -group -data DIR` | hält die Sperren des Clusters in der Firewall der Balancer-VM |
