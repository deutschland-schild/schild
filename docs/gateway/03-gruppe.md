---
short: Gruppe
description: "Mehrere Schild Gateways als Gruppe betreiben: was sie teilen, wie du sie mit einer Konfigurationsdatei oder von Hand einrichtest, was der Loadbalancer davor braucht, wie Sperren schon auf den Balancer-VMs greifen, was beim Ausfall eines Servers passiert und wo die Grenzen liegen."
---

# Mehrere Gateways als Gruppe betreiben

**Status:** experimentell, noch in keinem Release enthalten · Stand 22.11.2026 · technische Quelle: [contracts/cluster.md](../../contracts/cluster.md) · unabhängig gemessen am 21.11.2026 mit drei Servern auf einem Rechner ([Bericht](../../tests/results/MVP-27-group-measurement.md)); was dort durchfiel, ist behoben, und der letzte Lauf desselben Messprogramms am 22.11.2026 bestand 90 von 92 bewerteten Prüfungen (offen: siehe Grenzen)

**Kurz:**

- Eine Gruppe sind mehrere Gateways eines Betreibers hinter einem Loadbalancer. Sie teilen ihren Stand direkt untereinander. Du betreibst keine Datenbank, keinen Cache und keine Queue daneben.
- Zwei Server reichen. Fällt einer aus, arbeitet der andere mit allem weiter, was die Gruppe wusste.
- Geteilt werden Sperren, Einstellungen aus dem Dashboard, eigene Adressen, Logins, Zertifikate, die Zähler von Limits und Szenarien sowie Ereignisse und Anfragen.
- Keine Anfrage wartet auf einen anderen Server. Erreicht ein Server die Gruppe nicht, entscheidet er mit seinem letzten Stand.
- Ohne `cluster.enabled` ändert sich nichts. Ein einzelnes Gateway bleibt, wie es ist.

## Wofür eine Gruppe gut ist

Mit einem Gateway hängt deine Website an einem Server. Mit zwei oder mehr kannst du einen Server aktualisieren oder verlieren, ohne dass die Website ausfällt. Ein Hoster kann viele Websites hinter eine Reihe von Gateways stellen und Server dazunehmen, wenn der Traffic wächst.

Ohne Gruppe wäre jedes Gateway für sich: Eine Sperre gälte nur auf einem Server, ein Limit zählte pro Server, und Besucher:innen müssten die Browser-Prüfung auf jedem Server neu bestehen.

## Was die Gruppe teilt

| Was | Wie es sich verhält |
| --- | --- |
| Gesperrte Adressen | Eine Sperre aus einem Szenario, aus dem Dashboard oder von einem Agenten gilt nach etwa einer Sekunde auf jedem Server. „Freigeben“ hebt sie überall auf. |
| Einstellungen | Was du im Dashboard oder über die Agent-API einstellst, gilt auf jedem Server: Schalter der Regelquellen, Schwellen, Limits, Crawler-Regeln, Zugriffssperre, Browser-Prüfung, Ausnahmen. |
| Eigene Adressen und Freigaben | Die Liste eigener Adressen und freigegebene Absender gelten überall. Die eigene Liste eines Servers gewinnt immer gegen eine Sperre aus der Gruppe. |
| Logins | Ein Passwort und eine Anmeldung für das Dashboard jedes Servers. Agent-Tokens gelten auf allen. |
| Besucher:innen | Wer die Browser-Prüfung bestanden oder sich an der Zugriffssperre angemeldet hat, bleibt das auf dem nächsten Server. |
| Zertifikate | Eine Bestellung pro Zertifikat. Die Prüfung der Zertifizierungsstelle klappt, egal auf welchem Server sie landet. |
| Limits und Szenarien | Jeder Server meldet den anderen einmal pro Sekunde, was er gezählt hat. Ein Limit gilt damit für die Gruppe und nicht pro Server. |
| Verteilte Angriffe (Wellen) | Auch die Erkennung verteilter Angriffe zählt für die Gruppe. Eine Welle ist auf jedem Server dieselbe, ihre Reaktion greift überall, und „Beenden“ im Dashboard beendet sie auf allen. |
| Ereignisse und Anfragen | Jeder Server hält auch die Ereignisse, Vorfälle und einzelnen Anfragen der anderen. Jedes Dashboard zeigt die ganze Gruppe. |
| Löschung nach Art. 17 DSGVO | Eine gelöschte Adresse wird auf jedem Server gelöscht, auch auf einem, der gerade aus war und später zurückkommt. |

Nicht geteilt werden `schild.yaml`, `rules.d` und dein Caddyfile. Die verteilst du wie bisher mit deinem Deployment auf jeden Server.

## So ist eine Gruppe aufgebaut

**Zwei Server.** Davor steht der Loadbalancer deines Hosters oder eine Floating-IP, die zum jeweils aktiven Server zeigt. Beide Server halten den vollen Stand. Eine dritte Maschine brauchst du nicht.

**Viele Server.** Davor stehen zwei oder mehr Balancer-VMs, zum Beispiel mit HAProxy im TCP-Modus. Sie verteilen die Verbindungen auf die Gateways. TLS endet auf den Gateways.

Schild verschiebt selbst keine IP-Adresse und ist kein Loadbalancer. Das übernimmt dein Hoster, keepalived oder HAProxy.

Die Server sprechen über einen eigenen Port miteinander (`cluster.listen`), verschlüsselt mit TLS 1.3. Jeder Server hat einen eigenen Schlüssel, der den Server nie verlässt. Lege diesen Port in ein privates Netz. Schild lehnt eine öffentliche Adresse dafür ab, solange du sie nicht ausdrücklich erlaubst.

## Einrichten mit einer Konfigurationsdatei

Das ist der Weg für ein Deployment, das dieselben Dateien auf jeden Server schreibt. Du rufst auf keinem Server einen Befehl auf.

1. Erzeuge einmal ein Gruppen-Geheimnis und lege es dort ab, wo dein Deployment Geheimnisse hält:

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
   ```

   Nur `listen` unterscheidet sich von Server zu Server. `peers` nennt alle Server und darf die eigene Adresse enthalten.

4. Starte Schild neu. Jeder Server nimmt sich beim Start selbst in die Gruppe auf und findet die anderen. Die Reihenfolge ist egal.

Das Geheimnis lässt einen Server in die Gruppe und kann sonst nichts. Wer es hat, kann einen Server aufnehmen. Behandle es deshalb wie ein Passwort.

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

Tritt ein Server einer Gruppe bei, bringt er mit, was er hat. Seine eigenen Adressen, Freigaben, Limits und Einstellungen kommen zur Gruppe dazu, und er übernimmt, was die Gruppe hat.

Nur wenn beide Seiten denselben Eintrag haben, etwa denselben Schalter mit verschiedenen Werten, gilt der Wert der Gruppe. Was der Server dazu selbst hatte, bewahrt Schild auf dem Server auf und nennt es in `schild cluster status`.

## Was der Loadbalancer braucht

**Prüfung, ob ein Server bereit ist.** Lass den Balancer `/.schild/readyz` auf den Web-Ports abfragen. Ein Server antwortet mit 503, solange er den Stand der Gruppe noch nicht übernommen hat und während er anhält.

**Echte Adresse der Besucher:innen.** Hinter einem Balancer im TCP-Modus kommt die Adresse über das PROXY-Protokoll. In einer Gruppe verlangt Schild dafür eine Liste erlaubter Absender im Caddyfile:

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

Ohne diese Liste startet Schild in einer Gruppe nicht. Sonst könnte jeder, der einen Server direkt erreicht, eine beliebige Adresse als seine ausgeben, und eine Sperre dieser Adresse gälte dann auf jedem Server.

**Verteilung.** Verteilt der Balancer nach der Adresse der Besucher:innen, landet ein Client immer auf demselben Server. Dann zählen Limits genau. Mit reihum verteilten Verbindungen zählen sie mit etwa einer Sekunde Verzug.

## Sperren schon vor den Gateways

Hinter einem Balancer mit PROXY-Protokoll kommen alle Pakete vom Balancer. Die Firewall auf dem Gateway selbst (`schild firewall run`) kann gesperrte Adressen dort nicht erkennen. Der richtige Ort ist die Balancer-VM.

Eine Balancer-VM tritt der Gruppe als Edge bei. Sie bekommt nur die Liste gesperrter Adressen mit ihrem Ende. Ereignisse, Einstellungen, Logins, Zertifikate und Schlüssel erreichen sie nie.

```bash
# auf einem Gateway
schild cluster invite -role edge

# auf der Balancer-VM, mit Adresse und Code aus der Ausgabe
schild cluster join 10.0.0.1:8790 CODE -edge -name lb-1 -data /var/lib/schild-edge
schild firewall run -group -data /var/lib/schild-edge
```

Jede Sperre endet in der Firewall von selbst, auch wenn die VM kein Gateway mehr erreicht. Wie bei der Firewall auf einem Gateway betrifft sie nur die Ports 80 und 443.

Eine Edge lässt sich nur mit einem Code aufnehmen, nie mit dem Gruppen-Geheimnis. Das Geheimnis gehört nicht auf eine Balancer-VM.

## Wenn ein Server ausfällt

- Verbindungen, die auf dem ausgefallenen Server endeten, brechen ab. Anfragen, die dort gerade liefen, schlagen fehl. Kein Loadbalancer und kein Proxy kann eine laufende TLS-Verbindung auf einen anderen Server umziehen.
- Neue Verbindungen gehen an die anderen Server, sobald der Balancer den Ausfall bemerkt.
- Sperren, Einstellungen, Logins und Zertifikate liegen auf jedem Server. Es geht nichts verloren.
- Was der ausgefallene Server an Ereignissen und Vorfällen geschrieben hat, zeigen die anderen weiter an, bis auf die letzte Sekunde vor dem Ausfall.

Kommt der Server zurück, holt er Sperren, Einstellungen, eigene Adressen, Logins und Löschungen nach. Erst danach meldet er sich beim Balancer als bereit. Ereignisse und Vorfälle der anderen folgen in den Sekunden danach. Die einzelnen Anfragen, die die anderen inzwischen bedient haben, holt er im Hintergrund nach.

## Einen Server geplant anhalten

Für ein Update oder eine Wartung:

```bash
schild cluster drain
```

Der Server antwortet dem Balancer sofort mit 503 und bedient noch 15 Sekunden lang, was ankommt. So schickt der Balancer neue Verbindungen woanders hin, bevor eine einzige abgewiesen wird. Dann hält Schild an und gibt laufenden Anfragen 30 Sekunden, um fertig zu werden. `systemctl stop schild` macht dasselbe. Nach der Wartung startest du den Server mit `systemctl start schild` wieder.

Beide Zeiten stellst du unter `cluster.drain` ein. `delay_s` sollte länger sein als das Prüfintervall deines Balancers mal die Zahl der Fehlversuche, nach denen er einen Server herausnimmt.

## Einen Server aus der Gruppe nehmen

```bash
schild cluster remove web-3
```

Danach spricht kein Mitglied mehr mit diesem Server, und keines nimmt an, was er noch schickt. Das gilt auch, wenn der Server das Gruppen-Geheimnis hat. Der entfernte Server erfährt es und schreibt es in sein Log. Er bedient mit seinem letzten Stand weiter, bis du bei ihm `cluster.enabled: false` setzt oder ihn abschaltest.

## Wenn in der Gruppe etwas Falsches unterwegs ist

Eine Änderung erreicht jeden Server in etwa einer Sekunde, eine falsche auch. Für diesen Fall gibt es eine Notbremse:

```bash
schild cluster pause
```

Der Server bedient weiter mit dem Stand, den er hat. Er nimmt nichts mehr aus der Gruppe an und gibt nichts weiter. Was du währenddessen auf ihm änderst, wartet. Mit `schild cluster resume` nimmt er wieder teil und holt nach, was er verpasst hat.

## Den Stand prüfen

```bash
schild cluster status
```

Die Ausgabe nennt jedes Mitglied mit Rolle, Adresse, Zustand und letztem Kontakt, dazu die Zahl laufender Sperren und geteilter Einstellungen.

Dasselbe zeigt das Dashboard. Oben auf jeder Seite steht, ob der Server allein läuft („Einzelner Server“) oder Teil einer Gruppe ist („Gruppe · 3 Server“). Die Karte „Gruppe“ auf der Server-Seite nennt den Zustand des Abgleichs und jedes Gateway mit letztem Kontakt, Rückstand, Version und Konfiguration. Balancer-VMs stehen darunter für sich.

| Anzeige | Bedeutung |
| --- | --- |
| Abgleich aktiv | Der Server erreicht alle anderen Gateways. |
| Abgleich eingeschränkt | Mindestens ein Gateway ist nicht erreichbar. Mit den übrigen läuft der Abgleich weiter. |
| Abgleich unterbrochen | Der Server erreicht kein anderes Gateway und arbeitet mit dem letzten Stand weiter. |
| Abgleich pausiert | Auf dem Server wurde `schild cluster pause` aufgerufen. |
| Aus der Gruppe entfernt | Ein Mitglied hat dem Server gemeldet, dass er entfernt wurde. |

**Unterschiedliche Konfiguration.** Jedes Gateway nennt den anderen alle fünf Sekunden eine Prüfsumme seiner Konfiguration: `schild.yaml` ohne `node_name`, `cluster.listen` und `cluster.advertise`, dazu `rules.d`. Weicht ein Server ab, steht das in der Karte. Das ist ein Hinweis. Schild verteilt keine Konfiguration, das bleibt Aufgabe deines Deployments. Das Caddyfile geht in die Prüfsumme noch nicht ein.

In der Liste gesperrter Adressen steht bei jeder Sperre, welcher Server sie entschieden hat. Löschst du unter „Datenschutz“ eine Adresse, nennt das Dashboard die Server, die die Löschung schon erreicht hat, und die, bei denen sie noch aussteht.

## Daten und Datenschutz

Eine Gruppe ist ein Betreiber. Mit `cluster.share_data` (ab Werk an) hält jeder Server auch die Ereignisse und Anfragen der anderen, mit den Adressen der Besucher:innen. Sie reisen nur zwischen deinen eigenen Servern, über die verschlüsselte Verbindung der Gruppe. Nenne in deiner Datenschutzerklärung jeden Server als Ort der Verarbeitung.

Jeder Server wendet seine eigenen Aufbewahrungsfristen und Größengrenzen auf alles an, was er hält. Eine Löschung nach Art. 17 gilt auf jedem Server.

Jeder Server speichert damit, was die ganze Gruppe aufzeichnet. In einer großen Gruppe kann das zu viel sein. Mit `share_data: false` bleiben Ereignisse und Anfragen auf dem Server, der sie geschrieben hat. Sperren, Einstellungen, Logins und Zähler teilt die Gruppe trotzdem.

## Grenzen

- **Nur im Kleinen gemessen.** Eine unabhängige Messung lief mit drei Servern auf einem Rechner. Ein echter Loadbalancer, zehn Server, Zertifikate, gemischte Versionen und Lastspitzen sind nicht gemessen.
- **Zwei offene Befunde der Messung.** Kommt ein Server zurück, während dessen Ausfall eine gesperrte Adresse gelöscht wurde, meldet er sich etwa eine Zehntelsekunde zu früh als bereit und weist die Adresse so lange noch ab. Und „Freigeben“ auf einem anderen Server als dem, der gesperrt hat, kann in der ersten Sekunde nach der Sperre scheitern.
- **Dieselbe Einstellung auf zwei Servern geändert.** Änderst du denselben Schalter oder denselben Eintrag gleichzeitig auf zwei Servern, gilt überall die spätere Änderung. Verschiedene Einträge derselben Liste bleiben beide erhalten, auch wenn sich die Server zwischendurch nicht erreicht haben.
- **Limits mit Verzug.** Ein Client, der seine Anfragen über die Server verteilt, kommt um das hinaus, was die Server in einer Sekunde annehmen.
- **Einzelne Anfragen nach einem langen Ausfall.** Jeder Server hält seine letzten 32 768 Anfragen für die anderen bereit, höchstens 24 MiB. Ein Server, der aus war, holt daraus nach, was ihm fehlt. War er länger weg, als dieser Vorrat reicht, fehlen ihm die älteren Anfragen der anderen. Er schreibt die Zahl in sein Log, und die Server, die sie bedient haben, halten sie weiter. Startet ein Server neu, beginnt sein Vorrat leer.
- **Pro Server bleiben** die Zähler der Übersicht und die Server-Diagramme.
- **Wellen mit Verzug.** Wie bei den Limits vergeht bis zu einer Sekunde, bis die Server voneinander wissen. Eine Welle wird deshalb erkannt, sobald die Summe über der Schwelle liegt und die nächste passende Anfrage einen Server erreicht. Wie viele Anfragen eine Reaktion gestoppt hat, zählt jeder Server für sich.
- **Zertifikate bei Netztrennung.** Erreichen sich die Server nicht, kann jede Seite dasselbe Zertifikat bestellen. Das ist eine Bestellung zu viel, beide Zertifikate sind gültig.
- **Neues Geheimnis heißt neue Gruppe.** Ist das Gruppen-Geheimnis bekannt geworden, verteilst du ein neues und lässt die Server mit leerem Verzeichnis `cluster` neu starten. Einen Wechsel im laufenden Betrieb gibt es noch nicht.
- **Höchstens 16 Gateways und 8 Balancer-VMs.** Mehr lehnt die Gruppe ab. Im laufenden Betrieb erprobt sind bisher nur zwei und drei Gateways.

## Befehle

| Befehl | Was er tut |
| --- | --- |
| `schild cluster secret` | gibt ein neues Gruppen-Geheimnis aus |
| `schild cluster status` | Mitglieder, letzter Kontakt, geteilter Stand |
| `schild cluster drain` | nimmt diesen Server aus dem Traffic und hält ihn an |
| `schild cluster pause` und `resume` | der Server bedient weiter, nimmt aber nichts aus der Gruppe an und gibt nichts weiter, bis du `resume` aufrufst |
| `schild cluster remove NODE` | beendet die Mitgliedschaft eines Servers |
| `schild cluster init` | macht diesen Server zum ersten einer neuen Gruppe (von Hand) |
| `schild cluster invite [-role edge]` | gibt einen Beitrittscode aus, einmal gültig, eine Stunde lang |
| `schild cluster join ADRESSE CODE` | tritt der Gruppe bei (von Hand) |
| `schild cluster join ADRESSE CODE -edge -name NAME -data DIR` | Balancer-VM tritt als Edge bei |
| `schild firewall run -group -data DIR` | hält die Sperren der Gruppe in der Firewall der Balancer-VM |
