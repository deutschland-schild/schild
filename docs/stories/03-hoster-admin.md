---
short: Hoster-Admin
group: Personas
description: "Katrin, Admin bei einem kleinen Hoster mit vielen Servern und Plesk, will Schild per schild.yaml ausrollen und für ihre Kund:innen bürgen."
role: "Katrin, Admin bei einem kleinen Hoster · betreibt ein Schild Lab"
quote: "Ich wünsche mir weniger gehackte Kundenseiten. Jede davon landet bei mir als Abuse-Ticket und kostet Stunden."
---

# Katrin, Admin bei einem kleinen Hoster

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Katrin gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Katrin ist Systemadministratorin bei einem regionalen Hoster mit einem Dutzend Mitarbeitenden und betreut einige Hundert Server: Plesk, Root-Server in Kundenhand, etwas Shared Hosting, auf Debian, Ubuntu, AlmaLinux und teils noch CentOS 7. Sie verteilt Konfiguration mit Ansible, bearbeitet Abuse-Meldungen und hat CrowdSec auf einigen Servern. Ihr Hoster betreibt außerdem ein Schild Lab, das Katrin mit betreut. Sie kennt nftables, systemd und Plesk im Detail und will Formate, Signaturen und Grenzfälle sehen. Sie will weniger gehackte Kundenseiten und Abuse-Tickets und Admin-Zugänge aus dem offenen Internet nehmen. Sie fürchtet einen Rollout, der Hunderte Server gleichzeitig beschädigt, nächtliche Selbst-Updates, Haftung als Bürgin und Support-Aufwand durch Fehlsperren.

## User Stories

### US-HO-01: Auf vielen Servern ausrollen

Als Hoster-Admin möchte ich Schild über Paketquellen und eine zentrale Vorlage ausrollen, damit ich keinen Server einzeln anfassen muss.

- **Gegeben** Debian-, Ubuntu- und AlmaLinux-Server. **Wenn** Katrin die Paketquelle mit Ansible einträgt. **Dann** prüfen `apt` und `dnf` die Paketsignatur mit dem veröffentlichten Schlüssel.
- **Gegeben** ein Server mit CentOS 7. **Wenn** Katrin Schild installiert. **Dann** läuft das statische Binary ohne zusätzliche Bibliotheken.
- **Gegeben** eine `schild.yaml`-Vorlage mit Platz für Ergänzungen pro Server. **Wenn** Ansible sie verteilt. **Dann** prüft `schild validate` jede Datei vor dem Neuladen und bricht bei Fehlern ab, ohne die laufende Konfiguration zu ändern.
- **Gegeben** die Pakete sind installiert. **Wenn** der Dienst angelegt wird. **Dann** startet er im Modus `observe`, nicht im Sperrmodus.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md)

### US-HO-02: Programm-Updates selbst steuern

Als Hoster-Admin möchte ich entscheiden, wann das Programm aktualisiert wird, damit kein Release ungeprüft auf allen Servern landet.

- **Gegeben** eine neue Programmversion. **Wenn** `unattended-upgrades` läuft. **Dann** wird sie nicht installiert, weil die Paketquelle dort ab Werk nicht eingetragen ist.
- **Gegeben** neue Regeln kommen signiert über den Regelkanal. **Wenn** sie ankommen. **Dann** aktualisieren sie sich getrennt vom Programm und laufen zuerst im Probelauf.
- **Gegeben** jemand liefert über den Regelkanal ein Programm aus. **Wenn** das Gateway das Paket prüft. **Dann** lehnt es das Paket ab.

Bezug: [`SEC-05`](../concept/19-spezifikation.md), [Events und Geschwindigkeit](../concept/20-events-und-geschwindigkeit.md)

### US-HO-03: Plesk und SSH nur über VPN

Als Hoster-Admin möchte ich Plesk und SSH auf das VPN beschränken, ohne mich bei einem Fehler auszusperren.

- **Gegeben** ein Managed-Server mit NetBird. **Wenn** Katrin `vpn_only: [ssh, plesk]` aktiviert. **Dann** zeigt Schild vorher die geänderten Firewall-Regeln und verlangt eine erneute Bestätigung.
- **Gegeben** die Änderung ist aktiv. **Wenn** Katrin sie nicht innerhalb von 5 Minuten über das VPN bestätigt. **Dann** nimmt Schild die Firewall-Änderung automatisch zurück.
- **Gegeben** die Änderung ist bestätigt. **Wenn** Katrin das lokale Protokoll öffnet. **Dann** steht dort, wer was wann von welchem Gerät geändert hat.

### US-HO-04: Für Kund:innen bürgen

Als Hoster-Admin möchte ich für die Schild Gateways meiner Kund:innen Token ausgeben, damit ihre Signale im Netz zählen, ohne dass Labs wissen, welche Website meldet.

**Status:** OFFEN · Bürgen-Aufnahme, Kontingente und Haftung sind Governance-Fragen ([Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md), G7 und Abschnitt 5).

- **Gegeben** Katrins Hoster ist als Bürge aufgenommen. **Wenn** ein Kundenserver Signale schickt. **Dann** sieht das Lab den Bürgen, aber nicht, welcher Client meldet.
- **Gegeben** ein Kontingent pro Bürge. **Wenn** Kundenserver mehr Hinweise schicken als erlaubt. **Dann** werden die überzähligen nicht angenommen.
- **Gegeben** viele Kundenserver melden dasselbe. **Wenn** ein Lab die Hinweise zählt. **Dann** zählen sie als ein Bürge, nicht als viele Stimmen.
- **Gegeben** eine Regel stellt sich als vergiftet heraus. **Wenn** Labs nachprüfen. **Dann** erfährt Katrins Hoster, dass Hinweise aus seinem Kontingent beteiligt waren, und kann seine Kund:innen prüfen.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G2, G7), [`SEC-06`](../concept/19-spezifikation.md), [`ARC-07`](../concept/19-spezifikation.md)

### US-HO-07: Gekaperte Kundenserver früh erkennen

Als Hoster-Admin möchte ich gekaperte Server erkennen, bevor Abuse-Meldungen kommen, damit ich Kund:innen früh warnen kann.

- **Gegeben** ein Server verschickt plötzlich viel mehr Daten, als der Proxy an Besucher:innen ausgeliefert hat. **Wenn** der Zustand bewertet wird. **Dann** steigt der Kompromittierungs-Index, mit Begründung je Faktor.
- **Gegeben** der Index erreicht *verdächtig*. **Wenn** Schild reagiert. **Dann** benachrichtigt es und pausiert die Signale dieses Servers an die Labs.
- **Gegeben** `host_health.share` ist `off`. **Wenn** Signale verschickt werden. **Dann** enthalten sie keine Angabe zum Zustand.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md)

## Gestrichene Stories

US-HO-05, US-HO-06, US-HO-08 und US-HO-09 sind gestrichen. Die Nummern bleiben frei.
