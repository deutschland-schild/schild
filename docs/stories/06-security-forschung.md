---
short: Security-Forschung
group: Personas
description: "Kai aus der Hacker-Community will Protokoll und Neutralität angreifen, bevor es andere tun, und eigene Regeln vorschlagen."
role: "Kai, Security-Forscher aus der Hacker-Community"
quote: "Staatliche Überwachung und Vorratsdatenspeicherung sehe ich grundsätzlich kritisch. Ich will Infrastruktur, die wir selbst betreiben, und bei der alle, die eine Website betreiben, selbst entscheiden, wem sie vertrauen."
---

# Kai, Security-Forscher aus der Hacker-Community

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Kai gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Kai ist Ende 20, Pentester und abends im Hackspace, in einer Szene, wie man sie vom CCC kennt. Von Schild hörte er in einem Vortrag; seine erste Reaktion: „Ein Netz, das Angriffe vieler Websites sieht? Das will ich kaputt machen.“ Er liest Protokollentwürfe, baut eigene Clients, fälscht Signale und erwartet Spezifikationen, Testvektoren und reproduzierbare Builds. Er will herausfinden, ob sich Schild zum Abhören, Zensieren oder Anschwärzen missbrauchen lässt, Lücken so melden, dass sie behoben werden, und ohne Erlaubnis ein eigenes Repository oder Lab betreiben. Er misstraut einem „neutralen“ Netz, das in Wahrheit eine zentrale Sperrliste ist, und Versprechen ohne technische Grenzen.

## User Stories

### US-SF-01: Prüfen, ob das Binary zum Code passt

Als Security-Forscher möchte ich das `schild`-Binary selbst aus dem Quellcode bauen und vergleichen, damit ich nicht blind einem Release vertrauen muss.

- **Gegeben** ein veröffentlichtes Release. **Wenn** Kai es aus dem getaggten Quellcode baut. **Dann** ist das Ergebnis bitgleich mit dem Release.
- **Gegeben** das Release. **Wenn** Kai die Signaturen prüft. **Dann** findet er Schlüssel und Fingerprints auf der Website und im Log.
- **Gegeben** jemand will über den Regelkanal Code ausliefern. **Wenn** das Gateway das prüft. **Dann** lehnt es ab; Programme kommen nur aus dem Release-Kanal.

Bezug: [`SEC-05`](../concept/19-spezifikation.md), [Technik kompakt](../concept/13-technik-kompakt.md)

### US-SF-02: Nachprüfen, was den Server verlässt

Als Security-Forscher möchte ich jedes Signal sehen, das ein Schild Gateway verschickt, damit ich die Datenschutz-Versprechen überprüfen kann.

- **Gegeben** ein Schild Gateway im Betrieb. **Wenn** es ein Signal sendet. **Dann** protokolliert es das Signal lokal im Klartext.
- **Gegeben** ein Signal mit Feldern außerhalb des Schemas. **Wenn** das Gateway es bauen will. **Dann** verwirft es alles, was nicht auf der Positivliste steht.
- **Gegeben** ein Signal. **Wenn** Kai es untersucht. **Dann** enthält es keine Inhalte, keine Cookies, keine vollständige URL und keine Besucher-IP, auch nicht gehasht oder als Pseudonym.

Bezug: [`ARC-07`](../concept/19-spezifikation.md), [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md)

### US-SF-05: Eine gezielte Regel einschleusen

Als Security-Forscher möchte ich versuchen, über ein Lab eine Regel gegen eine einzelne Website oder den Endpunkt eines Konkurrenten einzuschleusen, damit wir die Neutralität prüfen.

- **Gegeben** Kai betreibt ein Lab und schlägt eine Regel für einen Pfad vor, den nur eine Website hat. **Wenn** die Verbreitungsprüfung läuft. **Dann** wird die Regel als gezielt abgelehnt und ist höchstens lokal zulässig.
- **Gegeben** eine Regel trifft einen Zahlungs-Webhook ohne Payload-Bedingung. **Wenn** die Gates laufen. **Dann** wird sie abgelehnt.
- **Gegeben** Kais Lab signiert allein. **Wenn** Gateways die Regel prüfen. **Dann** nehmen sie sie nicht an, weil Signaturen anderer Betreiber fehlen.

Bezug: [`SEC-03`](../concept/19-spezifikation.md), [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G3)

### US-SF-07: Netzregeln können nichts abschalten

Als Security-Forscher möchte ich prüfen, ob eine Netzregel den Schutz abschalten oder Daten ausleiten kann, damit ein gekapertes Lab nicht zur Hintertür wird.

- **Gegeben** eine Fernregel mit `ctl:ruleEngine=Off`. **Wenn** das Gateway sie lädt. **Dann** lehnt der Validator sie ab.
- **Gegeben** eine Fernregel will Inhalte nach außen senden. **Wenn** das Gateway sie lädt. **Dann** lehnt es sie ab; Regeln können nur prüfen, blocken oder eine Prüfung zeigen.
- **Gegeben** der Rückzug aller Netzregeln. **Wenn** Labs ihn auslösen. **Dann** nimmt er nur Netzregeln zurück, nie die lokalen Regeln des Betreibers.

Bezug: [`SEC-01`](../concept/19-spezifikation.md), [`SEC-02`](../concept/19-spezifikation.md)

### US-SF-09: Lücken vertraulich melden

Als Security-Forscher möchte ich eine Lücke in Schild vertraulich melden, damit sie behoben ist, bevor sie öffentlich wird.

**Status:** OFFEN · Meldeweg, Fristen und Ablauf sind noch nicht festgelegt.

- **Gegeben** Kai findet eine Lücke im Schild Gateway. **Wenn** er den dokumentierten Meldeweg nutzt. **Dann** bekommt er eine Eingangsbestätigung und einen Ansprechpartner.
- **Gegeben** die Lücke ist behoben. **Wenn** die Meldung veröffentlicht wird. **Dann** wird Kai genannt, wenn er das möchte.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md) (Wobei wir euch brauchen)

## Gestrichene Stories

US-SF-03, US-SF-04, US-SF-06 und US-SF-08 sind gestrichen. Die Nummern bleiben frei.
