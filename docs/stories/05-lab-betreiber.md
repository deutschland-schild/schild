---
short: Lab-Betreiberin
group: Personas
description: "Lena betreibt mit ihrer Hochschule und dem örtlichen Hackspace ein Schild Lab: Angriffe nachstellen, über Regeln abstimmen, eigenes öffentliches Log."
role: "Lena, Lab-Betreiberin an Hochschule und Hackspace"
quote: "Ich möchte, dass das, was wir im Lab herausfinden, bald echten Websites hilft und nicht erst nach dem nächsten Paper."
---

# Lena, Lab-Betreiberin an Hochschule und Hackspace

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Lena gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Lena arbeitet an einem Lehrstuhl für IT-Sicherheit und ist im Hackspace ihrer Stadt aktiv. Beide betreiben zusammen ein Schild Lab: Server im Rechenzentrum der Hochschule, eine abgeschottete Testumgebung mit verbreiteten CMS und Plugins, einige Honeypots. Lena schreibt SecLang-Regeln und kennt Fuzzing und Patch-Diffing; für 24/7-Betrieb fehlen Leute, am Wochenende springt der Hackspace ein. Sie will echte Angriffe nachstellen, daraus Regeln machen und mit anderen Labs auf Augenhöhe abstimmen, öffentlich nachvollziehbar. Sie sorgt sich um Missbrauch für Überwachung oder gezielte Sperren, rechtliche Fragen, Betriebsaufwand, vergiftete Eingaben und Regeln, die ungepatchte Lücken verraten.

## User Stories

### US-LA-01: Ein Lab starten

Als Lab-Betreiberin möchte ich das Schild Lab mit einer `lab.yaml` aufsetzen und im Monitoring-Dashboard sehen, was läuft, damit ich kein eigenes System bauen muss.

- **Gegeben** eine `lab.yaml` mit Betreiber-ID und Lab-Schlüssel. **Wenn** Lena das Lab startet. **Dann** laufen Go-Kern (Eingang, Signaturen, Feeds, Abstimmung) und die konfigurierten Analyse-Worker als getrennte Container mit eigenen, minimalen Rechten.
- **Gegeben** das Lab läuft. **Wenn** Lena das Monitoring-Dashboard öffnet. **Dann** sieht sie Eingang, Worker, Abstimmungen und Log-Stand (OpenTelemetry, Grafana).
- **Gegeben** Lena will ein eigenes Analysewerkzeug einbinden. **Wenn** sie es als Container mit der Worker-Schnittstelle baut. **Dann** kann es in beliebiger Sprache geschrieben sein. Schnittstelle: ZU PRÜFEN.
- **Gegeben** das Lab läuft. **Wenn** Lena nachsieht, mit wem es spricht. **Dann** sind das nur Peers, die sie ausdrücklich eingetragen hat.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md), [Architektur V1](../concept/21-architektur-v1.md)

### US-LA-04: Eine Regel mit Belegen vorschlagen

Als Lab-Betreiberin möchte ich eine Regel mit Zielsoftware, Version und Belegen vorschlagen, damit andere Labs sie nachprüfen können.

- **Gegeben** Lena hat einen Exploit gegen eine Plugin-Version nachgestellt. **Wenn** sie die Regel vorschlägt. **Dann** enthält der Vorschlag Ziel-Software, Version, die Regel in der erlaubten SecLang-Teilmenge und `evidence`.
- **Gegeben** die Regel nutzt `REMOTE_ADDR`, `@ipMatch` oder `ctl:ruleEngine=Off`. **Wenn** der Validator sie prüft. **Dann** lehnt er sie ab.
- **Gegeben** der Vorschlag ist eingereicht. **Wenn** Lena sein Ziel festlegt. **Dann** erreicht er ohne Belege anderer Labs höchstens `observe`.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G1, G2), [`SEC-01`](../concept/19-spezifikation.md)

### US-LA-05: Vorschläge anderer Labs nachstellen

Als Lab-Betreiberin möchte ich Vorschläge anderer Labs in meiner Testumgebung nachstellen, damit meine Zustimmung etwas bedeutet.

- **Gegeben** ein Vorschlag eines anderen Labs. **Wenn** Lenas Testumgebung die Zielsoftware nicht hat. **Dann** meldet ihr Lab „kein Befund“, und das zählt nicht als Zustimmung.
- **Gegeben** Lenas Lab stellt den Angriff nach. **Wenn** die Regel den Exploit-Request trifft, denselben Request ohne schädlichen Teil aber nicht. **Dann** ist der Minimalitätstest bestanden.
- **Gegeben** eine Regel trifft Anfragen aus dem Negativkorpus oder einen Endpunkt der Schutzliste ohne Payload-Bedingung. **Wenn** die Gates laufen. **Dann** lehnt Lenas Lab sie ab.
- **Gegeben** genug Labs verschiedener Betreiber haben bestätigt. **Wenn** die Regel `block` erreichen soll. **Dann** braucht es zusätzlich eine menschliche Freigabe in mindestens zwei Organisationen.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G2, G3), [Testkonzept](../concept/14-testkonzept.md), [`ARC-02`](../concept/19-spezifikation.md)

### US-LA-06: Ein eigenes öffentliches Log führen

Als Lab-Betreiberin möchte ich ein eigenes, nur anhängbares Log veröffentlichen, damit jede:r prüfen kann, was mein Lab signiert hat.

- **Gegeben** Lenas Lab signiert eine Regel. **Wenn** sie verteilt wird. **Dann** steht sie vorher in Lenas Log.
- **Gegeben** andere Labs zeichnen Lenas Checkpoints gegen. **Wenn** Lenas Lab verschiedenen Clients verschiedene Stände zeigen würde. **Dann** fällt das bei den Zeugen auf.
- **Gegeben** das Log. **Wenn** jemand es durchsucht. **Dann** findet er keine IPs und keine IP-Pseudonyme.

Bezug: [`SEC-04`](../concept/19-spezifikation.md), [Events und Geschwindigkeit](../concept/20-events-und-geschwindigkeit.md)

### US-LA-07: Lücken nicht verraten

Als Lab-Betreiberin möchte ich Regeln für ungepatchte Lücken verteilen, ohne die Lücke öffentlich zu machen, damit Angreifer nicht aus unserem Log lernen.

- **Gegeben** eine selbst gefundene, ungepatchte Lücke. **Wenn** die Regel ins Log kommt. **Dann** steht dort zuerst nur ein Hash.
- **Gegeben** der Hersteller hat gepatcht oder 90 Tage sind vorbei. **Wenn** Lena veröffentlicht. **Dann** kommt der Klartext ins Log, und jede:r kann ihn gegen den Hash prüfen.
- **Gegeben** Lenas Lab findet eine neue Lücke. **Wenn** es sie meldet. **Dann** geht sie per Responsible Disclosure an den Hersteller; veröffentlicht werden nur Erkennungsmuster, keine Exploits.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md) (Labs forschen mit KI)

## Gestrichene Stories

US-LA-02, US-LA-03 und US-LA-08 sind gestrichen. Die Nummern bleiben frei.
