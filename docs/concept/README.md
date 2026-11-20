# Deutschland-Schild – Dokumentation

> **Stand:** 23.10.2026 · **Status:** Konzept v1 (zur öffentlichen Diskussion) · **Format:** Markdown / Company as Code

**Kurz:**

- Index der Konzeptdateien; die Website zeigt sie unter `/doku`, gegliedert nach den Teilen von Deutschland-Schild, das Schild Gateway zuerst ([Gateway-Doku](../gateway/README.md), Reihenfolge in `site/app/utils/hub.ts`).
- Technischer Einstieg: [Technik kompakt](13-technik-kompakt.md), dann [Architektur V1](21-architektur-v1.md) und [Technologie & Security](04-technologie-und-security.md).
- Jede Datei beginnt mit Statuszeile und Kurz-Block; Status-Marker zeigen, was fest und was offen ist.

Deutschland-Schild ist eine **gemeinnützige, überparteiliche, unabhängige und quelloffene Initiative für den Grundschutz von Websites**. Betreiber:innen ohne 24/7-Security-Team bekommen einen einfachen, kostenlosen Grundschutz: einen offenen Filter auf dem Webserver (WAF) und ein Netz unabhängiger Labs.

**Stand:** Das Gateway ist als Alpha 0.1.0-alpha.1 veröffentlicht und läuft vor eigenen Projekten. Der Prototyp des Verbunds hat Stufe 2 im Testlabor bestanden (26.10.2026); Labs, Relays und Verbund sind geplant und nicht Teil der Alpha. Für die Alpha suchen wir Partner mit echten Systemen: Hoster, Agenturen, Open-Source-Projekte. Der Schnell-Check ist ein lokaler Entwurf. Gemeinnütziger Träger, Förderzusagen und Partner sind **noch nicht bestätigt**.

## Einstieg nach Arbeitsbereich

| Bereich | Dokument | Kernfrage |
| --- | --- | --- |
| Verbindliche Grundsätze | [00-grundsaetze.md](00-grundsaetze.md) | Was ist nicht verhandelbar? |
| Mission & Wirkung | [01-mission-und-wirkung.md](01-mission-und-wirkung.md) | Warum gibt es das Projekt? |
| Zielgruppen & Discovery | [02-zielgruppen-und-discovery.md](02-zielgruppen-und-discovery.md) | Für wen und welches Problem zuerst? |
| Produkt & UX | [03-produkt-und-ux.md](03-produkt-und-ux.md) | Was erleben Nutzer? |
| Technologie & Security | [04-technologie-und-security.md](04-technologie-und-security.md) | Wie bauen wir sicher und souverän? |
| Governance & Träger | [05-governance-und-traegerschaft.md](05-governance-und-traegerschaft.md) | Wer verantwortet was? |
| Company as Code | [06-company-as-code-und-agents.md](06-company-as-code-und-agents.md) | Wie arbeiten Team und Agents? |
| Community & Lernen | [07-community-und-wissensaufbau.md](07-community-und-wissensaufbau.md) | Wie wird vorhandenes Wissen nutzbar? |
| Finanzierung & Partner | intern, nicht im Repo | Was wird benötigt und von wem? |
| Pilot & Betrieb | [09-pilot-und-betrieb.md](09-pilot-und-betrieb.md) | Wie starten wir verantwortbar? |
| Kommunikation & Pitch | [10-kommunikation-und-pitch.md](10-kommunikation-und-pitch.md) | Wie erklären und pitchen wir das? |
| Offene Fragen & Risiken | [11-offene-fragen-und-risiken.md](11-offene-fragen-und-risiken.md) | Was wissen wir noch nicht? |
| Manipulation & Poisoning | [18-manipulation-und-poisoning.md](18-manipulation-und-poisoning.md) | Wie verhindern wir, dass jemand das Netz mit falschen Signalen gegen Dritte richtet? |
| Spezifikation (IDs) | [19-spezifikation.md](19-spezifikation.md) | Welche stabilen Nummern (SEC-01, ARC-03 …) haben die Festlegungen der Website? |
| Events & Geschwindigkeit | [20-events-und-geschwindigkeit.md](20-events-und-geschwindigkeit.md) | Wie werden Abfragen, Abstimmung der Labs und Verteilung schnell, ohne den Request-Pfad zu bremsen? |
| Architektur V1 (Föderation) | [21-architektur-v1.md](21-architektur-v1.md) | Wie wird es gebaut: Client ↔ Lab, Lab ↔ Lab, Vertrauenslisten, ACK, Protobuf, Bauabschnitte? |
| Quellen: CVE, IP, CrowdSec | [22-quellen-cve-ip-crowdsec.md](22-quellen-cve-ip-crowdsec.md) | Welche CVE- und IP-Quellen unter welchen Lizenzen, wie dockt CrowdSec an, wie wählt ein Lab seinen Mix? |
| Prototyp-Verifikation | [23-verifikation.md](23-verifikation.md) | In welcher Reihenfolge bauen und prüfen wir den Prototyp, und woran erkennen wir Showstopper? |
| Zugriffsregeln | [25-zugriffsregeln.md](25-zugriffsregeln.md) | Wie sperrt und öffnet man URL-Bereiche mit einer Regelliste pro Website? |
| Datenschutzkonzept | [24-datenschutz.md](24-datenschutz.md) | Welche Daten verarbeitet Schild wo, wer verantwortet sie, wie lange bleiben sie, was verlässt nie den Server? |
| Agentenregeln | [AGENTS.md](../AGENTS.md) | Wie dürfen Agents diese Dokumentation pflegen? |

## Statusmarkierungen

- **FIXIERT:** vom Initiator vorgegeben; nur durch seine ausdrückliche Entscheidung änderbar.
- **ZIEL:** angestrebter Zustand oder Termin, noch nicht zugesagt.
- **ENTWURF:** Vorschlag, zu diskutieren oder zu testen.
- **ZU PRÜFEN:** Behauptung, externer Kontakt, Rechtstatsache, Frist oder Zahl ohne aktuelle Bestätigung.
- **OFFEN:** Entscheidung steht noch aus.
- **ERSETZT:** gilt nicht mehr; der Nachfolger ist genannt oder verlinkt.

## Empfohlene erste Arbeitsschritte

1. [Prototyp-Umfang und Pilot festlegen](09-pilot-und-betrieb.md): Funktionen, Grenzen und Demo auf eigenen Projekten.
2. [Landingpage und Kurzpitch schärfen](10-kommunikation-und-pitch.md): keine unbelegten Versprechen.
3. Träger- und Finanzierungsgespräche vorbereiten.
4. [Mission und Prinzipien als Prüfkriterien nutzen](00-grundsaetze.md).
5. Agenten entlang des [Company-as-Code-Zyklus](06-company-as-code-und-agents.md) einsetzen.

**Arbeitsregel:** Jede neue Behauptung bekommt einen Status. Prototyp, Zielbild, Konzept und vertraglich Bestätigtes bleiben klar getrennt.
