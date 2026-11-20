---
short: Offene Fragen & Risiken
group: Offen & ehrlich
description: "Was wir noch nicht wissen. Lieber eine ehrlich offene Frage als eine falsch bestätigte Tatsache."
---

# Offene Fragen, Annahmen und Risiken

**Status:** Laufende Entscheidungsliste · **Zweck:** Vermeiden, dass Vorschläge zu vermeintlichen Fakten werden.

**Kurz:**

- Offene Fragen und Risiken mit Status und nötigem Nachweis: P0 vor einem öffentlichen Pilot, P1 Finanzierung und Skalierung, P2 Produkt und Community.
- P0 offen: real implementierte Prototypfähigkeiten, Pilotscope, Autorisierungsprüfung, rechtlicher Betreiber, Ausfallverhalten, Freigaberollen.
- Dazu Fragen aus den Fachdokumenten (Red-Team-Review, Manipulation, Events, Architektur V1, Quellen) mit Test- oder Mess-IDs.
- Was schon entschieden ist, steht unter „Bereits entschieden“; neue Entscheidungen nach Vorlage im Fachdokument erfassen.

## Bereits entschieden

Begründung und Folgen stehen im jeweiligen Fachdokument.

- Keine Besucher-IPs im Netz, auf keiner Stufe; lokal bleiben IP und Standort im Klartext (26.10.2026; [Prototyp-Verifikation](23-verifikation.md), E4/E7; Tests T27/T28).
- Prototyp und Alpha direkt per HTTPS, ab v1 OHTTP mit unverkettbaren Tokens (26.10.2026; E1).
- Keine Rollen für Geldgeber; die Voreinstellung folgt öffentlichen Kriterien, die noch auszuarbeiten sind (26.10.2026; [Architektur V1](21-architektur-v1.md), Red-Team H4).
- Eigener Code unter MIT (25.10.2026; `LICENSE`), eigene Dokumentation ebenfalls, beides in einem Repository (01.11.2026).

## Priorität P0 – vor einem öffentlichen Pilot

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Welche Prototypfähigkeiten halten auf echten Systemen? | OFFEN | Gebaut und im Testlabor gemessen ist der Kernablauf ([Prototyp-Verifikation](23-verifikation.md)); das Gateway läuft seit November 2026 vor eigenen Projekten, die Messungen D1–D3 auf echtem Traffic stehen aus |
| Welche Nutzergruppe und welche Systeme werden zuerst unterstützt? | OFFEN | Pilotpersona + Scope |
| Wie wird Eigentum/Autorisierung geprüft? | OFFEN | Verfahren + Abuse-Tests |
| Wer ist rechtlich/operativ Betreiber? | OFFEN | Trägervertrag oder alternative geeignete Struktur |
| Welche Nutzer- und Security-Daten werden verarbeitet? | ENTWURF | [Datenschutzkonzept](24-datenschutz.md); fachliche Prüfung und DSFA vor der Alpha |
| Wie wird der Dienst bei Fehlfunktionen gestoppt? | ENTWURF | Rückzug aller Netzregeln per k-von-n signiertem Regelstand ohne Netzregeln, Grundschutz läuft weiter (Richtung entschieden 27.10.2026, [Events und Geschwindigkeit, 4.5](20-events-und-geschwindigkeit.md)); Rollback und Runbook ([Technologie, KI und Sicherheitsarchitektur](04-technologie-und-security.md), „Härtung“) |
| Was passiert bei Zentral-, KI- oder Feed-Ausfall? | OFFEN | Ausfalltests + Fallback-Policy |
| Wer gibt riskante Änderungen frei? | OFFEN | Menschliche Rollen + Policy-Gates |
| Welche Aussagen darf die Landingpage machen? | OFFEN | Claims vs. Evidenz |

## Aus dem Red-Team-Review ([Red-Team-Review](15-red-team-review.md))

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Sybil-Schutz über Client-Token bürgender Hoster | OFFEN | Ausgabeprozess, Missbrauchstest |
| SecLang-Teilmenge für Fernregeln | OFFEN | Allowlist + Validator + Fuzzing |
| Rollen nach DSGVO (Art. 26 vs. 28) zwischen Betreibern, Labs, Dashboard | OFFEN | Rechtsgutachten + DSFA vor Pilot |
| § 202c StGB und CVD-Policy für Lab-Forschung | OFFEN | Gutachten, Policy nach ISO/IEC 29147 |
| Abgleich mit CrowdSec/BunkerWeb: Schild soll die offenen CrowdSec-Funktionen selbst abdecken (28.10.2026) | OFFEN | Gebaut (28.10.2026, Unit- und Integrationstests, Messungen im Testlabor stehen aus): Verhalten über mehrere Anfragen und Ratenbegrenzung ([`MVP-17`](../../tests/specs/MVP-17-behaviour-and-rate-limits.yaml)), verteilte Angriffe ([`MVP-18`](../../tests/specs/MVP-18-distributed-attacks.yaml)). Offen: enge Ausnahmen per Klick, Regel-Inhalte über Hub-Regeln |
| Name „Deutschland-Schild“ und „Cyber-Grundschutz“ klingen staatlich / kollidieren mit BSI-IT-Grundschutz | OFFEN | Entscheidung zum Namen |

## Aus Manipulation & Poisoning ([Manipulation und Poisoning](18-manipulation-und-poisoning.md))

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Client-Meldungen nur Hinweise; `block` nur mit Reproduktion bei ≥ 2 Lab-Betreibern; Zählung nach Bürgen (Issuer) | ENTWURF | Entscheidung; Tests T34/T35 |
| Fehlalarm-Rückmeldungen verengen statt abschalten; virtuelle Patches nie per Rückmeldung abwertbar | ENTWURF | Entscheidung; Test T33 |
| `X-Forwarded-For`-Fälschung und HTTP/3-0-RTT als Weg, ehrliche Clients fremde IPs melden zu lassen | ZU PRÜFEN | Selbsttest, Verhalten Caddy/quic-go bei 0-RTT; Tests T29/T30 |
| Schutzliste für Endpunkte (Webhooks, Callbacks) und Quellen für Absender-Etiketten (Zahlungsdienste, Such-Bots) | OFFEN | Quellen, Lizenzen, Pflegeprozess |
| Bürgen-Verfahren: wer darf Client-Tokens ausgeben, Kontingente, Widerruf, Weg für Selbstbetreiber | OFFEN | Governance-Entwurf, ARC/Rate-Limited-Tokens-Reife prüfen |
| Rechtsrahmen für Sanktionen gegen Anschwärzen (UWG, StGB, Haftung der Bürgen) | ZU PRÜFEN | Rechtliche Einschätzung |

## Aus Events & Geschwindigkeit ([Events und Geschwindigkeit](20-events-und-geschwindigkeit.md))

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Keine synchrone Netzabfrage im Request-Pfad; Regeln und Empfehlungen aus dem Netz wirken ab dem nächsten Request | ENTWURF | Entscheidung; Messung B01/B02 |
| Zwei Kanäle: Signale/Abfragen über OHTTP, Push über öffentlichen SSE-Strom (kein WebSocket-Rückkanal) | ENTWURF | Entscheidung; Datenschutz-Review der Metadaten am Push-Relay |
| Wer betreibt Push-Relays, wie viele mindestens, wie kommen sie in die Liste? | OFFEN | Governance wie bei Labs; Messung B05/B06 |
| Lab ↔ Lab als Vollvermaschung signierter Feeds statt gemeinsamem Broker; ab welcher Lab-Zahl GossipSub? | ENTWURF | Prototyp, Messung B09/B11 |
| Zielkonflikt Geschwindigkeit vs. Gates: `block` bleibt an Reproduktion und menschliche Freigabe gebunden | ENTWURF | Time-to-Protect in [Testkonzept](14-testkonzept.md) nach Stufen trennen |
| Coraza-Regelneuaufbau: Dauer, inkrementell möglich? | ZU PRÜFEN | Messung B07 |

## Aus Architektur V1 ([Architektur V1](21-architektur-v1.md))

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Scoring-Stream mit Client-Schlüssel vs. unverkettbare OHTTP-Signale: zwei Betriebsarten (unverkettbar als Standard, Scoring-Abo als Opt-in)? | OFFEN | Entscheidung; Datenschutz-Review |
| Transport für Scoring-Abo und Föderation: gRPC-Bidi oder HTTP/2-Streaming mit DSSE-JSON | OFFEN | Prototyp, Messung B03/B05 |
| Score-Skala: Semantik, Versionierung, Median über unabhängige Betreiber | OFFEN | Spezifikation, Testdaten |
| Reports über Clients: wann nur Hinweis, wann lokale Einschränkung; Widerruf und Entlastung | OFFEN | Policy-Entwurf, Abgleich mit [Manipulation und Poisoning](18-manipulation-und-poisoning.md) |
| Rechtliche Fragen zur optionalen Prüfseite (Sitzungsmodus nur `passive`, nichts aus dem Browser an Labs; [Architektur V1](21-architektur-v1.md), 6.1) | ZU PRÜFEN | [Datenschutzkonzept, Abschnitt 10](24-datenschutz.md), 10.7 |
| Kapazität: welcher Anteil der Events geht ins Netz (nur Auffälliges + Stichprobe)? | ZU PRÜFEN | Lasttest, Messung |
| Wer betreibt ein unabhängiges OHTTP-Relay (ab v1)? | OFFEN | [Prototyp-Verifikation](23-verifikation.md), E1 |
| Rechtsrolle Alpha und v1: Auftragsverarbeitung (Art. 28) oder gemeinsame Verantwortung (Art. 26) zwischen Website und Lab | ENTWURF (29.10.2026) | Sache der Lab-Betreiber: Sie betreiben Labs für sich selbst und vereinbaren untereinander, was nötig ist. Das Projekt ist keine Vertragspartei |

## Aus Quellen: CVE, IP, CrowdSec ([Quellen](22-quellen-cve-ip-crowdsec.md))

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Ist ein gemeinnütziges Lab, das auch für Shops und Firmen bewertet, bei AbuseIPDB, abuse.ch, GreyNoise, DShield „nicht kommerziell“? | ZU PRÜFEN | Schriftliche Anfrage je Anbieter, juristische Prüfung |
| Dürfen Labs fremde Sperrlisten spiegeln oder nur Erlaubt-Listen und CC0-Daten (G1)? | ENTSCHIEDEN 28.10.2026 (Initiator) | Weder noch: keine IP-Listen über die Labs, auch keine Erlaubt-Listen. IP-Daten nur als Etikett, das der Server selbst lädt ([Quellen](22-quellen-cve-ip-crowdsec.md) §1, [18](18-manipulation-und-poisoning.md) G6) |
| Lizenz der CrowdSec-Blocklist- und CTI-Daten; Nutzung durch gemeinnützige Labs | ENTSCHIEDEN 28.10.2026 (Initiator) | Entfällt: keine CrowdSec-IP-Daten, weder am Server noch im Lab |
| CrowdSec-Integration | ENTSCHIEDEN 28.10.2026 (Initiator) | Keine IP-Listen, kein Konto, keine Daten an CrowdSec; Labs nutzen Hub-Regeln (MIT) als Kandidaten; das Gateway bringt die öffentlichen Hub-Regeln mit automatischen Updates selbst mit (ENTSCHIEDEN 30.10.2026, MVP-26); Parallelbetrieb dokumentiert ([Quellen](22-quellen-cve-ip-crowdsec.md) §4). Offen bleibt nur, ob Labs Regeln an den Hub zurückgeben. |
| Herkunft in Stimmen (`evidence.sources`), gleiche Upstream-Quelle zählt einmal | ENTWURF | Aufnahme in Protobuf-Skizze ([Architektur V1](21-architektur-v1.md)), Testfälle |
| KI-Klauseln (z. B. abuse.ch: kein Training) vs. eigene Entscheidungsmodelle der Labs | ZU PRÜFEN | Lizenz-Registry mit KI-Spalte |
| US-Abhängigkeit der CVE-Infrastruktur (CVE-Programm, NVD-Anreicherung reduziert, KEV, GHSA, OSV); EUVD/BSI noch lückenhaft | OFFEN | Beobachten; Rohdaten im Lab cachen; EUVD-Weiterverwendung bei ENISA klären |
| Gemeinsame, öffentliche Lizenz-Registry der Labs (Quelle, Etikett, Prüfdatum) | OFFEN | Repository anlegen, Pflegeprozess |

## Priorität P1 – Finanzierung und Skalierung

| Frage / Risiko | Status | Benötigter Nachweis / Entscheidung |
| --- | --- | --- |
| Welcher Fiscal Host passt satzungsrechtlich (z. B. Open Collective Europe)? | OFFEN | Due Diligence + Gespräch |
| Sponsoring per Rechnung an PrioPad: steuerliche Einordnung für Sponsoren, Umsatzsteuer, Interessenkonflikt (Betreuer = Auftragnehmer) | OFFEN | Steuerberatung, öffentliche Leistungsbeschreibung und Rechnungsübersicht |
| Betrieb von abliterated Modellen für Exploit-Analyse: Zugriffskontrolle, Protokollierung, § 202c StGB, Nutzungsbedingungen der Modelle | OFFEN | Policy, Rechtsgutachten |
| Welches Träger- und Finanzierungsmodell trägt langfristig? | ENTWURF (29.10.2026) | Open Collective mit gemeinnützigem Fiscal Host; alle Beteiligten rechnen per Rechnung ab, keine Anstellungen; Firmensponsoring per Rechnung, keine Spendenquittungen; keine AVVs, weil jeder Betreiber Schild selbst betreibt |
| Wie hoch sind GPU-Kosten pro Nutzer? | OFFEN | Benchmark + Lastprofil |
| Wem gehören vorhandener Code, Marke und Daten? | OFFEN | IP-/Lizenzanalyse und Vertrag |
| Welche Lizenzen gelten für eingebundene Software (Caddy, Coraza, CRS) und KI-Modelle? | OFFEN | Lizenzinventar |
| Welche Partner machen konkret mit? | ZU PRÜFEN | Schriftliche Zusagen |
| Wie wird längerfristiger Betrieb finanziert? | OFFEN | 2–3-Jahres-Modell |
| Wie sichern wir die Unabhängigkeit bei Trägerwechsel? | OFFEN | Exit-Plan, Portabilität, Schlüsselhoheit |

## Priorität P2 – Produkt und Community

- Welche UX-Defaults schützen und bleiben trotzdem niedrigschwellig?
- Welche Regelquellen dürfen automatisch blockieren, welche nur informieren?
- Welche Standards setzen wir als verifizierte Best Practices um?
- Wie wird der externe Cybersicherheitsbeirat besetzt und unabhängig gehalten?
- Wie wird Community-Wissen geprüft, gepflegt und lizenziert?
- Welche Bildungsinhalte verbessern Sicherheitskompetenz tatsächlich?

## Aussagen, die vor externer Kommunikation geprüft werden müssen

- Rechtliche Gemeinnützigkeit und Satzungszweck eines künftigen Trägers
- Namen, aktuelle Funktionen und Erreichbarkeit externer Kontaktpersonen
- Zahl potenziell betroffener Systeme und volkswirtschaftliche Wirkung
- Jede konkrete Partner-, Beirats-, BSI- oder Sponsoringzusage
- Technische Leistungsfähigkeit und Sicherheit des Prototyps

## Vorschlag für Entscheidungen

Jede Entscheidung im betroffenen Fachdokument so erfassen:

```markdown
### Entscheidung: <kurzer Titel>
- Datum:
- Status: ENTWURF / ENTSCHIEDEN / ERSETZT
- Verantwortlich:
- Problem und Optionen:
- Entscheidung und Begründung:
- Sicherheits-/Nutzerrisiken:
- Prüfnachweis / Test:
- Konsequenzen für andere Bereiche:
```
