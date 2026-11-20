---
short: Überblick
group: Personas
description: "Wozu Personas und User Stories da sind, wie eine Story aufgebaut ist und wie wir Akzeptanzkriterien schreiben."
---

# Personas und User Stories: Überblick

**Status:** ENTWURF · Personas und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Die Personas sind erfunden.** Es gibt diese Menschen nicht, und ihre Zitate sind angenommene Wünsche, keine Kundenstimmen.

## Wozu das hier da ist

Bevor wir Funktionen festlegen, beschreiben wir, für wen wir bauen: Personas mit Alltag, Zielen und Sorgen. Daraus folgen User Stories, also prüfbare Aussagen darüber, was Schild für diese Menschen leisten muss. Passt eine Funktion zu keiner Persona, bauen wir sie später oder gar nicht. Aus den Akzeptanzkriterien werden Tests ([Testkonzept](../concept/14-testkonzept.md)). Eine Story beschreibt ein Ziel, keinen heutigen Stand.

Namen von Personen, Vereinen und Firmen sind erfunden. Sie bündelt, was wir aus Gesprächen und eigener Erfahrung erwarten; ob das stimmt, prüfen wir in Interviews und Tests ([Zielgruppen und Product Discovery](../concept/02-zielgruppen-und-discovery.md)).

## So ist eine Story aufgebaut

```text
### US-<CODE>-<nn>: <kurzer Titel>

Als <Persona> möchte ich <Ziel>, damit <Nutzen>.

- **Gegeben** <Ausgangslage>. **Wenn** <Handlung>. **Dann** <prüfbares Ergebnis>.

Bezug: <Konzept>, <Spec-IDs>
```

Der Code hat zwei Buchstaben je Persona, dann eine laufende Nummer. **Story-IDs werden nie umnummeriert und nie wiederverwendet.** Fällt eine Story weg, bleibt ihre Nummer frei und wir vermerken das in der Datei. So bleiben Verweise aus Issues, Tests und Reviews gültig, wie bei den Spec-IDs der [Spezifikation](../concept/19-spezifikation.md). „Bezug“ verlinkt Konzepte und Spec-IDs wie [`SEC-03`](../concept/19-spezifikation.md).

## So schreiben wir Akzeptanzkriterien

Gherkin-Stil auf Deutsch: **Gegeben** ist die Lage vorher, **Wenn** genau eine Handlung oder ein Ereignis, **Dann** ein von außen prüfbares Ergebnis (Anzeige, Protokolleintrag, Statuscode, Datei).

- Prüfbar statt schwammig: „in höchstens drei Schritten, ohne Fachbegriffe“ statt „ist einfach“.
- Zahlen nur, wenn ein Konzept sie festlegt (etwa 5-Minuten-Totmannschalter, 14 Tage Log-Aufbewahrung ab Werk).
- Befehle, Schlüssel und Formate auf Englisch (`schild setup`, `mode: observe`), der Rest auf Deutsch.
- Auch das Nein gehört dazu: keine Besucher-IP an Labs, keine Sperre allein wegen der IP, keine Fernabschaltung.

## Status

Status-Wörter bedeuten dasselbe wie in den Konzepten:

| Status | Bedeutung |
| --- | --- |
| FIXIERT | Grundsatz, nur nach ausdrücklicher Entscheidung änderbar |
| ENTSCHIEDEN | Festgelegt, mit Datum im jeweiligen Konzept |
| ZIEL | Wollen wir erreichen, Weg noch offen |
| ENTWURF | Vorschlag, wird mit Gesprächen und Tests geprüft |
| ZU PRÜFEN | Fakt oder Annahme, die wir noch belegen müssen |
| OFFEN | Noch nicht entschieden |
| ERSETZT | Gilt nicht mehr, Nachfolger ist verlinkt |

Alle Personas und Stories sind ENTWURF. Hängt eine Story an einer offenen Entscheidung, ist sie mit OFFEN markiert.

## Die Personas

| Datei | Persona | Code | In einem Satz |
| --- | --- | --- | --- |
| [01-hobby-admin.md](01-hobby-admin.md) | Jens, Hobby-Admin | `HA` | Elektriker, betreut ehrenamtlich die Joomla-Seite seines Sportvereins. |
| [02-agentur.md](02-agentur.md) | Selin, Agentur | `AG` | Viele Kundenseiten, arbeitet mit Git und Coding-Agent. |
| [03-hoster-admin.md](03-hoster-admin.md) | Katrin, Hoster-Admin | `HO` | Hunderte Server mit Plesk, will Schild ausrollen und für Kund:innen bürgen. |
| [04-provider-inhouse.md](04-provider-inhouse.md) | Miriam, Provider in-house | `PR` | Großer Provider, betreibt alle Bausteine selbst. |
| [05-lab-betreiber.md](05-lab-betreiber.md) | Lena, Lab-Betreiberin | `LA` | Betreibt mit Hochschule und Hackspace ein Schild Lab. |
| [06-security-forschung.md](06-security-forschung.md) | Kai, Security-Forschung | `SF` | Will Protokoll und Neutralität angreifen, bevor es andere tun. |
| [07-foerderer-cto.md](07-foerderer-cto.md) | Sabine, Unterstützerin | `FO` | CTO, entscheidet über Förderung und will Belege statt Versprechen. |

Zuerst bauen wir für Betreiber:innen von Webservern (Jens, Selin, Katrin), dann für die, die das Netz mittragen (Lena, Kai, Miriam). Sabine entscheidet mit, ob es losgeht.

## Mitmachen

Fehler gefunden oder Story fehlt? Auf [GitHub](https://github.com/deutschland-schild/schild) ist ein Issue oder Pull Request willkommen.
