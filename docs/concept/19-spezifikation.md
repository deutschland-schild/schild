---
short: Spezifikation (IDs)
group: Offen & ehrlich
description: "Stabile Nummern für alle Festlegungen auf der Website – zum Zitieren in Issues, Reviews und Kritik."
---

# Spezifikation: stabile IDs

**Status:** ENTWURF · bis 05.11.2026 aus der Website-Seite für Security-Nerds erzeugt, seitdem hier von Hand gepflegt.

**Kurz:**

- Register stabiler IDs für die zentralen Festlegungen der Website: Härtung `SEC-01` bis `SEC-06`, Architekturentscheidungen `ARC-01` bis `ARC-07`.
- IDs werden nie umnummeriert oder wiederverwendet; eine weggefallene ID bleibt frei, neue Festlegungen bekommen die nächste freie Nummer.
- Gedacht zum Zitieren in Issues, Reviews und Kritik; auf der Website selbst stehen die Nummern nicht.

Die zentralen Festlegungen der Website – Härtung (SEC) und Architekturentscheidungen (ARC) – haben eine feste ID (z. B. `SEC-01`). Andere Listen bekommen bewusst keine IDs, damit es einfach bleibt. Auf der Website stehen die Nummern bewusst nicht; hier und im Handbuch-Teil „Spezifikation“ sind sie zum Zitieren in Issues, Reviews und Kritik.

Regeln: **IDs werden nie umnummeriert und nie wiederverwendet.** Fällt eine Festlegung weg, bleibt ihre ID frei; neue Festlegungen bekommen die nächste freie Nummer. Inhalte und Code bleiben auf Englisch, die Texte hier auf Deutsch.

## SEC – Härtung: wenn ein Teil des Netzes böse wird

| ID | Festlegung |
| --- | --- |
| `SEC-01` | Netzregeln können nur schützen, nie abschalten |
| `SEC-02` | Ein Rückzug betrifft nur Netzregeln |
| `SEC-03` | Keine Regel von nur einer Stelle |
| `SEC-04` | Öffentliche Logs bei jedem Lab |
| `SEC-05` | Regeln und Programm getrennt |
| `SEC-06` | Gegen gefälschte Clients |

## ARC – Architekturentscheidungen mit Belegen

| ID | Festlegung |
| --- | --- |
| `ARC-01` | Aktionen statt IP-Listen. |
| `ARC-02` | Mehrere unabhängige Labs, jedes mit eigenem Beleg. |
| `ARC-03` | Erst prüfen, dann sperren. |
| `ARC-04` | Ganze Sitzungen bewerten, nichts verraten. |
| `ARC-05` | Erst normalisieren, dann prüfen. |
| `ARC-06` | KI forscht – entschieden wird nach festen Regeln. |
| `ARC-07` | Keine Besucher-IP im Netz – auch nicht gehasht. |
