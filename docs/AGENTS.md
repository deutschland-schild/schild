# AGENTS – Arbeitsregeln für KI-Agenten

Diese Datei gilt für alle Dateien in `docs/`:

| Ordner | Inhalt | Öffentlich |
| --- | --- | --- |
| `gateway/` | Doku zum Schild Gateway: alle Funktionen und Betrieb, nur Gebautes | ja, gerendert unter `/doku/gateway/<datei>`, erster Abschnitt der Doku |
| `concept/` | Konzept (Grundsätze, Strategie, Governance, Architektur, Tests, Risiken) | ja, gerendert unter `/doku/konzept/<datei>`; `UNPUBLISHED_CONCEPT` in `site/app/utils/hub.ts` bleibt als Schutz für nicht zu rendernde Dateien |
| `brand/` | Marke, Sprache und Gestaltung (ein Dokument), Design Tokens | ja, `01-marke` gerendert unter `/doku/marke/01-marke`, Logos aus `brand/assets/` |
| `stories/` | Personas und User Stories mit Akzeptanzkriterien | ja, gerendert unter `/doku/personas/<datei>` |

### Dokumentation auf der Website (`/doku`)

Die Website rendert diese Markdown-Dateien direkt – keine Kopien. `/doku` ist die Wissensbasis und Diskussionsplattform nach dem Prinzip **Company as Code**. Sie ist nach den Teilen von Deutschland-Schild gegliedert: zuerst das Schild Gateway, das es heute gibt, dann die geplanten Teile, dann das Projekt. Oben auf `/doku` stehen die vier Teile (Gateway, Lab-Server, Relays, Managed Schild) mit ihrem Status.

1. **Gateway** (verfügbar, Alpha) – gateway 00, 01, 02, concept 25
2. **Lab-Server** (geplant) – concept 21, 18, 22, dazu „Schild erklärt in 5 Minuten“ auf `/netz`
3. **Relays** (geplant) – concept 20

Unter **Allgemeines** (in der Seitenleiste zugeklappt, `general: true`):

4. **Gesamtsystem & Forschung** – concept 13, 04, 24, 03, 12, 19, 16, 17
5. **Qualität & Risiken** – concept 11, 14, 23, 15
6. **Strategie & Organisation** – concept 02, 05, 06, 07, 09, 10 (08 ist nicht öffentlich)
7. **Personas & User Stories** – stories
8. **Werte & Grundsätze** – concept 00, 01
9. **Marke** – brand 01

**Verfügbar oder geplant:** Jede Seite eines geplanten Abschnitts zeigt oben einen Hinweis, dass es diesen Teil noch nicht im Betrieb gibt, mit Link zum Gateway. In `gateway/` steht nur, was gebaut ist und ohne Labs läuft. Geplantes fürs Gateway steht dort nicht, auch nicht als Liste: Sie veraltet zu schnell. Labs, Relays, Signale und Freigaben aus dem Netz gehören nicht in `gateway/`.

Jede Konzeptdatei beginnt nach H1 und Statuszeile mit einem Block **Kurz:** (höchstens 5 Zeilen: was das Dokument festlegt oder beschreibt, was fest und was offen ist). Im Kurz-Block keine Status-Marker in Großbuchstaben – die stehen in der Statuszeile und würden sonst doppelt gezählt.

Die Zuordnung und der Status stehen in `site/app/utils/hub.ts` (`HUB_SECTIONS`, `COMPONENTS`), nicht im Frontmatter. Neue Konzept- und Gateway-Dateien erscheinen automatisch (ohne Zuordnung unter „Gesamtsystem & Forschung“). Status-Marker (`FIXIERT`, `ENTSCHIEDEN`, `ZIEL`, `ENTWURF`, `ZU PRÜFEN`, `OFFEN`, `IDEE`, `ERSETZT`) sind für die Agenten und treten in der gerenderten Doku zurück: Status-Zeilen (`**Status:** …`) und die Abschnitte „Als Nächstes“ und „Gestrichene Stories“ stehen zugeklappt unter „Arbeitsstand und nächste Schritte“ am Seitenende, Marker-Legenden und Tabellenspalten „Status“ fallen weg, Klammern mit nur einem Marker (plus Datum/Initiator) verschwinden, Marker im Satz werden zu normalen Wörtern („zu prüfen“). Sätze deshalb so schreiben, dass sie auch mit kleingeschriebenem Marker lesbar bleiben. Relative Links zwischen den Dateien werden auf `/doku`-Routen umgeschrieben; Links auf nicht veröffentlichte Dateien erscheinen als reiner Text.

**Vor dem Veröffentlichen prüfen:** keine Namen privater Personen, keine Kontaktlisten oder internen Verweise, keine unbestätigten Partner, Logos oder Zusagen, keine internen Finanzen. Im Zweifel nach `internal/` auslagern. Inhalte aus `internal/` nie in öffentliche Dateien, Commits, PRs oder Issues übernehmen.

## Auftrag

Agenten verbessern Spezifikationen, Quellenlage, Umsetzungspläne, Tests und Dokumentation. Sie ersetzen keine verantwortlichen Menschen bei Sicherheitsfreigaben, rechtlichen Entscheidungen, Finanzen oder Änderungen an Nutzersystemen.

## Nicht verhandelbar

1. Die Festlegungen in [concept/00-grundsaetze.md](concept/00-grundsaetze.md) beachten.
2. **Gemeinnützig und überparteilich** sind Anforderungen, keine Marketingfloskeln.
3. Keine zentrale Zwangskontrolle, kein Single Point of Failure, keine nicht autorisierten Scans oder Eingriffe.
4. Keine Behauptung, BSI, Stiftungen, Geldgeber oder Unternehmen seien Partner, solange keine Zusage dokumentiert ist.
5. Keine Behauptung über amtlich bestätigte Gemeinnützigkeit ohne entsprechenden Träger- oder Steuerstatus.
6. Prototypstatus nicht ausschmücken: Funktionsumfang und Ergebnisse müssen durch eine Demo/Testprotokolle belegt werden.
7. Bestehende Komponenten und Open-Weight-Modelle bevorzugen; keine eigene Foundation-Model-Entwicklung planen.
8. Keine Geheimnisse, personenbezogenen Nutzerinformationen, Credentials oder verwertbare ungepatchte Schwachstellendetails in öffentliche Dokumente einfügen.

## Bearbeitung von Dateien

- Bearbeite möglichst nur die fachlich zuständige Markdown-Datei.
- Diagramme als Mermaid-Codeblock (```` ```mermaid ````) – rendert auf GitHub und der Website. Die Website liefert sie als fertiges SVG aus `site/diagrams/` aus: Nach einer Diagramm-Änderung in `site/` `npm run diagrams` ausführen (Anleitung in `site/scripts/diagrams.mjs`) und die SVGs mit committen; `npm run diagrams -- --check` prüft, ob alle aktuell sind. Fehlt ein SVG, rendert die Seite das Diagramm im Browser.
- Die [Kultur](brand/01-marke.md#kultur) gilt auch für Agents: innovativ, Security by Design, läuft einfach.
- Markenregeln aus [brand/01-marke.md](brand/01-marke.md) gelten für alle öffentlichen Texte (Du-Ansprache, keine Angstkommunikation).
- Halte Änderungen klein, verständlich, verlinkt und überprüfbar.
- Unterscheide `FIXIERT`, `ZIEL`, `ENTWURF`, `ZU PRÜFEN`, `OFFEN`.
- Kennzeichne Annahmen und Quellen einschließlich Prüfdatum.
- Ergänze nach Möglichkeit: **Problem → Hypothese → Akzeptanzkriterium → Test → Implementierung → Betriebsmetrik**.
- Nenne mögliche Risiken und Reversibilität jeder relevanten Änderung.
- Prüfe, ob Änderungen Dokumente anderer Bereiche betreffen, und aktualisiere die Links.
- Vermeide erfundene Kennzahlen, Personenrollen, Förderfristen oder Zusagen.

## Rollen (keine zusätzlichen Stellen erforderlich)

| Agent / Funktion | Primäre Dokumente |
| --- | --- |
| Strategy | 00, 01 |
| Discovery | 02, 03 |
| Product / UX | 03, 09 |
| Architecture / Security | 04, 09 |
| Governance | 05 |
| Operations / Engineering | 06, 09 |
| Community / Knowledge | 07 |
| Funding / Partnerships | 08 |
| Communications | 10, brand/ |
| Risk & Validation | 11 und Querverweise |

## Fertig-Kriterium für Änderungen

Eine wesentliche Änderung ist erst fertig, wenn Ausgangsproblem und Zweck dokumentiert, Nutzerwirkung geklärt, betroffene Specs aktualisiert, erforderliche Tests benannt oder ausgeführt und betriebliche Risiken berücksichtigt sind. Sicherheitsrelevante Ausführung benötigt menschliche Freigabe gemäß Policy.

## Update-Zyklus

`Strategie → Discovery → Living Specs → Tests / TDD → Implementierung → Betrieb → Erkenntnisse → Strategie/Discovery`
