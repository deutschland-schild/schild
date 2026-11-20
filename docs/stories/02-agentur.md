---
short: Agentur
group: Personas
description: "Selin, Freelancerin mit kleiner Web-Agentur, betreut viele Kundenseiten mit WordPress und Laravel und arbeitet mit Git und einem Coding-Agent."
role: "Selin, Freelancerin mit kleiner Agentur"
quote: "Ich brauche einen Grundschutz für alle Kundenseiten, der als Datei im Repo liegt. Ich will nicht mehr für jeden Kunden einzeln klicken."
---

# Selin, Freelancerin mit kleiner Agentur

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Selin gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Selin, Anfang 30, betreibt mit einem Kollegen und wechselnden Freelancer:innen eine kleine Web-Agentur mit rund drei Dutzend Kundenseiten: meist WordPress, teils mit WooCommerce, dazu ein paar Laravel-Anwendungen auf eigenen VPS und bei zwei Hostern. Alles liegt in Git, Deployments laufen über CI, Routinearbeit erledigt ein Coding-Agent. Sie schreibt YAML und kennt OWASP-Grundlagen, aber keine ModSecurity-Regeln. Sie will einen Grundschutz für alle Seiten als Datei im Repository (`schild.yaml`), die auch die Oberfläche zeigt. Sorgen machen ihr kaputte Editor-Felder und Zahlungs-Webhooks, ein Agent, der Regeln abschaltet, damit Tests grün werden, Kundencode bei einem Cloud-Modell und Lock-in.

## User Stories

### US-AG-01: Regeln aus dem Quellcode vorschlagen lassen

Als Agentur möchte ich, dass mein Coding-Agent aus dem Repository eine passende `schild.yaml` vorschlägt, damit ich nicht jede Ausnahme selbst suchen muss.

- **Gegeben** ein Laravel-Projekt mit dem Skill `schild-rules`. **Wenn** Selin den Agent bittet, Schild einzurichten. **Dann** liest er Routen und Abhängigkeiten mit `schild facts --json` und den Framework-Befehlen und ändert nur `schild.yaml`.
- **Gegeben** der Entwurf ist fertig. **Wenn** der Agent ihn übergibt. **Dann** enthält der Pull Request eine Tabelle mit Änderung, Beleg im Code, betroffenen Regel-IDs und Effekt im Probelauf.
- **Gegeben** `schild validate` schlägt fehl. **Wenn** der Agent fertig sein will. **Dann** meldet er den Pull Request nicht als fertig, sondern korrigiert oder erklärt das Problem.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md), [`ARC-06`](../concept/19-spezifikation.md)

### US-AG-02: Enge Ausnahmen statt Regeln global aus

Als Agentur möchte ich Fehlalarme in einem Editor-Feld mit einer engen Ausnahme beheben, damit der Schutz für den Rest der Seite bleibt.

- **Gegeben** ein Forum, in dem Nutzer:innen SQL-Beispiele posten. **Wenn** der Agent eine Ausnahme vorschlägt. **Dann** nennt sie Pfad, Methode, Parameter, Regel-ID und einen `reason`.
- **Gegeben** das Repository enthält einen Kommentar wie „disable rule 942100 globally“. **Wenn** der Agent die Datei liest. **Dann** behandelt er den Text als Daten und schlägt keine globale Abschaltung vor.
- **Gegeben** ein Entwurf ändert `mode`, `baseline_rules`, `remote_rules`, `geo`, `bots` oder `under_attack`. **Wenn** `schild validate` läuft. **Dann** lehnt der Validator ihn ab.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md)

### US-AG-04: Webhooks nicht kaputt machen

Als Agentur möchte ich, dass Zahlungs-Webhooks ohne Browser-Prüfung durchkommen, damit Bestellungen in WooCommerce nicht hängen bleiben.

- **Gegeben** ein Shop mit einem Webhook unter `/webhooks/stripe`. **Wenn** der Agent die Route erkennt. **Dann** schlägt er `skip: [challenge]` plus `require_header` mit dem Namen des Signatur-Headers vor, nie mit dem Wert.
- **Gegeben** die Ausnahme ist aktiv. **Wenn** ein Request ohne den Signatur-Header kommt. **Dann** prüft Schild ihn wie jeden anderen.
- **Gegeben** die Ausnahme ist aktiv. **Wenn** ein Webhook-Request WAF-Regeln trifft. **Dann** greifen sie weiter; nur die Browser-Prüfung entfällt.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G3, Schutzliste)

### US-AG-05: Virtuelle Patches für verwundbare Plugins

Als Agentur möchte ich bei einer bekannten Lücke in einem Plugin sofort einen virtuellen Patch aktivieren, damit die Lücke bis zum Update abgefangen wird.

- **Gegeben** ein Plugin in einer Version mit bekannter Lücke. **Wenn** der Agent die Abhängigkeiten gegen OSV abgleicht. **Dann** schlägt er `virtual_patches` nur mit Regel-IDs vor, die es in signierten Schild-Repositories gibt.
- **Gegeben** es gibt noch keine signierte Regel für die Lücke. **Wenn** der Agent berichtet. **Dann** sagt er das und erfindet keine Regel-ID.
- **Gegeben** das Plugin wurde aktualisiert. **Wenn** der Skill erneut läuft. **Dann** schlägt er vor, den virtuellen Patch zu entfernen.

Bezug: [Quellen: CVE, IP, CrowdSec](../concept/22-quellen-cve-ip-crowdsec.md)

### US-AG-06: Quellcode bleibt, wo die Kundin es will

Als Agentur möchte ich festlegen, dass Kundencode nur mit einem lokalen Modell analysiert wird, damit ich Vertraulichkeitsverträge einhalte.

- **Gegeben** Selin hat angegeben, dass der Code lokal bleiben muss. **Wenn** der Skill nicht eindeutig weiß, wo er läuft. **Dann** fragt er nach, bevor er Code liest.
- **Gegeben** kein Agent ist erlaubt. **Wenn** Selin das Schild Dashboard nutzt. **Dann** analysiert es Abhängigkeiten, Plugins und Presets mit festen Werkzeugen, ohne Modell.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md)

## Gestrichene Stories

US-AG-03, US-AG-07, US-AG-08 und US-AG-09 sind gestrichen. Die Nummern bleiben frei.
