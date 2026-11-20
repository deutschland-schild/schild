---
short: Zielgruppen & Discovery
group: Was
description: "Für wen wir zuerst bauen und wie wir Annahmen mit echten Menschen prüfen."
---

# Zielgruppen und Product Discovery

**Status:** Zielgruppen ZIEL · Priorisierung OFFEN

**Kurz:**

- Im Fokus steht die Website: vom Hobby-Admin über Vereine, kleine Unternehmen und Agenturen bis zu Hostern und Lab-Betreibern.
- Priorisierung offen: Der Pilot braucht eine eng definierte erste Nutzergruppe; die Pilotpersona steht noch nicht fest.
- Fünf Hypothesen mit Prüfmethode, etwa: Die größte Hürde ist zu erkennen, ob eine Warnung einen betrifft und was zu tun ist.
- Pilotempfehlung (Entwurf): wenige freiwillige, überprüfbar autorisierte Websites mit verbreitetem Stack.
- Discovery in sechs Schritten von Problem bis Entscheidung; keine personenbezogenen Interviewdaten ohne Einwilligung im öffentlichen Repository.

## Für wen?

Im Mittelpunkt steht die **Website** (auf der Website: „Vom Hobby-Admin bis zur Agentur“):

- Hobby-Admins und Self-Hoster mit eigener Website ohne Security-Team
- Vereine, gemeinnützige Organisationen und ehrenamtlich betreute Websites
- Kleine Unternehmen und Selbstständige mit eigener Website
- Agenturen, die Websites für Kund:innen betreuen
- Hoster und Provider, die Schild für viele Websites einschalten
- Lab-Betreiber (Hoster, Hochschulen, CERTs, Community), die Signale prüfen und Regeln vorschlagen
- Perspektivisch Bildungseinrichtungen und weitere kleine Organisationen

Personas und User Stories dazu stehen unter [Personas](../stories/00-ueberblick.md).

Wir bedienen nicht alle Gruppen gleichzeitig. Der Pilot braucht **eine eng definierte erste Nutzergruppe**.

## Hypothesen

| Hypothese | Wie wir sie prüfen |
| --- | --- |
| Nichttechnische Betreiber verstehen Warnmails oder Scanberichte oft nicht. | 5–10 Interviews, Beispielbefunde vorlegen |
| Die zentrale Hürde ist die Einordnung: Betreiber wissen nicht, ob eine Warnung sie betrifft und was zu tun ist. | Beispielwarnungen mit einer Beispiel-Umgebung vorlegen, Verständnis messen |
| Ein einfaches Onboarding erhöht Aktivierung und Dauerbetrieb. | Beobachtete Tests mit zwei Onboarding-Varianten |
| Hoster-Integrationen senken Aufwand stark. | 2–3 technische Pilotgespräche und ein Integrations-Prototyp |
| Transparentes Open Source erhöht Vertrauen. | Interviews mit Nutzern und Admins; nicht voraussetzen |

## Discovery-Rhythmus

1. **Problem:** konkrete Nutzersituation, Auswirkungen, heutiger Workaround.
2. **Beobachten:** Interview oder Test, mit realen Problemen statt Wunschideen.
3. **Hypothese:** Welche Veränderung erwarten wir?
4. **Experiment:** kleinstmöglicher, sicherer Test.
5. **Erkenntnis:** Beobachtung, Evidenz, Unsicherheit.
6. **Entscheidung:** verwerfen, überarbeiten, priorisieren; Specs und Tests aktualisieren.

## Offene Pilotentscheidung

**Empfehlung (ENTWURF):** wenige freiwillige, überprüfbar autorisierte Websites mit verbreitetem Stack. Daran lassen sich Abwehr auf dem Webserver, verständliche Erklärungen und der Abgleich von Warnungen messen, ohne eine universelle Plattform zu versprechen.

## Interviewfragen

- Welchen Sicherheitsvorfall oder Hinweis hast du zuletzt erhalten?
- Was hast du danach tatsächlich gemacht?
- Welche Stelle war unverständlich oder zu zeitaufwendig?
- Was würde dich davon abhalten, einem automatischen Schutz zu vertrauen?
- Welche Maßnahmen würdest du selbst freigeben, welche niemals?
- Was müsste passieren, damit du den Dienst dauerhaft aktiviert lässt?

## Discovery-Artefakte

Jede Erkenntnis bekommt ein kurzes Issue mit Zielgruppe, Beobachtung, Häufigkeit, Risiko, Hypothese, Evidenz und Entscheidung. Personenbezogene Interviewdaten kommen nur mit Einwilligung ins öffentliche Repository.

## Als Nächstes

- [ ] Pilotpersona festlegen.
- [ ] Mindestens fünf Problemgespräche durchführen.
- [ ] Prototyp mit technisch unerfahrenen Menschen testen.
- [ ] Ein erstes Problem mit messbarem Nutzen auswählen (z. B. Zeit von neuer Lücke bis Regel).
