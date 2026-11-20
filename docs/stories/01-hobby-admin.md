---
short: Hobby-Admin
group: Personas
description: "Jens, Elektriker und ehrenamtlicher Admin, betreut die Joomla-Seite seines Sportvereins am Wochenende auf einem günstigen Server."
role: "Jens, Hobby-Admin im Sportverein"
quote: "Ich bin Elektriker, kein Security-Experte. Ich wünsche mir einen Schutz, der einfach läuft und sich nur meldet, wenn ich wirklich etwas tun muss."
---

# Jens, Hobby-Admin im Sportverein

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Jens gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Jens ist Mitte 40, Elektriker und betreut ehrenamtlich die Joomla-Seite seines Sportvereins: Termine, Kontaktformular, Mitgliederbereich. Sie läuft auf einem günstigen Root-Server mit zu alter Distribution, den ein früheres Vorstandsmitglied eingerichtet hat. Jens kann per SSH Befehle aus Anleitungen kopieren und Joomla-Updates einspielen, meist samstags. Er will keine wöchentlichen Sicherheitsmeldungen lesen, aber im Ernstfall verstehen, was los ist, und es in einer Stunde beheben. Er fürchtet, sich auszusperren, Anrufe von Mitgliedern, die nicht mehr auf die Seite kommen, ein Werkzeug, das unverstanden am Server dreht oder Daten an Dritte gibt, und eine Installation, die er nie wieder loswird.

Wie ein Selbstbetreiber ohne Hoster an einen Bürgen kommt, um Signale ans Netz zu schicken, ist offen ([Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md), Abschnitt 5). Für den Schutz seiner Seite braucht Jens keinen: Regeln kommen auch ohne Bürgen an.

## User Stories

### US-HA-01: In Minuten installieren

Als Hobby-Admin möchte ich Schild mit wenigen kopierten Befehlen installieren, damit es mich nicht den ganzen Samstag kostet.

- **Gegeben** ein Debian- oder Ubuntu-Server mit Joomla hinter nginx oder Apache. **Wenn** Jens die Befehle aus dem Handbuch kopiert und `sudo schild setup` startet. **Dann** erkennt Schild den Stack, schlägt das Preset `joomla` vor und fragt nichts, was Fachwissen braucht.
- **Gegeben** eine Distribution ohne Support. **Wenn** Jens installiert. **Dann** läuft das statische Binary trotzdem; der Server-Check weist ruhig auf das Support-Ende hin.
- **Gegeben** die Installation ist fertig. **Wenn** Jens die Website aufruft. **Dann** läuft sie unverändert, und Schild startet im Modus `observe`.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md), [`SEC-05`](../concept/19-spezifikation.md)

### US-HA-02: Mich nie selbst aussperren

Als Hobby-Admin möchte ich meine eigene IP und meinen DynDNS-Namen freischalten, damit ich auch nach einer Regeländerung auf meinen Server komme.

- **Gegeben** Jens richtet Schild per SSH ein. **Wenn** `schild setup` läuft. **Dann** schlägt es vor, die IP der aktuellen SSH-Sitzung mit `level: no_block` freizuschalten.
- **Gegeben** Jens hat zu Hause eine wechselnde IP. **Wenn** er seinen DynDNS-Namen in die Allowlist einträgt. **Dann** löst Schild ihn regelmäßig auf und sperrt die aktuelle IP nie.
- **Gegeben** Jens sieht trotzdem die Sperrseite. **Wenn** er per SSH `schild allow --mine` ausführt. **Dann** ist seine IP sofort freigeschaltet.
- **Gegeben** eine freigeschaltete IP. **Wenn** von ihr Anfragen kommen. **Dann** protokolliert die WAF weiter, es gehen keine Signale an Labs, und die Freischaltung wird nie verteilt.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G1)

### US-HA-04: Verstehen, was passiert ist

Als Hobby-Admin möchte ich in Alltagssprache sehen, was Schild abgewehrt hat, damit ich es dem Vorstand erklären kann.

- **Gegeben** Schild hat eine Anfrage geblockt. **Wenn** Jens den Vorfall im Schild Dashboard öffnet. **Dann** sieht er, was die Anfrage wollte, welche Regel woher gegriffen hat und wie er die Sperre zurücknimmt.
- **Gegeben** eine ruhige Woche mit vielen abgewehrten Scans. **Wenn** Jens das Dashboard öffnet. **Dann** sieht er eine kurze Zusammenfassung statt einer Liste roter Warnungen.
- **Gegeben** eine geblockte Anfrage hat einen Joomla-Fehler ausgelöst. **Wenn** Jens die Fehlerübersicht öffnet. **Dann** hebt Schild das als möglichen Hinweis auf eine echte Lücke hervor.

### US-HA-05: Zu Unrecht gesperrte Mitglieder freigeben

Als Hobby-Admin möchte ich Freigabe-Anträge mit einem Klick beantworten, damit ein gesperrtes Mitglied nicht lange wartet.

- **Gegeben** ein Mitglied wurde gesperrt. **Wenn** es die Sperrseite sieht. **Dann** stehen dort eine Vorfall-Nummer, der voraussichtliche Ablauf der Sperre und der Button „Freigabe beantragen“.
- **Gegeben** ein Antrag liegt vor. **Wenn** Jens Mail oder Dashboard öffnet. **Dann** sieht er Vorfall, Grund und Regel und gibt mit einem Klick befristet frei oder lehnt ab.
- **Gegeben** Jens reagiert am Wochenende nicht. **Wenn** die Sperre abläuft. **Dann** kommt das Mitglied ohne Zutun wieder auf die Seite.

Bezug: [Produkt, UX und Onboarding](../concept/03-produkt-und-ux.md) (Entsperren beantragen), [`ARC-03`](../concept/19-spezifikation.md)

### US-HA-09: Ausfall und Deinstallation ohne Folgen

Als Hobby-Admin möchte ich, dass ein Ausfall von Schild die Seite nicht lahmlegt und ich Schild wieder loswerde, damit ich beim Ausprobieren nichts riskiere.

- **Gegeben** der Schild-Prozess ist abgestürzt. **Wenn** Besucher:innen die Seite aufrufen. **Dann** bleibt sie erreichbar.
- **Gegeben** kein Lab ist erreichbar. **Wenn** Angriffe kommen. **Dann** schützt Schild weiter mit den zuletzt bestätigten Regeln.
- **Gegeben** Jens entfernt Schild nach Handbuch. **Wenn** er fertig ist. **Dann** läuft die Website wie vorher, und in der Webserver-Konfiguration bleibt nichts von Schild zurück.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md) (Local First, fail-open)

### US-HA-10: Wissen, ob eine Warnung mich betrifft

Als Hobby-Admin möchte ich bei einer neuen Sicherheitswarnung in einem Satz erfahren, ob sie meine Seite betrifft, damit ich nicht selbst Versionen vergleichen muss.

- **Gegeben** eine neue Warnung zu einer Joomla-Erweiterung. **Wenn** Schild sie mit der Umgebung des Servers abgleicht. **Dann** sieht Jens eines von: betroffen · abgefedert · wahrscheinlich nicht betroffen · unklar. Nie „alles sicher“.
- **Gegeben** das Ergebnis ist „betroffen · abgefedert“. **Wenn** Jens es öffnet. **Dann** steht dort, dass eine Regel aus dem Netz die bekannten Angriffe bis zum Update abfängt, und welches Update er einspielen soll. Einspielen muss er es selbst.
- **Gegeben** das Ergebnis ist „unklar“. **Wenn** Jens es öffnet. **Dann** bekommt er einen Befehl zum Prüfen, z. B. `openssl version`.
- **Gegeben** der Abgleich ist gelaufen. **Wenn** Jens nachsieht, was den Server verlassen hat. **Dann** steht dort: Die Liste der Software und Versionen bleibt auf dem Server.

Die Quelle der Warnungen im Netz ist ZU PRÜFEN.

Bezug: [Produkt, UX und Onboarding](../concept/03-produkt-und-ux.md) (Sicherheitswarnungen), [Architektur V1](../concept/21-architektur-v1.md) Abschnitt 2.1

## Gestrichene Stories

US-HA-03, US-HA-06, US-HA-07 und US-HA-08 sind gestrichen. Die Nummern bleiben frei.
