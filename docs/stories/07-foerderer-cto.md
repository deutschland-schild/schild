---
short: Unterstützer-CTO
group: Personas
description: "Sabine, CTO eines mittelständischen Software-Unternehmens, entscheidet, ob sie Schild unterstützt – und will Belege, Ehrlichkeit, klare Governance und keinen Lock-in."
role: "Sabine, CTO und mögliche Unterstützerin"
quote: "Wenn ich fördere, sollen alle Websites etwas davon haben. Ich will keinen Lock-in und kein Abo."
---

# Sabine, CTO und mögliche Unterstützerin

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Sabine gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Sabine ist CTO eines mittelständischen Software-Unternehmens mit eigenem Security-Team und Budget für Open-Source-Förderung. Sie überlegt, ob ihr Unternehmen den Prototyp unterstützt, mit Geld, Rechenleistung oder eigenen Systemen in der Alpha, und muss das vor ihrer Geschäftsführung vertreten. Sie liest Zusammenfassungen und springt gezielt in Details; die Detailprüfung übernimmt ihr Team. Sie will etwas fördern, das kleinen Organisationen hilft, und wissen, dass das Geld ankommt, wo es versprochen ist. Sie fürchtet überzogene Versprechen, unklare Trägerschaft, ungefragt als „Partner“ genannt zu werden, Lock-in und einen verschwiegenen Interessenkonflikt zwischen Initiative und ausführendem Dienstleister.

## User Stories

### US-FO-01: Den ehrlichen Stand sehen

Als Unterstützerin möchte ich auf einen Blick sehen, was heute funktioniert und was nicht, damit ich meiner Geschäftsführung nichts Falsches erzähle.

- **Gegeben** Sabine öffnet Website und Konzepte. **Wenn** sie den Stand sucht. **Dann** trennt jeder Abschnitt per Status-Markierung Konzept, Entwurf und Offenes.
- **Gegeben** eine beschriebene Funktion ist noch nicht gebaut. **Wenn** Sabine davon liest. **Dann** steht das dabei; keine Aussage erweckt den Eindruck, sie laufe schon.
- **Gegeben** es gibt noch keine Messungen zur Wirkung. **Wenn** Sabine nach Zahlen fragt. **Dann** sagt das Projekt das, statt Zahlen zu schätzen.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md) (Ehrlicher Stand)

### US-FO-03: Kein Einfluss durch Geld

Als Unterstützerin möchte ich schriftlich sehen, dass Geldgeber keine Sicherheitsbewertungen bestimmen, damit niemand meinem Unternehmen später Einflussnahme vorwirft.

- **Gegeben** Sabines Unternehmen fördert. **Wenn** es eine Regel oder Bewertung ändern will. **Dann** bleibt ihm nur der öffentliche Weg, der allen offensteht.
- **Gegeben** die Grundsätze. **Wenn** Sabine sie liest. **Dann** steht dort, dass Geldgeber, Hoster, Staat oder einzelne Anbieter Sicherheitsbewertungen nicht bestimmen.
- **Gegeben** ein unabhängiger Beirat ist geplant. **Wenn** Sabine nach Interessenkonflikten fragt. **Dann** wird erklärt, wie sie dokumentiert werden und dass Geldgeber den Beirat nicht dominieren.

Bezug: [Verbindliche Grundsätze](../concept/00-grundsaetze.md) (Grundsätze), [Governance, Gemeinnützigkeit und Projektträgerschaft](../concept/05-governance-und-traegerschaft.md) (Governance), [`SEC-03`](../concept/19-spezifikation.md)

### US-FO-05: Kein Lock-in

Als Unterstützerin möchte ich, dass das Geförderte weiterlebt, auch wenn die Initiative endet, damit die Investition nicht verloren ist.

- **Gegeben** Code, Protokoll und Regelformate. **Wenn** Sabine die Lizenzen prüft. **Dann** sind sie Open Source und ohne Erlaubnis der Initiative betreibbar.
- **Gegeben** die Initiative stellt die Arbeit ein. **Wenn** Websites weiterlaufen. **Dann** schützen die Gateways weiter mit den zuletzt bestätigten Regeln, und andere Labs können übernehmen.
- **Gegeben** ein Trägerwechsel wird nötig. **Wenn** er ansteht. **Dann** ist vorher geregelt, wie Code, Domains und Schlüssel übergehen.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md), [`ARC-02`](../concept/19-spezifikation.md), [Governance, Gemeinnützigkeit und Projektträgerschaft](../concept/05-governance-und-traegerschaft.md) (Governance)

### US-FO-06: Wirkung belegen

Als Unterstützerin möchte ich nach der Alpha messbare Ergebnisse sehen, damit ich entscheiden kann, ob wir weiter fördern.

- **Gegeben** die Alpha auf eigenen Projekten und bei befreundeten CTOs ist abgeschlossen. **Wenn** berichtet wird. **Dann** gibt es Testprotokolle mit gemessenen Werten, etwa Fehlsperren und Anteil der Freigaben an allen Sperren.
- **Gegeben** ein Ergebnis ist schlecht. **Wenn** es berichtet wird. **Dann** steht es genauso im Bericht wie gute Ergebnisse.
- **Gegeben** nur ein Lab läuft. **Wenn** über Konsens berichtet wird. **Dann** steht dort, dass es noch keinen Konsens unabhängiger Betreiber gibt.

Bezug: [Testkonzept](../concept/14-testkonzept.md), [Produkt, UX und Onboarding](../concept/03-produkt-und-ux.md) (Einführung: klein anfangen)

### US-FO-08: Nicht ungefragt als Partner auftauchen

Als Unterstützerin möchte ich selbst entscheiden, ob und wie mein Unternehmen genannt wird, damit wir nicht ohne Zusage als Partner gelten.

- **Gegeben** Sabines Unternehmen hat nichts zugesagt. **Wenn** jemand Website und Konzepte durchsucht. **Dann** taucht es dort nicht als Partner oder Unterstützer auf.
- **Gegeben** eine Zusage ist dokumentiert. **Wenn** das Unternehmen genannt wird. **Dann** in der Form, die Sabine freigegeben hat.

Bezug: [Governance, Gemeinnützigkeit und Projektträgerschaft](../concept/05-governance-und-traegerschaft.md)

## Gestrichene Stories

US-FO-02, US-FO-04 und US-FO-07 sind gestrichen. Die Nummern bleiben frei.
