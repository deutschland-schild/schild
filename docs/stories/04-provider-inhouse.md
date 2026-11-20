---
short: Provider in-house
group: Personas
description: "Miriam verantwortet Plattform-Security bei einem großen Hosting-Provider, der Gateways, Lab, Relays und Dashboard selbst betreibt – ohne das Netz zu dominieren."
role: "Miriam, Plattform-Security bei einem großen Hosting-Provider"
quote: "Wir wollen alles selbst betreiben und trotzdem von dem lernen, was andere Labs finden."
---

# Miriam, Plattform-Security bei einem großen Hosting-Provider

**Status:** ENTWURF. Persona und Stories sind Annahmen aus der Discovery. Das Schild Gateway ist als Alpha veröffentlicht; was davon gebaut ist, steht in der [Gateway-Doku](../gateway/01-funktionen.md).

> **Erfundene Persona.** Miriam gibt es nicht. Persona und Zitat sind unsere Annahmen darüber, was Menschen in dieser Rolle brauchen. Das Zitat ist ein angenommener Wunsch und keine Kundenstimme. Die Stories beschreiben Ziele, keinen heutigen Stand.

## Persona

Miriam leitet das Plattform-Security-Team bei „Provider Nordstern“, einem großen Hosting-Provider (ausgedachter Name, kein echtes Unternehmen) mit Root- und Managed-Servern, Shared Hosting und Website-Baukasten. Das Team hat Honeypots, ein Abuse-Desk, Rechenkapazität und ein Kundencenter. Miriam denkt in Rollouts, SLOs und Datenschutz-Folgenabschätzungen. Sie will alle Bausteine selbst betreiben (Schild Gateway, Schild Lab, Relay, Log, Schild Dashboard) und Kund:innen Grundschutz ohne Zusatzaufwand bieten. Sie sorgt sich, was andere Labs von ihren Kund:innen sehen, dass ein Fehler im eigenen Lab sehr viele Websites gleichzeitig trifft und dass man Nordstern vorwirft, als Großer das Netz zu bestimmen.

## User Stories

### US-PR-01: Gateways vorinstallieren

Als Provider möchte ich Schild auf Root- und Managed-Servern über unseren eigenen Paketspiegel vorinstallieren, damit alle Kund:innen ab dem ersten Tag Grundschutz haben.

- **Gegeben** ein eigener Spiegel der Schild-Paketquelle. **Wenn** ein neuer Server aus dem Image entsteht. **Dann** ist Schild installiert und die Paketsignatur gegen den veröffentlichten Schlüssel geprüft.
- **Gegeben** das vorinstallierte Gateway. **Wenn** eine Kundin es im Kundencenter abschaltet. **Dann** läuft ihre Website ohne Schild weiter, und die Entscheidung steht in ihrem Protokoll.
- **Gegeben** Shared Hosting ohne Root. **Wenn** Miriam den Rollout plant. **Dann** sieht sie im Konzept, dass das über einen vorgeschalteten Reverse-Proxy laufen soll und noch nicht entschieden ist.

Bezug: [Technik kompakt](../concept/13-technik-kompakt.md) (Beispiel Provider in-house)

### US-PR-02: Eigenes Lab, aber nur eine Stimme

Als Provider möchte ich ein eigenes Lab mit Honeypots und Sandboxen betreiben, damit unsere Erkenntnisse ins Netz fließen, ohne dass wir allein Regeln durchsetzen können.

- **Gegeben** das Nordstern-Lab schlägt eine Regel vor. **Wenn** kein Lab eines anderen Betreibers den Angriff nachstellt. **Dann** wird die Regel nicht gemeinsam signiert und erreicht keine Gateways über `observe` hinaus.
- **Gegeben** Nordstern betreibt mehrere Labs. **Wenn** sie dieselbe Regel bestätigen. **Dann** zählen sie als ein Betreiber.
- **Gegeben** Nordstern bürgt für sehr viele Clients. **Wenn** eine Empfehlung gezählt wird. **Dann** trägt Nordstern höchstens ein Drittel der Belege.

Bezug: [Lab-Betreiberin](05-lab-betreiber.md), [`SEC-03`](../concept/19-spezifikation.md), [`ARC-02`](../concept/19-spezifikation.md), [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G2)

### US-PR-04: Dashboard im Kundencenter

Als Provider möchte ich das Schild Dashboard ins Kundencenter einbinden, damit Kund:innen keinen weiteren Login brauchen.

- **Gegeben** das gehostete Dashboard im Kundencenter. **Wenn** ein Kundenserver verbunden wird. **Dann** baut der Server nur eine ausgehende Verbindung auf; am Server öffnet sich kein Port.
- **Gegeben** eine Kundin ändert den Modus. **Wenn** sie speichert. **Dann** muss sie erneut bestätigen, und der Schild-Kern auf ihrem Server prüft die Änderung mit demselben Validator wie `schild.yaml`.
- **Gegeben** eine Kundin will ihre Einstellungen mitnehmen. **Wenn** sie exportiert. **Dann** bekommt sie eine `schild.yaml`, die auch ohne Nordstern funktioniert.

### US-PR-07: Kund:innen bleiben frei

Als Provider möchte ich, dass Kund:innen weitere Labs wählen oder unseres abschalten können, damit uns niemand Lock-in vorwerfen kann.

- **Gegeben** eine Kundin mit Nordstern-Gateway. **Wenn** sie im Dashboard ein weiteres Lab hinzufügt. **Dann** gilt es ohne Zustimmung von Nordstern.
- **Gegeben** eine Kundin schaltet das Nordstern-Lab ab. **Wenn** neue Regeln kommen. **Dann** nimmt ihr Gateway nur Regeln der Labs an, die sie gewählt hat.
- **Gegeben** ein Signal vom Kundenserver. **Wenn** andere Labs es sehen. **Dann** sehen sie nur pseudonyme Daten und keine Besucher-IP, auch wenn Nordstern bürgt.

Bezug: [Architektur V1](../concept/21-architektur-v1.md)

### US-PR-08: Ein Fehler bleibt klein

Als Provider möchte ich, dass eine fehlerhafte Regel nicht auf allen Kundenservern gleichzeitig Schaden anrichtet, damit unser Support nicht überrollt wird.

- **Gegeben** eine neue Netzregel. **Wenn** sie verteilt wird. **Dann** läuft sie zuerst im Probelauf, dann nur bei einem kleinen Teil der Gateways.
- **Gegeben** eine Regel trifft auf einem Server ungewöhnlich viel unauffälligen Traffic. **Wenn** das Gateway das bemerkt. **Dann** setzt es sie lokal in den Probelauf und meldet das.
- **Gegeben** eine Regel muss netzweit zurück. **Wenn** Nordstern das allein auslösen will. **Dann** geht das nicht: Der Rückzug aller Netzregeln braucht mehrere Betreiber und nimmt nur Netzregeln zurück.

Bezug: [Manipulation und Poisoning](../concept/18-manipulation-und-poisoning.md) (G8), [`SEC-01`](../concept/19-spezifikation.md), [`SEC-02`](../concept/19-spezifikation.md)

## Gestrichene Stories

US-PR-03, US-PR-05, US-PR-06 und US-PR-09 sind gestrichen. Die Nummern bleiben frei.
