---
short: Kommunikation & Pitch
group: Offen & ehrlich
description: "Positionierung, Landingpage, Pitch – und was wir nicht behaupten."
---

# Landingpage, Kommunikation und Pitch

**Status:** Kernbotschaft ENTWURF · Anspruchsniveau muss technisch/juristisch geprüft werden

**Kurz:**

- Positionierung: offener Filter für Webserver (WAF) plus Netz unabhängiger Labs, Claim „Bedingungsloser Grundschutz für alle Websites.“; Kernbotschaft ist Entwurf.
- Quelle für Aufbau und Texte der Startseite ist die Startseite selbst (`site/app/pages/index.vue`); erste Zielgruppe sind Betreiber:innen ohne 24/7-Security-Team.
- Sprach- und Claim-Regeln stehen in der Marke; hier nur, was für Pitch und Kommunikation dazukommt.
- Enthält 30-Sekunden-Pitch, sieben Pitch-Folien und Beweisstücke; Bedarf: Sponsoren per Rechnung, GPU-Rechenleistung, Sparring, Alpha-Tester.
- Noch offen: technische und juristische Prüfung des Anspruchsniveaus, Impressum/Datenschutz, Abgleich der Website mit realen Prototyp-Fähigkeiten.

## Positionierung

**Deutschland-Schild** – Grundschutz für alle Websites.  
**Bedingungsloser Grundschutz für alle Websites.**  
Kostenlos, offen, gemeinnützig.

Wir bauen einen offenen Filter für Webserver (WAF) und ein Netz unabhängiger Labs. Sieht eine Website ein neues Angriffsmuster, prüfen es die Labs, und alle bekommen die passende Regel. Für alle ohne 24/7-Security-Team, vom Hobby-Admin über Start-ups bis zum Konzern.

Für Claims und Wortwahl gelten die Regeln der [Marke](../brand/01-marke.md#claims). Für Pitch und Kommunikation kommt dazu: keine unbewiesenen Logos, Partnerschaften, Zertifizierungen oder Aussagen wie „100 % sicher“.

So beschreiben wir den Stand: „Das Gateway ist als Alpha 0.1.0-alpha.1 veröffentlicht und läuft vor eigenen Projekten. Der Prototyp des Verbunds hat Stufe 2 im Testlabor bestanden (26.10.2026). Für die Alpha suchen wir Partner mit echten Systemen: Hoster, Agenturen, Open-Source-Projekte.“

## Zwei Zielgruppen, eine Website

**Für Nutzer:** „Endlich Sicherheit, die verständlich ist und mich wirklich weiterbringt.“

**Für Träger, Förderer und Partner:** „Ein konkreter technischer Ansatz mit fertigem Konzept, klarem Gemeinwohlauftrag, klein anfangendem Fahrplan und nachvollziehbarem Bedarf.“

## Kernbotschaften der Startseite

Die Startseite verkauft ein Produkt, das Schild Gateway, und hat eine Hauptaktion: „Schild Gateway installieren“ (Entscheidung Initiator, 01.11.2026). Sie spricht zuerst Betreiber:innen ohne 24/7-Security-Team an; Labs, Relays und Fahrplan stehen auf `/netz`. Was Betreiber:innen und Admins brauchen (Dashboard, Installation, Voreinstellungen, Fragen aus dem Alltag), steht seit 05.11.2026 direkt auf der Startseite; eigene Seiten für Security-Nerds und Unterstützer gibt es nicht mehr, die Technik steht in der Dokumentation. Die tragenden Botschaften der Website insgesamt:

1. **Sicherheit als Teamsport.** Jede Website im Verbund ist ein Sensor; was eine sieht, schützt alle. Geteilt werden Muster, keine Daten. Die Labs sind das Team dahinter.
2. **Sicherheit ist vor allem Bedienbarkeit.** Gute Voreinstellungen (Presets automatisch, 14 Tage beobachten, fail-open, Sperren laufen ab, Entsperr-Weg, Programm-Updates nie ohne Betreiber), Alltagssprache, Probelauf, alles rücknehmbar.
3. **Warum gerade Hobby-Admins es brauchen.** Angriffe kommen über gekaperte Privatgeräte (Residential Proxies) und mischen sich mit Bots und KI-Crawlern. Die Menge wächst monatlich. Gut von böse zu unterscheiden schafft ein Einzelner nicht mehr.
4. **Angreifer skalieren mit KI, die Abwehr auch.** KI arbeitet in den Labs (Patch-Diffing, Fuzzing, Honeypots, Regelvorschläge), nicht pro Request. Entschieden wird nach festen, getesteten Regeln.
5. **Das BSI warnt. Schild sagt dir, ob es dich betrifft.** Schild gleicht jede Warnung lokal mit der Umgebung ab (Software, Versionen); die Liste verlässt den Server nicht. Ergebnis in einem Satz: betroffen · abgefedert · wahrscheinlich nicht betroffen · unklar, nie „alles sicher“. Bis zum Update fängt eine Regel aus dem Netz die bekannten Angriffe ab ([Produkt, UX und Onboarding](03-produkt-und-ux.md), „Sicherheitswarnungen“). Das ist nicht der IT-Grundschutz des BSI, und es gibt keine Partnerschaft.
6. **Regeln statt IP-Listen, Labs statt Zentrale.** Der Vergleich mit fail2ban, CrowdSec und Cloudflare steht als Tabelle mit Quellen auf der Startseite. Kernsatz: „CrowdSec teilt IP-Adressen über eine Firma. Schild teilt geprüfte Regeln über unabhängige Labs.“ Gegen riesige DDoS-Angriffe auf Netzebene hilft ein großes Netz; Schild ersetzt das nicht, beides lässt sich kombinieren.

Aufbau der Startseite (Stand 01.11.2026): Hero mit Headline, einer Aktion und angeschnittenem Dashboard-Screenshot → Warum jetzt? → So funktioniert es → Was das Gateway mitbringt → Vergleich mit fail2ban, CrowdSec und Cloudflare → kurzer Hinweis auf das Schild-Netz → Häufige Fragen → Mehr für dich → Mitmachen. Bei Änderungen gilt der Code-Kommentar oben in `index.vue`.

## 30-Sekunden-Pitch

> Cybersicherheit schützt unsere Wertegesellschaft, unseren Wohlstand und die Zukunft der nächsten Generation. KI macht Angriffe billig und massenhaft, und viele Hobby-Admins, Vereine und kleine Websitebetreiber haben keine eigene Security-Abteilung. Deutschland-Schild ist ein offener Filter auf dem Webserver (WAF) plus ein Netz unabhängiger Labs: Sieht eine Website ein neues Angriffsmuster, prüfen es die Labs, und alle bekommen die passende Regel. Dazu sagt Schild bei jeder neuen Sicherheitswarnung, ob sie dich betrifft. Kostenlos, gemeinnützig, überparteilich, Open Source. Wir verbinden bestehende Open-Source-Sicherheit (Caddy, Coraza, OWASP CRS) mit kontrolliert betriebenen Open-Weight-KI-Modellen in den Labs. Das Gateway ist als Alpha veröffentlicht, das Netz der Labs ist als Prototyp gebaut und im Testlabor gemessen. Für den Prototyp suchen wir Sponsoren (per Rechnung), GPU-Rechenleistung, Sparring und Alpha-Tester.

## Sieben Pitch-Folien

1. **Warum jetzt?** Schnellere Angriffe, strukturelle Unterversorgung, gesellschaftliche Folgen (Wirtschafts- und Demokratieschutz).
2. **Das Problem:** Warnungen erreichen Betreiber:innen, aber niemand sagt ihnen, ob sie betroffen sind. Bis zum Update sind sie ungeschützt.
3. **Die Lösung:** WAF auf dem Webserver plus Netz unabhängiger Labs; Abgleich von Warnungen lokal; Server-Check nur lesend.
4. **Der Beweis:** der gebaute Prototyp mit den Messungen aus dem Testlabor ([Prototyp-Verifikation](23-verifikation.md)), ab der Alpha Demo auf echten Systemen; nur, was **tatsächlich vorhanden** ist.
5. **Warum wir anders arbeiten:** Open Source, Reuse First, lokale KI, dezentrale Architektur, UX, Company as Code.
6. **Umsetzungsmodell:** Träger, 2–3 Personen, Partner, externer Cybersicherheitsbeirat, Fahrplan in drei Phasen (Alpha → Externe Labs → Für alle).
7. **Der konkrete Bedarf:** Sponsoren für den Prototyp (per Rechnung), GPU-Rechenleistung, Sparring, Alpha-Tester, Warm-Intros, nächste Meilensteine. Keine Beträge.

## Beweisstücke für jeden Pitch

- Live-Demo / kurzes Video
- Was heute funktioniert / was noch nicht
- Pilot-User-Journey
- Erste Sicherheits-/Qualitätstests
- Budget mit Annahmen
- Governance-/Unabhängigkeitsrahmen
- Konkrete Bitte und nächster Termin

## Als Nächstes

- [ ] Domain, Kontakt, Impressum, Datenschutzhinweise klären.
- [ ] Website mit den realen Prototyp-Fähigkeiten abgleichen.
- [ ] 2-minütige Demo und 7-Folien-Pitch vorbereiten.
- [ ] Einseiter für Träger-/Fördergespräche exportieren.
