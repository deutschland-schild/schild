---
short: Red-Team-Review
group: Wie
description: "Wie ein kritisches CCC-Mitglied das Konzept zerlegen würde – typische Kritik, echte Lücken, Gegenmittel, ehrlichere Sprache."
---

# Red-Team-Review: Was ein CCC-Vortrag zerlegen würde

**Status:** ENTWURF · interne Selbstprüfung von [Verbindliche Grundsätze](00-grundsaetze.md), [Produkt, UX und Onboarding](03-produkt-und-ux.md), [Technologie, KI und Sicherheitsarchitektur](04-technologie-und-security.md), [Governance, Gemeinnützigkeit und Projektträgerschaft](05-governance-und-traegerschaft.md), [Offene Fragen, Annahmen und Risiken](11-offene-fragen-und-risiken.md), [Technik kompakt](13-technik-kompakt.md), [Testkonzept](14-testkonzept.md) und Startseite · Stand Oktober 2026

**Kurz:**

- Interne Selbstprüfung: wie ein kritischer CCC-Vortrag das Konzept angreifen würde, mit Urteil je Kritikpunkt und fehlenden Gegenmitteln.
- Lücken nach Schwere: kritisch K1–K7, hoch H1–H10, mittel M1–M8.
- K1 und K2 (HMAC-Schlüssel, IP-Bewertungen im Log) sind mit E4 entschieden: Signale enthalten keine IPs.
- Noch offen u. a.: Fail-open per Timeout (K3), Grundregeln ohne Konsens (K4), Sybil-Clients (K5), steuerbare Rückkopplung (K6), zu mächtige Fernregeln (K7).
- Abschnitt 4 listet angreifbare Formulierungen mit ehrlicheren Alternativen; Folgeaufgaben gehen nach [Offene Fragen](11-offene-fragen-und-risiken.md) und [Testkonzept](14-testkonzept.md).

## Bereits erledigt

| # | Befund | Gelöst durch |
| --- | --- | --- |
| K1 | Gemeinsamer HMAC-Schlüssel ist faktisch öffentlich: Jedes Gateway braucht ihn, 2^32 IPv4-Werte sind in Minuten durchgerechnet, mit öffentlichem Log wäre jede bewertete IP rückrechenbar. | ENTSCHIEDEN (26.10.2026): Signale enthalten keine IPs, auch nicht gehasht oder als Pseudonym; kein IP-Netzwissen ([Prototyp-Verifikation](23-verifikation.md), E4) |
| K2 | Öffentliches Transparenz-Log mit IP-Bewertungen wäre ein ewiges Register pseudonymer Personen und kollidiert mit der Löschpflicht (Art. 17 DSGVO). | ENTSCHIEDEN (26.10.2026): ins Log nur Regeln, Presets, Lab-Schlüssel und Commitments; keine Bewertungen pro IP im Netz (E4) |
| – | „KI entscheidet / Halluzination“ | Entschärft: KI nur Zweitmeinung, nie allein über Schwellwert; Regressionstest, Schattenmodus, Reproduktion durch andere Labs (04, 13, T24). Rest-Risiko Prompt Injection siehe Abschnitt 1. |

## 1. Typische Kritik – trifft sie zu?

| Kritik | Urteil | Begründung (Konzeptstelle) | Was fehlt |
| --- | --- | --- | --- |
| **Zentraler Kill Switch / MITM à la Cloudflare** | teilweise entschärft | Innerer Modus hinter nginx, TLS bleibt beim Betreiber; kein Master-Lab, k-von-n (04). Aber Linie 2 „Managed Reverse-Proxy … ähnlich großen CDN-Anbietern“ (03, Produktlinien) **ist** zentrale TLS-Terminierung, und eine Konsensregel kann alles blocken oder per `ctl:ruleEngine=Off` den Schutz abschalten. Die Startseite sagt „Kein zentraler Ausschalter“, [Offene Fragen, Annahmen und Risiken](11-offene-fragen-und-risiken.md) listet „Kill Switch“ als OFFEN. | K7; Obergrenze für den Anteil betroffener Requests pro Regel; Linie 2 nur mit Keyless-/Hoster-eigener TLS und öffentlicher Betreiberliste; Widerspruch zur Startseite auflösen. |
| **Überwachungsinfrastruktur / VDS durch die Hintertür** | teilweise entschärft | Positivliste, lokales Protokoll jedes Signals, OHTTP optional (04). Der IP-Teil ist mit E4 erledigt. | H7; OHTTP Pflicht ab v1 ([`auth.md`](../../contracts/auth.md)). |
| **Behörden-Labs (BSI unter BMI) → Zensur-/Sperrinfrastruktur** (Zugangserschwerungsgesetz, Chatkontrolle) | **trifft zu** | „Keine gezielten Regeln“ (04) ist technisch nicht durchsetzbar: Eine Regel auf `/wp-json/vereinsplaner/v1/…` gilt für alle, trifft aber faktisch eine Site. `baseline_rules: bsi-baseline` (13) läuft offenbar **ohne** Konsens. Ein künftiges Gesetz könnte die Infrastruktur zur Sperrliste umwidmen. | K4; maximale Spezifität für Fernregeln (keine Hostnamen, keine Einzelpfade unter einer Mindestverbreitung); Behörden nie in der *Standard*auswahl stimmberechtigt; Warrant Canary, Charta mit Austrittsautomatik; öffentlich sagen, was bei einer Sperranordnung passiert (Abschalten statt Umsetzen). |
| **„Cyberdome“/Hackback-Rhetorik, Name klingt nach Landesverteidigung** | **trifft zu** | „Cyber-Grundschutz für alle“, „KI-basierte Abwehr“; der Entwurf des Cyber Solidarity Act (VO 2025/38) hieß „European Cyber Shield“; „Cyber-Grundschutz“ kollidiert mit BSI-„IT-Grundschutz“. Hackback gibt es im Konzept nicht, die Sprache klingt danach. | Abschnitt 4. |
| **WAF = Security Theater, Patchen schlägt WAF** | teilweise entschärft | [Produkt, UX und Onboarding](03-produkt-und-ux.md) setzt auf „Erkennen → beheben“. Die Startseite verkauft das Gateway aber als Schutz. CRS ist mit Encoding, Parser-Differentials, JSON/Multipart-Tricks und Body-Limits umgehbar; sqlmap-`--tamper` steht selbst im Testkonzept (14, §3). | Virtuelles Patching als *Überbrückung* kommunizieren, jede Sperre verlinkt auf das fehlende Update; Kennzahl „Tage bis Patch“. |
| **False Positives** | teilweise entschärft | Autoverify, Schattenmodus, Canary, Freigabe-Flow (04). Aber Default ist Autoblock, CRS-Paranoia-Level ungeklärt, und Kollaboration erhöht Fehlalarme (Melis/Pyrgelis/De Cristofaro, SIGCOMM CCR 2018). | Default-Paranoia-Level 1, die ersten 14 Tage „Beobachten“, Fehlalarmrate pro Regel öffentlich. |
| **IP-Blocklisten treffen CGNAT/Tor/VPN** | teilweise entschärft | „Nie allein wegen der IP sperren“ (04), aber Event-Kreislauf Schritt 6 schickt „IPs zum Blocken automatisch an den Client“. Preset „Deutscher Verein“ stellt Login aus Nicht-EU (Tor, viele VPNs, Mitglieder im Ausland) unter PoW. | Schritt 6 streichen bzw. auf Autoverify begrenzen; Tor-Exits nie sperren, nur PoW; Geo-Preset opt-in. |
| **„Anonymisiert“ vs. pseudonymisiert (DSGVO)** | teilweise entschärft | 04 und 13 sagen „pseudonym“, die Startseite sagte „anonymisiert“. Pseudonyme Daten bleiben personenbezogen (EDPB-Leitlinien 01/2025, vgl. EuGH Breyer C‑582/14). EuGH EDPS/SRB C‑413/23 P (4.9.2025) erlaubt einen relativen Ansatz: Ein Lab ohne Mittel zur Re-Identifizierung könnte anonyme Daten verarbeiten, ein Client nie. Gemeinsame Verantwortlichkeit (Art. 26, vgl. EuGH Fashion ID C‑40/17) ist ungeklärt. | Startseite korrigieren; Rollenmodell (Art. 26 vs. 28) und DSFA vor Pilot. Mit E4 und OHTTP ab v1 trägt das SRB-Argument für Labs ([Datenschutz](24-datenschutz.md), Abschnitt 4). |
| **Data Poisoning / Sybil / Weaponisierung gegen Konkurrenz** | **trifft zu** | Lab-Konsens schützt gegen ein lügendes *Lab*, nicht gegen viele Fake-*Clients*, die *alle* Labs füttern. „3 Clients bei 2 Betreibern“ ist bei domainlosen, rotierenden Schlüsseln (04) nicht prüfbar. Vertrauen über Trefferquote ist per On-Off-Angriff spielbar (Li/Meng/Kwok 2018). | K5; Honeypots als Ground Truth; nur unveränderte, öffentliche Erkennungsszenarien zählen (wie bei CrowdSec). |
| **Prompt Injection in die Lab-KI** | offen | Rest-Risiko aus „KI entscheidet“: Honeypot-Payloads und Signale gelangen in die Lab-KI (04 nennt das nur allgemein). | Lab-KI ohne Zugriff auf Signierschlüssel; Payloads nur als Daten, nie im Prompt-Kontext mit Werkzeugen. |
| **Exploit-Forschung mit KI = Dual Use, § 202c** | teilweise entschärft | Testlab rechtlich gerahmt (14, §3). Ungelöst: Eine Regel gegen eine **selbst gefundene** Lücke im **öffentlichen** Log legt die Lücke vor dem Patch offen. | H9; CVD-Policy nach ISO/IEC 29147 mit Frist (90 Tage); § 202c-Gutachten vor Lab-Start. |
| **PoW: Barrierefreiheit, alte Geräte, Energie, Anubis-Kritik** | **trifft zu** | „Bots scheitern“ (03, 04) ist falsch: Ein Botnetz rechnet PoW verteilt und billig, ein altes Android braucht für die „etwa eine Sekunde“ zehnmal so lange. Anubis wurde genau dafür kritisiert. Der Weg ohne JS ist unspezifiziert. | PoW als Kostenbremse kommunizieren; adaptive, gedeckelte Schwierigkeit; Privacy-Pass-Token als Alternative; WCAG-2.2-Test mit Screenreadern; No-JS-Weg definieren. |
| **Lieferkette: auto-updatender Proxy vor jeder Website** | teilweise entschärft | Reproduzierbare Builds, k-von-n, TUF (04). Aber in [Technik kompakt](13-technik-kompakt.md) darf jedes Repository „Client-Updates“ veröffentlichen; wer Binärdateien signiert, steht nirgends; beim 2–3-Personen-Team ist k-von-n eher 2-von-3 *im selben Team*. | H8; Sigstore mit Transparenz; kein Auto-Update der Binärdatei per Default; Caddy-Module und Go-Abhängigkeiten einbeziehen. |
| **Egress-Proxy = TLS aufbrechen** | teilweise entschärft | 14, §6: bevorzugt nur Metadaten. Die Signatur über `Body-Hash` setzt aber voraus, dass der Proxy den Body sieht. | M6; nur SNI/Ziel/Menge, Signatur ohne Body-Hash; keine TLS-Interception im Produktiv-Betrieb. |
| **Abhängigkeit von Stiftung/Großhoster** | teilweise entschärft | Charta, Projektvereinbarung mit dem Fiscal Host Punkt 6 (05), „Sponsoring ohne Einfluss“ (08). Aber die Startseite zeigt „Mein Hoster“ vorausgewählt neben „Deutschland-Schild“, also schon Konsens. Ein großer Hoster kann Geldgeber, Default-Lab und Stufe-2-Betreiber zugleich sein. | H4, H5, M8; kein Geldgeber > 25 % des Budgets und keiner als stimmberechtigtes Default-Lab; Finanzbericht mit Namen. |
| **„Ihr erfindet CrowdSec/Cloudflare neu“** | **trifft zu** | CrowdSec hat Caddy-Bouncer, Coraza/CRS-AppSec, Blocklist mit Trust-Score, Honeypots und zählt nur unveränderte Hub-Szenarien. Der echte Unterschied ist **Governance**, nicht Technik. | Vor der ersten Zeile Code: schriftlicher Abgleich mit CrowdSec und BunkerWeb, Gespräch über föderierten Betrieb; Unterschied offen als Governance benennen. |

**Ergebnis:** Wirklich entschärft sind nur „KI entscheidet“ und, für Linie 1 im inneren Modus, die MITM-Kritik. Konsens und Opt-in helfen gegen den Missbrauch durch ein einzelnes Lab, nicht gegen Sybil-Clients, Grundregeln und die Sprache. Solange Autoblock und eine vorausgewählte Quellenliste Standard sind, gilt: Wer die Defaults setzt, regiert (vgl. Root-Stores der Browser).

## 2. Architekturlücken, die noch nicht adressiert sind

### 2.1 Kritisch

K1 und K2 sind erledigt (siehe „Bereits erledigt“).

| # | Lücke | Warum | Lösung | Status |
| --- | --- | --- | --- | --- |
| K3 | **Fail-open pro Request auslösbar** | `error_page 502 503 504 = @schild_bypass` (04) leitet bei Timeout den *gleichen* Request ungefiltert ans Backend. Ein Payload, der Coraza langsam macht (ReDoS, verschachteltes JSON/Multipart, übergroßer Body), kommt so ohne Absturz durch. Ein Crash des Gateways schaltet den Schutz für alle ab. | Fail-open nur für Verbindungsfehler (502 bei *refused*), nie bei 504; bei Timeout 503 an den Client. Harte Body-/Parse-Limits mit „deny bei Überschreitung“ (`SecRequestBodyLimitAction Reject`). Circuit Breaker: fail-open nur nach N Fehlern in Folge, mit Alarm. Fuzzing des Gateways (go-fuzz, OSS-Fuzz). Test T12 um „Timeout-Bypass“ erweitern. | OFFEN |
| K4 | **Grundregeln ohne Konsens** | `baseline_rules:` (13) sind Einzelquellen; Konsens gilt nur für „Bewertungen“. Eine Behörde oder ein kompromittiertes Grundregel-Repo kann allein ausrollen. | Grundregel-Updates ebenfalls k-von-n verschiedener Organisationen, oder neue Versionen nur im Modus „Prüfen“, oder Version gepinnt mit lokalem Diff. | OFFEN |
| K5 | **Sybil auf Client-Ebene; Lab-Konsens ist korreliert** | Alle Labs bewerten dieselben Signale derselben (ggf. gefälschten) Clients. „2 Betreiber“ ist bei domainlosen, rotierenden Schlüsseln unprüfbar. | Knappe, anonyme Client-Berechtigung: **Privacy Pass** (RFC 9576/9578), ausgegeben gegen Nachweis (Domain-Kontrolle per ACME-ähnlicher Challenge bei einem Issuer, nicht beim Lab). Rate-Limited Tokens pro Zeitfenster. Labs stützen Bewertungen auf *eigene* Belege (Honeypots, Reproduktion), nicht nur auf Client-Meldungen. | OFFEN |
| K6 | **Angreifer steuern die Rückkopplung** | „Besteht ein Absender die Prüfung, geht ein Fehlalarm-Signal“ und „Steigt die Bestehensquote, wird die Regel automatisch zurückgezogen“ (04). Ein Botnetz, das PoW billig löst, wertet so gezielt die Regel ab, die es stört, und zieht Canary-Regeln zurück. | Bestehensquote nur aus Requests, die *keine* gefährliche Aktion versuchen; Fehlalarm-Signale nur aus Freigaben durch Betreiber (Mensch), nicht aus PoW. Rückzug nie automatisch, sondern Alarm + Konsens. | OFFEN |
| K7 | **Fernregeln sind mächtiger als behauptet** | „Regeln können nur prüfen, blocken, Captcha“ (04) stimmt für SecLang nicht: `ctl:ruleEngine=Off`, `ctl:ruleRemoveById`, `setvar`, `logdata`/`msg` mit `%{REQUEST_HEADERS.Cookie}`. Letzteres schleust Cookies in Events, die ans gehostete Dashboard gehen. Eine Regel `@rx .` + `deny` ist ein globaler Ausschalter. | Fernregeln nur in einer **Allowlist-Teilmenge** von SecLang (Operatoren/Aktionen), Validator im Gateway; `logdata` auf Positivliste; Kappung: Eine Regel, die > x % des legitimen Traffics trifft, wird lokal ausgesetzt. Getrennte Schlüssel für Regeln und Binärdateien. | OFFEN |

### 2.2 Hoch

| # | Lücke | Lösung | Status |
| --- | --- | --- | --- |
| H1 | **Signale verraten verwundbare Ziele.** `kategorie`, `aktion_sig`, `waf_regeln` und gewählte Presets („PHP 7.4“) sagen einem Lab (oder dem, der es hackt), welche Site welchen Stack hat. OHTTP ist nur „optional“; ohne OHTTP verrät die Absender-IP des Servers die Domain (Reverse-DNS, Zertifikate). | OHTTP verpflichtend; Presets nie im Signal; Aggregation am Client vor Versand (DAP/Prio, RFC-Entwurf `draft-ietf-ppm-dap`) für Statistik; k-Anonymität ≥ 10 Sites, bevor eine Signatur Labs erreicht. |
| H2 | **Metadaten über Timing und Volumen.** Signale in Echtzeit zeigen, wann eine Site angegriffen wird und wie groß sie ist. | Batching mit Jitter (z. B. 5 min), Padding auf feste Größen, Dummy-Signale. Zielkonflikt mit Time-to-Protect < 5 min (14) offen benennen. |
| H3 | **Transparenz-Log ohne Witnesses.** „Clients gleichen den Log-Stand untereinander ab“ (04), aber Clients hinter NAT ohne P2P können das nicht. Split View bleibt möglich. | Witness-Cosigning nach C2SP `tlog-witness`/`tlog-cosignature` (Sigsum-Modell); Client akzeptiert nur Checkpoints mit ≥ 2 Witness-Signaturen verschiedener Organisationen; Witnesses ≠ Labs. |
| H4 | **Default-Quellenliste = Gatekeeper.** Wer die vorausgewählten Labs festlegt, hat die Macht, die das Konzept dezentralisieren will. Aufnahmekriterien „OFFEN“ (04). | Default-Liste als öffentliches Repo mit Aufnahmeverfahren wie die Mozilla Root Store Policy, Entscheidung durch Beirat + öffentliche Kommentierung; Default-Mix ohne Behörden-Stimmrecht und ohne Geldgeber. |
| H5 | **Kollusion großer Betreiber.** Zwei große Hoster mit hohem Default-Gewicht erreichen 0,6 und „2 Betreiber“ allein. | Kein Betreiber > 1/3 des Default-Gewichts; Konsens verlangt mindestens zwei *Betreiberarten* (Community + Nicht-Community). |
| H6 | **JA4 im inneren Modus nicht verfügbar.** Hinter nginx terminiert nginx TLS; das Gateway sieht kein ClientHello, die Client-Signatur funktioniert im Standardmodus nicht. Die Client-IP kommt nur über `X-Forwarded-For`, fälschbar bei falscher Trust-Konfiguration. | JA4 nur im äußeren Modus oder per nginx-Modul durchreichen; `trusted_proxies` streng auf 127.0.0.1; JA4+ meiden (FoxIO-Lizenz verbietet kommerzielle Nutzung, Problem für Hoster), nur BSD-lizenziertes JA4. |
| H7 | **Gehostetes Dashboard ist eine zentrale Datensammlung mit Klar-IPs** (04, Event-Kreislauf 5–6). | Gehostetes Dashboard erhält nur die Signale, nicht Events; oder AV-Vertrag, Speicherfrist 7 Tage, Standort und Betreiber auf der Startseite. |
| H8 | **Binär-Updates aus beliebigen Repositories** (13: Repository veröffentlicht „Client-Updates“). | Siehe Lieferkette: ein Release-Kanal, getrennte Schlüssel, SLSA L3, unabhängige Rebuilder. |
| H9 | **Offenlegung vor Patch durch öffentliche Regeln** (siehe Dual Use). | Commit-then-Reveal im Log, Embargo-Fristen. |
| H10 | **Haftung bei Fehlsperre.** Autoblock by default sperrt Patient:innen einer Praxis aus; Labs haben empfohlen, der Betreiber hat nicht aktiv gewählt. [Governance, Gemeinnützigkeit und Projektträgerschaft](05-governance-und-traegerschaft.md) nennt Haftung nur als Vertragsposten. | Haftungsausschluss der Labs im Protokoll (Empfehlung, keine Zusicherung); Default-Modus juristisch bewerten; Pflicht-Hinweis beim Einrichten; Versicherung prüfen. |

### 2.3 Mittel

| # | Lücke | Lösung | Status |
| --- | --- | --- | --- |
| M1 | **Freigabe-Flow:** Der Betreiber sieht Kontaktdaten der Antragsteller:innen; das Formular ist ein Kanal für Phishing/Belästigung und bestätigt „diese Site läuft Schild in Modus X“. | Antrag per Default ohne Freitext, Links nicht klickbar; einheitliche Sperrseite verrät keine Version/Modus; Rate-Limit per Privacy-Pass-Token statt IP. |
| M2 | **„Uneinig = vorsichtig“** lässt ein einzelnes Lab Autoverify für eine Signatur erzwingen: Reibung als Waffe. | Uneinigkeit → nur Beobachten, nicht PoW. |
| M3 | **Latenz bis Konsens vs. Time-to-Exploit:** k-von-n Signaturen über Organisationen in < 5 min (14) sind organisatorisch unrealistisch, wenn Menschen prüfen. | Zweistufig: schnelle, kurzlebige (≤ 1 h) Empfehlungen nur Autoverify; Block-Empfehlungen mit menschlicher Prüfung. |
| M4 | **Update-Kadenz vs. Stabilität.** CRS-Updates brechen regelmäßig Anwendungen. | Kanäle stable/testing wie Debian, gestaffelter Rollout per Canary auch für Grundregeln. |
| M5 | **Governance des Protokolls:** Wer ändert `schild.signal/0.x`? Markenrecht „Deutschland-Schild“ beim Träger macht Forks rechtlich angreifbar. | Spezifikation unter offener Lizenz bei neutraler Stelle (z. B. IETF-Draft oder eigener RFC-Prozess), Marke ≠ Protokoll; Fork-Recht ausdrücklich zusichern. |
| M6 | **Egress-Signatur:** Schlüssel in der kompromittierten App (14 benennt das). | Nur Sidecar-Schlüssel mit Ziel-Allowlist; Egress als Anomalieerkennung vermarkten, nicht als Signaturschutz. |
| M7 | **Betriebskomplexität:** zweiter Proxy, eigene Logik, Docker-Dashboard sind für Vereine ohne Admin unrealistisch; Linie 2 löst das nur durch Zentralisierung. | Offen sagen: Linie 1 ist für Admins und Hoster. Hoster-Integration ist der eigentliche Verteilungsweg. |
| M8 | **CRA:** Pflichten für Hersteller (Hoster, die Schild vertreiben) und Steward-Rolle des Trägers (Art. 24). | CRA-Rollenmodell in [Governance, Gemeinnützigkeit und Projektträgerschaft](05-governance-und-traegerschaft.md) aufnehmen. |

## 3. Top 10: Was ein CCC-Vortrag über Deutschland-Schild zerlegen würde

1. „Euer HMAC-Schlüssel steckt in jeder Installation.“ Erledigt (E4).
2. „Ein Request, der eure WAF in den Timeout schickt, geht über `@schild_bypass` ungefiltert durch.“ → K3
3. „Konsens unter Labs, die alle meine 5.000 Fake-Clients lesen, ist kein Konsens.“ → K5
4. „Mein Botnetz hat eure Proof-of-Work-Aufgabe gelöst und damit eure Lieblingsregel abgeschaltet.“ → K6
5. „Die BSI-Grundregeln laufen am Konsens vorbei; das ist Sperrinfrastruktur mit besserem Marketing.“ → K4
6. „Hier ist `ctl:ruleEngine=Off` und eine `logdata`-Regel, die Session-Cookies ans Dashboard schickt.“ → K7
7. „Euer Transparenz-Log ohne Witnesses zeigt mir, was ihr mir zeigen wollt.“ → H3
8. „Euer KI-Lab hat eine 0-Day drei Wochen vor dem Patch als Regel ins öffentliche Log gestellt.“ → H9
9. „Auf der Startseite ‚anonymisiert‘, im Konzept ‚pseudonym‘. Welche Seite lügt?“ → Abschnitt 4, Startseite an [Technologie, KI und Sicherheitsarchitektur](04-technologie-und-security.md) angleichen
10. „Ihr habt CrowdSec mit anderem Logo nachgebaut und startet mit genau einer Instanz.“ → öffentlicher CrowdSec-Abgleich; Dezentralität erst behaupten, wenn ≥ 3 unabhängige Labs laufen

## 4. Kommunikation: angreifbare Formulierungen

| Heute | Ort | Problem | Ehrlicher |
| --- | --- | --- | --- |
| „Auffälliges geht **anonymisiert** ans Dashboard und an die Schild-Labs“ | Startseite, Live-Simulation | Rechtlich falsch, widerspricht [Technologie, KI und Sicherheitsarchitektur](04-technologie-und-security.md) / [Technik kompakt](13-technik-kompakt.md). | „… geht **pseudonymisiert**, ohne Klar-IP und ohne Inhalte, an …“ |
| „**Nichts Persönliches** verlässt den Server“ | Startseite „Neutral“, 13 | Auch Land, ASN und Browser-Familie sind zusammen pseudonym, nicht anonym (EDPB 01/2025). | „Keine IP-Adressen und keine Inhalte verlassen den Server; was rausgeht, ist pseudonym.“ |
| „**DSGVO-konform by Design**“ | Hero-Merkmal | 04 sagt selbst: erst nach DSFA und Prüfung. Abmahn- und Glaubwürdigkeitsrisiko. | „Datensparsam gebaut – Datenschutzprüfung läuft.“ |
| „**Neutral**“ / „Neutral by Design“ | Startseite, 13 | Nicht beweisbar, solange Grundregeln am Konsens vorbeigehen und Defaults gesetzt werden. | „Überprüfbar: alle Regeln signiert und öffentlich protokolliert.“ |
| „**Kein zentraler Ausschalter**“ | Startseite | [Offene Fragen, Annahmen und Risiken](11-offene-fragen-und-risiken.md) plant einen Kill Switch; eine Konsensregel kann alles blocken. | „Keine einzelne Stelle kann allein Regeln ausrollen.“ |
| „**Deutschland-Schild**“ | Name | Klingt nach Staatsprogramm/Landesverteidigung (vgl. „European Cyber Shield“). | Prüfen: neutraler Projektname (z. B. „Schild – gemeinnütziger Webschutz“), „Deutschland“ allenfalls als Region. |
| „**Cyber-Grundschutz**“ | Hero | Kollision mit BSI-IT-Grundschutz, Behördennähe. | „Grundschutz für Websites“. |
| „**KI-basierte Abwehr**“ | Hero-Merkmal | Widerspricht „KI sperrt nicht“; Abwehr = Militärsprache. | „Regeln aus offener Forschung, KI hilft beim Einordnen.“ |
| „**Eine Website wird angegriffen – alle werden geschützt.**“ / „Alle sind geschützt“ | Hero, Simulation | Überversprechen; WAF ist umgehbar. | „… – die anderen sind früher gewarnt.“ |
| „**Bots scheitern**“ / „Ein Mensch besteht unsichtbar“ | 03, 04, Simulation | PoW stoppt keine Botnetze. | „Macht Massenanfragen teurer.“ |
| „**Empfehlungen** – nichts wird erzwungen“ bei **Autoblock by default** | 03, 13, Startseite | Default = faktische Entscheidung. | „Standard ist automatisches Blocken; du kannst es jederzeit umstellen.“ |
| „**Dezentral**“ | Startseite | Linie 1 = eine Instanz. | „Für Dezentralität gebaut – startet mit einer Referenz-Instanz.“ |

## Als Nächstes

- [ ] K3–K7 als Entscheidungen nach Vorlage in [Offene Fragen, Annahmen und Risiken](11-offene-fragen-und-risiken.md) aufnehmen (P0).
- [x] Startseite: „anonymisiert“, „nichts Persönliches“, „DSGVO-konform by Design“, „Kein zentraler Ausschalter“ ersetzen.
- [ ] Testkonzept 14 ergänzen: Timeout-Bypass (K3), PoW-lösendes Botnetz gegen Canary-Rückzug (K6), bösartige SecLang-Aktionen (K7).
- [x] CrowdSec-Abgleich: entschieden am 28.10.2026, keine Kopplung, Hub-Regeln als Kandidaten ([Quellen](22-quellen-cve-ip-crowdsec.md), §4).
- [ ] Externes Review dieses Dokuments durch Community (Einladung, keine Zusage).
