---
short: Manipulation & Poisoning
group: Wie
description: "Wie Betreiber, Fake-Clients, Angreifer und Labs das Netz mit falschen Signalen gegen Dritte richten könnten – und welche Regeln das verhindern: IPs nie verteilen, Muster nur mit eigener Reproduktion, Stimmen nach Bürgen statt nach Clients."
---

# Manipulation und Poisoning: Wer das Netz gegen andere richtet

**Status:** ENTWURF · Bedrohungsanalyse und Designänderungen zu [Technologie, KI und Sicherheitsarchitektur](04-technologie-und-security.md), [13](13-technik-kompakt.md), [14](14-testkonzept.md), [15](15-red-team-review.md) · Stand 25.10.2026

**Kurz:**

- Bedrohungsanalyse: wie Betreiber, Fake-Clients, externe Angreifer und Labs das Netz mit falschen Signalen gegen Dritte richten könnten (Varianten A1–E5).
- Grundannahme: Lügen lässt sich nicht verhindern, nur entwerten. Client-Signale sind Hinweise (`tip`); Regeln brauchen eigene Belege von Labs.
- Gegenmittel G1–G11: Zählung nach Bürgen statt Clients, Gates gegen Allergie-Regeln, Rückmeldung verengt statt abschaltet, Schutzliste, gestaffelte Höchstaktion.
- Seit E4 (26.10.2026) enthalten Signale keine Besucher-IPs, und es gibt kein IP-Netzwissen; aktuelles Format ist `schild.signal/0.3` laut `contracts/signal.md`.
- Ungelöst: Sybil (nur auf Bürgen verschoben), Privatheit vs. Rechenschaft, nicht reproduzierbare Verhaltensmuster, Geschwindigkeit vs. Gates. Neue Testfälle T27–T36.

**Frage des Initiators:** Wie verhindern wir, dass Betreiber von Schild Gateways (im Netz: Clients) gefälschte Signale einspeisen, um etwa Kund:innen eines Konkurrenten, einen Zahlungsdienst oder Googlebot netzweit sperren zu lassen oder legitime Endpunkte (eine fremde API, ein verbreitetes Plugin) zur Sperrregel zu machen?

**Kurzantwort:** Lügen selbst können wir nicht verhindern. Ein Betreiber baut ein korrekt signiertes Signal auch ohne echten Traffic; Signatur und Token beweisen nur, *wer* meldet, nie, *dass es stimmt*. Also darf sich Lügen nicht lohnen: IPs verlassen nie den Server (E4), Regeln brauchen eigene Belege von mindestens zwei Labs, gezählt wird nach Bürgen, und jede neue Regel hat einen begrenzten Schadensradius. Als Restrisiko bleibt Reibung (eine Rechenaufgabe mehr), keine Aussperrung.

## 1. Was ein Angreifer kontrolliert – und was nicht

| Akteur | Kontrolliert | Kontrolliert nicht |
| --- | --- | --- |
| **Böswilliger Client-Betreiber** (Konkurrent, Erpresser) | Inhalt, Zeitpunkt, Menge und Signatur seiner Signale; eigene Freigaben; beliebig viele Domains | Andere Clients, Labs, Bürgen; sein Token-Kontingent; die Reproduktion in Labs |
| **Externer Angreifer ohne Client** | Echten Traffic an Schild-Websites (Inhalte, Header inkl. `X-Forwarded-For`, Timing); Quell-IPs aus Proxy-Pools ([Mi et al., IEEE S&P 2019](https://cse.buffalo.edu/faculty/xmi/publication/resi_sp/)); Fehlalarm-Wege für Besucher:innen | Die Quell-IP eines vollständigen TCP-Handshakes, solange er nicht on-path ist (2.1) |
| **Kompromittierter Client** | Wie oben, aber mit gutem Ruf und echtem Bürgen | Mehr Tokens als das Kontingent |
| **Böswilliger Bürge (Hoster)** | Beliebig viele Client-Tokens, also Sybil in seinem Namen | Stimmen anderer Bürgen; Lab-Reproduktion |
| **Böswilliges Lab** | Eigene Bewertungen, „Honeypot-Belege“ und KI-Ausgaben; was es weiterreicht | Signaturen anderer Labs (k-von-n), Log-Witnesses |
| **Angreifer auf die Lab-Forschung** | Honeypot-Traffic, gefälschte PoCs/Advisories, Payloads mit Prompt Injection | Patch-Diffs der Hersteller (sofern Quelle geprüft) |

Daraus folgen zwei getrennte Probleme. **Ehrliche Clients, die getäuscht werden** (gefälschtes XFF, 0-RTT, geformter Traffic), schützt Eingangshygiene am Client. Gegen **unehrliche Clients, die lügen**, hilft am Client nichts, nur Wirkungsbegrenzung, Zählregeln und unabhängige Belege bei den Labs.

## 2. Bedrohungsanalyse

### 2.1 IPs anschwärzen („Framing“)

Seit E4 (ENTSCHIEDEN, 26.10.2026) enthalten Signale keine Besucher-IPs, auch nicht gehasht oder als Pseudonym, und es gibt kein IP-Netzwissen ([Prototyp-Verifikation](23-verifikation.md)). Erfundene IP-Meldungen bewirken im Netz deshalb nichts. Anschwärzen lässt sich höchstens ein ganzes Netz (ASN) oder Land; dafür gilt G1 sinngemäß.

| # | Variante | Möglich? | Wirkung | Heute entschärft durch | Restrisiko |
| --- | --- | --- | --- | --- | --- |
| A1 | **Betreiber erfindet Angriffe „von“ Kunden-IPs eines Konkurrenten** | **nein** (keine IPs im Signal) | Autoverify oder kurze Sperre beim Konkurrenten | E4; „nie allein wegen der IP sperren“ (04) | über das Netz keins → G1 |
| A2 | **Büro-IP / CGNAT-Bereich eines Konkurrenten** | über das Netz nein; lokal mit echtem Traffic über Mobil-Proxies desselben Netzbetreibers | Hunderte Unbeteiligte hinter einer IP ([Cloudflare 2025: CGNAT-IPs ~3× öfter gedrosselt](https://blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage/)) | Netzklasse `mobile`/`residential` (13), 17-4.1.4 (CGNAT → nur PoW) | **mittel**: CGNAT-Erkennung ist unscharf → G1 |
| A3 | **Zahlungsdienst, Webhook-Absender, Monitoring** | ja | Zahlungen schlagen fehl | „Keine Prüfung, wo kein Browser ist“, Webhook-Presets (04, 13 `require_header`) | **mittel**: keine netzweite Schutzliste → G6 |
| A4 | **Googlebot / Bingbot** | ja | SEO-Schaden | FCrDNS/Web Bot Auth (04, T14) | **gering**, wenn verifizierte Bots *vor* jeder Bewertung ausgenommen sind; Reihenfolge fehlt → G6 |
| A5 | **Gefälschtes `X-Forwarded-For`** bei zu weitem `trusted_proxies` | **ja**, häufigster Proxy-Konfigurationsfehler | Ehrlicher Client ordnet den Angriff der gefälschten IP zu; seit E4 nur lokal | 15-H6, `real_ip` (13) | **hoch** ohne Selbsttest und Herkunftsfeld → G5 |
| A6 | **IP-Spoofing über TCP** | **praktisch nein** off-path: Ein Request braucht einen vollständigen Handshake ([RFC 6528](https://www.rfc-editor.org/rfc/rfc6528), heute [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)); fehlende Absenderfilterung ([CAIDA Spoofer, CCS 2019](https://users.caida.org/~mjl/ccs-spoofer.pdf)) betrifft nur SYN-Floods | – | – | gering |
| A7 | **IP-Spoofing über HTTP/3 0-RTT** | **ZU PRÜFEN, plausibel ja**: 0-RTT-Daten mit gefälschter Adresse, verarbeitet vor der Adressvalidierung ([RFC 9000 §8](https://www.rfc-editor.org/rfc/rfc9000#section-8)); ob Caddy/quic-go 0-RTT annimmt: ZU PRÜFEN | wie A5, ohne Konfigurationsfehler | – | **mittel** bis geklärt → G5 |
| A8 | **Opfer-IPs in echte Angriffswellen einstreuen** | wie A1 | wie A1 | – | wie A1 → G1 |

### 2.2 Muster und Endpunkte anschwärzen („Allergie-Angriff“)

Der *Allergy Attack* bringt einen automatischen Signatur-Generator dazu, legitimen Traffic zu blocken ([Chung, Mok, RAID 2006](https://doi.org/10.1007/11856214_4)). Verwandt sind gezieltes Rauschen ([Perdisci et al., IEEE S&P 2006](https://ieeexplore.ieee.org/abstract/document/1623998)) und korrekt gelabelte, aber bösartig gewählte Trainingsdaten ([Newsome, Karp, Song, „Paragraph“, RAID 2006](https://doi.org/10.1007/11856214_5)).

| # | Variante | Möglich? | Wirkung | Heute entschärft durch | Restrisiko |
| --- | --- | --- | --- | --- | --- |
| B1 | **Betreiber meldet legitimen Request als Angriff** (`POST /wp-json/wc/store/v1/checkout`) | ja | Regel bricht Checkout oder eine Website | Eigene Lab-Belege, Regressionstest, Probelauf, Canary (04, 13); „keine gezielten Regeln“ (04) | **gering bis mittel**: „eigener Beleg“ und „gezielt“ sind nicht definiert → G2, G3 |
| B2 | **Angreifer formt echten Angriffs-Traffic**: jeder SQLi-Versuch an `/wp-json/contact-form-7/v1/…` mit demselben harmlosen Parameter | **ja**, ohne eigenen Client; ehrliche Clients melden korrekt | Lab leitet Regel „Endpunkt + Parameter“ ab, das Plugin bricht überall | Regressionstest (13, „Labs forschen“; T24) | **mittel**: greift nur, wenn der Negativkorpus den Endpunkt enthält → G3 |
| B3 | **Plugin eines Konkurrenten unbrauchbar machen** | ja, über B1/B2 | Reputationsschaden beim Hersteller | wie B1 | mittel → G3 |
| B4 | **Schutzregel per Massen-„Fehlalarm“ abschalten** | **ja**: Freigaben echter Betreiber zählen (03, 04), Sybil-Betreiber können freigeben | Virtueller Patch fällt **unmittelbar vor einem Exploit** weg (2.5) | K6/Härtung 04: Rückzug nur durch Betreiber-Freigaben | **hoch** → G4 |
| B5 | **Unblock-Formular gegen Betreiber** (Phishing, Belästigung, Erschöpfung) | ja | Betreiber schaltet Schild ab | 15-M1 | mittel, organisatorisch |

### 2.3 Identität: Sybil, Kollusion, Ruf

| # | Variante | Möglich? | Wirkung | Heute entschärft durch | Restrisiko |
| --- | --- | --- | --- | --- | --- |
| C1 | **Sybil-Clients** | ja; Domain ~1 €, Server wenige € | „3 Clients bei 2 Betreibern“ trivial erfüllt | Privacy-Pass über bürgende Hoster (04, 13); neue Clients Gewicht 0,2 | **mittel**: Ohne Issuer-Zählung zählt ein Hoster mit 1.000 Kund:innen wie 1.000 Stimmen. Ohne zentrale Identitätsinstanz ist Sybil immer möglich ([Douceur, IPTPS 2002](https://www.microsoft.com/en-us/research/publication/the-sybil-attack/)) |
| C2 | **Bürge als Sybil-Fabrik** | ja | wie C1, mit gutem Anschein | – | **hoch**, bis Aufnahme und Widerruf von Issuers geregelt sind → G2, G7 |
| C3 | **Kollusion echter Betreiber** (Kartell, Agenturen) | ja | Mindestvielfalt erreicht | Vielfalt nach ASN/Betreiberart (04) | mittel, wenn über ≥ 3 Bürgen verteilt → G2 |
| C4 | **On-Off**: monatelang ehrlich melden, dann den Ruf „ausgeben“ | ja ([Li, Meng, Kwok 2018](https://doi.org/10.3390/fi10010006)) | Hohes Gewicht im entscheidenden Moment | Client-Vertrauen 0,2–1,0 (04) | **hoch** → G2: Ruf nur zum Priorisieren |
| C5 | **Replay fremder Angriffe** (Honeypot-Datensätze, Feeds, alte Logs) | ja, nicht unterscheidbar | Aufgeblähte Zählung, Rufaufbau | Eine Meldung pro Client und Fenster (04) | mittel → G2 |
| C6 | **Dasselbe signierte Signal mehrfach einreichen** | nur ohne Zeitfenster/Nonce | Aufgeblähte Zählung | DSSE-Signatur (13) | gering mit Kontext-Bindung (G2) |
| C7 | **Kompromittierter Client** | ja | wie C4 ohne Vorlauf | – | mittel → G7 |

### 2.4 Labs und KI-Forschung

| # | Variante | Möglich? | Wirkung | Heute entschärft durch | Restrisiko |
| --- | --- | --- | --- | --- | --- |
| D1 | **Böswilliges Lab** stimmt für vergiftete Regel | ja | nur mit Konsens | k-von-n, ≥ 2 Betreiber, T07 (04, 14) | gering; **in der Alpha laufen nur unsere eigenen Labs** (03) |
| D2 | **Lab erfindet Honeypot-Treffer** | ja | Beleg-Pflicht ausgehebelt | – | **mittel** → G2: für Block nur reproduzierbare Belege |
| D3 | **Honeypots gezielt füttern** | ja | Vergiftete Ground Truth | – | mittel → G2, G3 |
| D4 | **Gefälschte PoCs, Advisories, CVE-Texte** | ja | zu breite Regel; Malware in der Lab-Range | Patch-Diff statt CVE-Text (17-4.1.5), isolierte Range (14, T25) | gering bis mittel → nur signierte Hersteller-Quellen |
| D5 | **Prompt Injection über Payloads** an die Lab-KI | ja ([Hackett et al. 2025](https://arxiv.org/abs/2504.11168)) | KI schlägt bösartige Regel vor | KI ohne Werkzeuge/Schlüssel (15, 17-4.1.7) | gering, solange Gates deterministisch sind |
| D6 | **Negativkorpus vergiften**, falls er aus Client-Daten stammt | ja | Umgehung statt Fehlsperre | – | mittel → G3: Korpus kuratiert |
| D7 | **Adaptive Angriffe auf robuste Aggregation** (Median, Trimmed Mean, Krum; [Fang et al., USENIX Sec 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/fang)) | ja, falls Labs föderiert trainieren | – | – | Aggregation ersetzt keine eigene Vertrauenswurzel (vgl. [FLTrust, NDSS 2021](https://www.ndss-symposium.org/ndss-paper/fltrust-byzantine-robust-federated-learning-via-trust-bootstrapping)) |

### 2.5 Timing

| # | Variante | Wirkung | Gegenmittel |
| --- | --- | --- | --- |
| E1 | **Fehlalarm-Flut kurz vor Exploit** (B4 + Angriff) | Virtueller Patch weg | G4: reproduzierte virtuelle Patches nie per Rückmeldung abwertbar |
| E2 | **Poisoning im Rauschen einer echten Welle** (5-Stunden-Fenster nach WordPress-CVE, 17-2.3) | Schnellpfad wird ausgenutzt | Schnellpfad nur `log` + `challenge`, nie `block` (17-4.1.5) |
| E3 | **Epochenwechsel**: Dedup und Kontingente setzen zurück | doppelte Zählung | Überlappende Zählfenster; Kontingent auch je Bürge |
| E4 | **Wochenende/Nacht** ohne Menschen in Labs | Freigaben ohne Mensch | Block braucht Menschen aus ≥ 2 Organisationen, sonst höchstens `challenge` |
| E5 | **Frog Boiling** der lokalen Baseline (14) | lokale Umgehung | Baselines versioniert und eingefroren (14), Drift-Alarm |

## 3. Gegenmittel (priorisiert)

**P0** muss vor der Phase „Externe Labs“ stehen (Autoblock ab Werk, externe Labs), **P1** vor „Für alle“.

### G1 – IPs bleiben auf dem Server, IP-Aussagen wirken nur lokal (P0)

- **Kein IP-Netzwissen (ENTSCHIEDEN, 26.10.2026).** IPs, auch als Pseudonym, stehen in keinem Signal, keiner verteilten Regel, keinem Preset, TUF-Target oder Transparenz-Log. Es gibt keine IP-Listen und keine IP-Abfragen über das Netz. Der Regel-Validator lehnt in Fernregeln `REMOTE_ADDR`, `@ipMatch`, `@ipMatchFromFile`, `@geoLookup` und IP-Variablen in `chain` ab. Land und ASN gehen nur als Merkmal eines Musters mit.
- **Lokal bleiben** Ratenbegrenzung, eigene Sperren und lokal abgeglichene Fremdlisten per Opt-in (etwa AbuseIPDB, [Quellen](22-quellen-cve-ip-crowdsec.md)). Ihr Beitrag ist auf `+15` Punkte gedeckelt und hebt allein nie über eine Schwelle (40 bzw. 70); er verstärkt nur Aktionen, die schon verdächtig sind. **Null-Beitrag** gilt für `net_class` ∈ {`mobile`, `cgnat`, `tor`}, vom Gateway selbst verifizierte Bots, lokal freigegebene Absender (G6) und API-/Webhook-Pfade (Preset `skip: [challenge]`).
- **Ausnahme Spamhaus DROP (Entwurf D28):** DROP listet gekaperte Netze ohne legitimen Traffic und sperrt ab Werk lokal auf Netzwerkebene, ohne Score; die ersten 7 Tage nur im Probelauf ([MVP-15](../../tests/specs/MVP-15-network-blocking.yaml)). Jedes Gateway holt die Liste direkt bei Spamhaus; einzelne Adressen lassen sich im Dashboard erlauben. Alle anderen Listen sind Opt-in.

### G2 – Zählen nach Bürgen, Muster nur mit unabhängiger Reproduktion (P0)

Client-Meldungen sind Hinweise (`tip`). Sie bestimmen, *was Labs untersuchen*, nicht, *was Clients tun*.

| Wirkung, die eine Empfehlung höchstens haben darf | Nötige Belege |
| --- | --- |
| `observe` (nur zählen) | Hinweise von ≥ 3 Bürgen (Issuers) |
| `challenge` / Ratenbegrenzung, max. 7 Tage | zusätzlich: eigene Sensoren (Honeypot, Lab-Range) bei ≥ 2 Lab-Betreibern **oder** Reproduktion bei 1 Lab; Gates G3 bestanden |
| `block` | **Reproduktion** des Exploits gegen eine benannte, verwundbare Softwareversion in den Ranges von **≥ 2 Lab-Betreibern verschiedener Art**, Gates G3 bestanden, menschliche Freigabe in ≥ 2 Organisationen |

- **Verhaltensmuster** (Credential Stuffing, Scan-Wellen) lassen sich nicht reproduzieren und bekommen aus dem Netz höchstens `challenge`. Lokale Regeln dürfen mehr.
- **Vielfalt zählt nach Issuer:** eine Stimme pro Issuer, Signatur und Zeitfenster; kein Issuer trägt mehr als 1/3 der Belege. Das ist robuste Aggregation ([Yin et al., ICML 2018](https://proceedings.mlr.press/v80/yin18a.html); [Krum, Blanchard et al., NeurIPS 2017](https://proceedings.neurips.cc/paper/2017/hash/f4b9ec30ad9f68f89b29639786cb62ef-Abstract.html)) auf Ebene der Bürgen, mit dem Vorbehalt aus D7.
- **Einmal pro Client und Kontext, unverkettbar:** Anonymous Rate-Limited Credentials ([draft-yun-privacypass-arc](https://datatracker.ietf.org/doc/draft-yun-privacypass-arc/), Krypto-Teil [draft-yun-cfrg-arc](https://datatracker.ietf.org/doc/draft-yun-cfrg-arc/)) mit Kontext `(epoch, request_sig)`, Limit 1. Alternative: Rate-Limited Tokens ([draft-ietf-privacypass-rate-limit-tokens](https://datatracker.ietf.org/doc/draft-ietf-privacypass-rate-limit-tokens/), Experimental), nur Mengenbegrenzung. Reifegrad beider: ZU PRÜFEN.
- **Ruf priorisiert, entscheidet aber nicht.** Er bestimmt, welche Hinweise Labs zuerst ansehen, und zählt nicht in Schwellen. On-Off (C4) kauft damit nur Aufmerksamkeit.
- Anders als bei CrowdSec, wo die höchste Vertrauensstufe ohne Honeypot-Abgleich veröffentlichen darf ([FAQ](https://www.crowdsec.net/faq)), veröffentlicht bei uns niemand ohne Lab-Beleg.

### G3 – Gates gegen Allergie-Regeln (P0)

Jede Regel über `observe` hinaus muss automatisch bestehen:

1. **Negativkorpus:** null Treffer gegen kuratierte legitime Requests (Playwright-Läufe der Presets, Plugin-Testsuites, Admin-Workflows im Testlab, 14), nie aus Client-Meldungen (D6).
2. **Schutzliste für Endpunkte** (über TUF signiert, öffentlich): Zahlungs-Webhooks, OAuth-/OIDC-Callbacks, Checkout-Routen großer Shopsysteme, REST-Routen der Top-N-Plugins (aus Routenformen des Agent-Skills `schild-rules`, 13, und Plugin-Verzeichnissen), `/.well-known/*`. Trifft eine Regel einen geschützten Endpunkt ohne Payload-Bedingung, wird sie abgelehnt; mit Payload-Bedingung braucht sie `block`-Belege und menschliche Freigabe.
3. **Minimalitätstest:** Derselbe Request **ohne** den schädlichen Teil darf nicht treffen. Damit fällt eine Regel „Endpunkt + harmloser Parameter“ (B2) durch.
4. **Verbreitung:** Ein Pfad-Muster muss zu Software gehören, die auf ≥ N Websites läuft. Sonst ist es eine gezielte Regel und nur lokal zulässig (04, Neutralität).
5. **Hersteller-Benachrichtigung** an den CVD-Kontakt (passt zu Commit-then-Reveal, 04). Das hilft gegen B3 und bringt eine zweite Meinung.

### G4 – Fehlalarm-Rückmeldung verengt, statt abzuschalten (P0)

- Rückmeldungen (`schild.feedback`) wirken **sofort lokal** beim meldenden Client.
- Netzweit erzeugen sie einen **Verengungsvorschlag**: Das Lab sieht nur die Form des Treffers (Ort `ARGS:text`, Content-Type, Längenklasse) und sucht eine engere Regel, die den Exploit weiter fängt. Sie durchläuft G3.
- **`virtual_patch`-Regeln mit Reproduktion werden durch Rückmeldungen nie abgewertet**, nur verengt (E1). `heuristic`/`behavioral` dürfen bei Rückmeldungen von ≥ 3 Issuers von `block` auf `challenge` fallen, nie auf „aus“.
- Es zählen nur Rückmeldungen, über die ein **Mensch im Dashboard** entschieden hat (K6, 15), gezählt nach Issuer (G2).

### G5 – Eingangshygiene beim ehrlichen Client (P0)

- **Die IP kommt nur aus dem TCP-Peer oder einer verifizierten Proxy-Kette.** `trusted_proxies` ist per Default Loopback (innerer Modus) bzw. leer (äußerer Modus); `client_ip_headers` gilt nur für vertrauenswürdige Peers (Caddy-Syntax je Version ZU PRÜFEN).
- **Selbsttest bei Installation und täglich:** Das Gateway schickt sich über den externen Weg einen Request mit `X-Forwarded-For: 192.0.2.1` (TEST-NET-1). Taucht diese IP als Client-IP auf, sendet es keine Signale mehr und meldet den Fehler im Dashboard.
- **`origin.attribution`** ∈ {`tcp_peer`, `trusted_proxy`}; jede andere Zuordnung erzeugt kein Signal.
- **0-RTT:** Requests vor der Adressvalidierung (`early_data`) dürfen lokale Sperren und Ratenbegrenzung nicht beeinflussen. Bis A7 geklärt ist, bleibt 0-RTT aus.
- **Keine Log-Injection:** Signale entstehen aus strukturierten Coraza-Daten, nie aus geparsten Logzeilen (vgl. Fail2ban, [CVE-2007-4321](https://osv.dev/vulnerability/CVE-2007-4321), [CVE-2013-2178](https://www.openwall.com/lists/oss-security/2013/06/12/4)).

### G6 – Etiketten für Absender, Freigabe nur lokal (P0)

- **Etiketten statt Erlaubt-Liste (ENTSCHIEDEN 28.10.2026, Initiator):** Eine Erlaubt-Liste aus dem Netz wäre ein Angriffspunkt. Mehrere Labs könnten sich zusammentun und etwa die Server eines Werbenetzes eintragen, und überall fielen Prüfungen weg, ohne dass es jemand merkt. Deshalb verteilen Labs keine Absenderlisten. Das Gateway lädt veröffentlichte Bereiche selbst beim Herausgeber: Such-Bots ([FCrDNS nach Google](https://developers.google.com/search/docs/advanced/crawling/verifying-googlebot)), Web-Bot-Auth-Schlüssel ([IETF-Entwurf](https://datatracker.ietf.org/group/webbotauth/documents/)), Absenderbereiche von Zahlungsdiensten und Monitoring, MISP-Warninglists (13). Daraus werden Etiketten im Dashboard und in Signalen; ein Etikett ändert keine Aktion.
- **Freigeben nur lokal:** Such-Bots nimmt das Gateway erst nach eigener Prüfung (FCrDNS, Web Bot Auth) aus der Bot- und IP-Bewertung aus. Alles andere gibt der Betreiber selbst frei, im Dashboard mit Vorschlag aus dem Etikett („Stripe-Webhooks freigeben?“).
- **Freigaben gelten nie für Angriffsmuster:** WAF-Regeln und virtuelle Patches prüfen auch freigegebene und verifizierte Absender. Eine Freigabe neutralisiert nur IP-Score, IP-Listen und Bot-Prüfung.
- **Reihenfolge im Gateway:** lokale Freigaben → lokale Regeln → Netzbeitrag. Signale über verifizierte oder freigegebene Absender tragen `origin.protected: true`.
- **Kanarien-Treffer:** Häufen sich bei einem Issuer solche Hinweise für Muster, die sonst niemand sieht, wird der Issuer-Kontext markiert, wie bei CrowdSec ([FAQ](https://www.crowdsec.net/faq)). Weil gekaperte Cloud-Adressen echt angreifen können, bleiben Treffer an diesen Adressen lokal.

### G7 – Kontingente, Rechenschaft, Widerruf (P1)

- **Kontingente** pro Client und Epoche (z. B. 500 Hinweise/Tag) und pro Issuer (nach Kundenzahl, gedeckelt), durchgesetzt über ARC oder Rate-Limited Tokens.
- **Rechenschaft auf Issuer-Ebene:** Jeder Hinweis nennt seinen Issuer. Ist eine Regel vergiftet, sehen Labs, welche Issuers beteiligt waren, ohne einzelne Clients zu kennen. Das Issuer-Gewicht sinkt, der Issuer muss seine Kund:innen prüfen, bei Wiederholung wird die Bürgschaft über TUF widerrufen.
- **Prüfspeicher in den Labs:** Hinweise mit Issuer, Kontext-Tag und Zeit liegen 30 Tage in einem nicht öffentlichen, nur anhängbaren Speicher; öffentlich sind nur Merkle-Commitments je Epoche (15-K2).
- **Bürgen werden aufgenommen wie Labs** (15-H4): öffentliche Liste, Charta, Missbrauchsverfahren, Haftungszusage für Kontingente.
- **Rechtlich** kann gezieltes Anschwärzen gezielte Behinderung (§ 4 Nr. 4 UWG) oder Computersabotage (§ 303b StGB) sein, ZU PRÜFEN. Die Nutzungsbedingungen sollten es verbieten und die Weitergabe an Ermittlungsbehörden regeln.

### G8 – Schadensradius und Rücknahme (P0)

- **Gestaffelte Höchstaktion:** Probelauf (≥ 24 h) → Canary (≤ 5 % der Clients) → `challenge` bis `max_action_until` (7 Tage) → `block`. Bei kritischer CVE (17-4.1.5) direkt `challenge`, nie `block`.
- **Lokale Notbremse:** Trifft eine Netzregel lokal mehr als `max_match_share` (Vorschlag 0,1 %) der sonst unauffälligen Requests oder erzeugt sie Freigaben, schaltet das Gateway sie lokal in den Probelauf und meldet `feedback`. Weil nur der eigene Traffic zählt, kann ein Angreifer das nur auf seiner eigenen Website auslösen.
- **Netzweiter Rückzug** nur per k-von-n ([Events und Geschwindigkeit, 4.5](20-events-und-geschwindigkeit.md)), nie durch Signale, die Angreifer erzeugen können.

### G9 – Lab-Forschung gegen vergiftete Eingaben (P1)

- Patch-Diffing nur aus **signierten Hersteller-Releases** (WordPress.org-SVN, Packagist mit Signatur, GitHub-Releases), PoCs nur in der isolierten Range (14, T25).
- Honeypot-Daten sind Hinweise und öffnen ohne Reproduktion keine `block`-Stufe (D2, D3).
- KI-Ausgaben sind Vorschläge, die G3 bestehen müssen; das Modell hat keine Werkzeuge (15, 17).
- Jede Regel nennt in `evidence` ihre Belege, damit andere Labs nachrechnen können.

### G10 – Verteilte Angriffe über Residential Proxies (P1)

Angreifer mieten Privatanschlüsse und wechseln mit jeder Anfrage IP und User-Agent. Zähler pro Absender (MVP-17) laufen dann nie voll, und eine IP-Sperre träfe beim nächsten Mal den Nachbarn mit derselben Adresse. Schild fragt deshalb nicht „wer schickt viel?“, sondern „was passiert gerade viel?“ (Initiator, 28.10.2026; [`MVP-18`](../../tests/specs/MVP-18-distributed-attacks.yaml)).

- **Zählen nach dem Ziel:** pro Website und Route Fehlversuche, Verhältnis von Fehlern zu Erfolgen und Anteil neuer Absender gegen den eigenen Normalzustand; pro Konto Fehlversuche über viele Adressen (Schlüssel nur im Arbeitsspeicher); pro Anfrageform dieselbe `request_sig` von vielen Adressen.
- **Merkmale, die beim Wechseln bleiben:** TLS-Fingerabdruck JA4 und HTTP/2-Einstellungen, wenn Schild TLS selbst beendet (nur JA4 unter BSD-Lizenz, kein JA4+); Widersprüche zwischen User-Agent, Client Hints, `Sec-Fetch-*` und Fingerabdruck (human_score Stufe 0, [Datenschutzkonzept](24-datenschutz.md) Abschnitt 10); Verhalten wie ein POST auf den Login ohne vorheriges Formular, ohne Cookie, in gleichmäßigem Takt.
- **Reaktion auf die Gruppe, nie auf die Adresse:** Die angegriffene Route wird befristet strenger (Rechenaufgabe oder enges Limit für alle, die zur Gruppe passen oder kein Sitzungs-Cookie haben); das betroffene Konto bekommt eine kurze Wartezeit, nie eine Sperre, damit niemand echte Nutzer aussperren kann; eine eindeutig bösartige Anfrageform blockt eine lokale Regel, egal von welcher Adresse. Alles läuft von selbst aus und steht in Alltagssprache im Dashboard.
- **Das Netz hilft ohne IPs:** Auf Wunsch meldet das Gateway die Welle als IP-freien Hinweis (Szenario als `category`, Routenform als `request_sig`, Netzklasse, optional JA4 wie bisher). Labs sehen so dieselbe Welle auf vielen Websites und verteilen eine Regel gegen Form oder Fingerabdruck (G1, G2).
- **Bewusst nicht:** Listen mit Residential-Proxy-Adressen (kommerziell, schnell veraltet, treffen Unbeteiligte), dauerhafte Sperren aus einer Gruppen-Erkennung.
- **Grenze:** Gegen echte Browser mit echtem Fingerabdruck und menschlichem Tempo hilft Erkennen kaum noch. Dann geht es ums Verteuern: Rechenaufgabe auf der Route, Schutz einzelner Konten, Hinweis auf Passkeys und Zwei-Faktor im Dashboard.

### G11 – Angriffe auf die öffentlichen Logs (P1)

Die öffentlichen Logs der Labs verhindern Verstecken und Unterschieben. Sie sind aber selbst ein Angriffsziel (Initiator, 28.10.2026):

- **Mitlesen:** Ein neuer virtueller Patch im Log verrät, dass eine Lücke gerade ausgenutzt wird, welchen Endpunkt sie betrifft und wie die Regel aussieht; Angreifer suchen gezielt Umgehungen. Geheimhaltung ist in einem offenen Netz keine Option, denn jedes Gateway bekommt die Regeln ohnehin. Das ist ein bewusster Preis der Transparenz. Gegenmittel: Regeln treffen den Angriffsweg, nicht ein Beispiel (Minimalitätstest, G3); gemeldete Umgehungen werden schnell als Variante nachgeschoben.
- **Split View:** Ein Lab zeigt einem Gateway einen anderen Log-Stand als allen anderen, um eine Regel unterzuschieben oder eine Rücknahme vorzuenthalten. Gegenmittel: Gegenzeichnen durch die anderen Labs (Witness-Cosigning, 15-H3), Übernahme nur bei Eintrag in den Logs mehrerer Labs verschiedener Betreiber.
- **Mehrere Labs unter einer Hand:** Wer mehrere scheinbar unabhängige Labs betreibt, zeichnet sich selbst gegen. Gegenmittel: k von n nach Betreibern, eigene Lab-Auswahl jedes Gateways, Freigabe durch mindestens zwei Organisationen (G2).
- **Einfrieren und alte Stände:** Ein Angreifer hält ein Gateway auf einem alten Log-Stand, damit es eine Rücknahme oder einen neuen Patch nicht sieht. Gegenmittel: Checkpoints mit Ablaufzeit und Rollback-Schutz (Contract), Warnung im Dashboard bei zu altem Stand.
- **Logs lahmlegen:** Ausfall oder Überlastung der Logs verzögert neue Patches, gerade bei Zero-Days. Der Grundschutz läuft weiter (lokale Regeln, WAF). Gegenmittel: Spiegel und Checkpoint-Kopien über die Relays, kein einzelner Abrufpunkt.
- **Datenlecks:** Ein Log enthält nichts über Websites oder Besucher, weder Domains noch Signal-Mengen pro Website noch Adressen. Eine Prüfung im Lab lehnt Einträge mit solchen Feldern ab.
- **Log als Gütesiegel:** Ein Eintrag beweist nur, dass etwas veröffentlicht wurde, nicht dass es gut ist. Die Güte sichern Reproduktion, Probelauf und G2/G3.

## 4. Änderungen am Design und an den Formaten

### 4.1 Designänderungen (Vorschlag)

| Heute (Konzept) | Neu | Status |
| --- | --- | --- |
| „Schlechte IP-Bewertung führt höchstens zu Autoverify“ (04) | IP-Bewertungen nur lokal, nur verstärkend, Deckel +15 (G1); kein IP-Wissen aus dem Netz | ENTSCHIEDEN (26.10.2026, E4) |
| Sequenzdiagramm 04: „Bewertung S / h: hoch“ an alle | Bewertungen nur für Muster und Regeln | ENTSCHIEDEN (26.10.2026, E4) |
| „Zählt ab 3 Clients bei 2 Betreibern“ (04, 13) | ≥ 3 Issuers; Wirkung nach Belegstufe (G2) | ENTWURF |
| Client-Vertrauen 0,2–1,0 als Gewicht (04) | Ruf nur zur Priorisierung (G2) | ENTWURF |
| Fehlalarme „fließen ein“, Empfehlungen werden „automatisch abgewertet“ (04) | Lokal sofort, netzweit nur Verengung; `virtual_patch` nie abwertbar (G4) | ENTWURF |
| Automatischer Rückzug bei steigender Bestehensquote (04) | Lokale Notbremse; netzweit nur k-von-n (G8) | ENTWURF |
| Signal mit festem `client: ed25519:…` (13) | Kein Absender im Signal; im Prototyp `site-key`, ab v1 ARC mit offenem Issuer (4.2) | ENTWURF |
| `trusted_proxies` „streng“ (15-H6) | Default Loopback/leer, Selbsttest, `origin.attribution`, 0-RTT aus (G5) | ENTWURF |
| Gute Bots „gesondert behandeln“ (04, 13) | Etiketten statt Erlaubt-Liste, Freigabe nur lokal, nie für WAF-Regeln, feste Reihenfolge, Kanarien-Treffer (G6) | ENTSCHIEDEN 28.10.2026 (Etiketten statt Erlaubt-Liste, Initiator) · Rest ENTWURF |
| T08 Sybil, T07 Vergiftung (14) | Neue Testfälle T27–T41 (4.4) | ENTWURF |

### 4.2 Signal `schild.signal/0.3`

Aktueller Vertrag (v0.3, ENTSCHIEDEN mit E4): [`contracts/signal.md`](../../contracts/signal.md), Schema [`signal.schema.json`](../../contracts/signal.schema.json).

```json
{
  "schema": "schild.signal/0.3",
  "id": "8663a79b-d4c2-4b75-aad6-70cb2530cf94",
  "kind": "tip",
  "time_bucket": "2026-10-26T11:55:00Z",
  "action_sig": "login-burst/wp-admin",
  "request_sig": "sha256:…",
  "waf_rules": [930120, 949110],
  "score": 72,
  "category": "wordpress-login-bruteforce",
  "origin": { "country": "NL", "asn": 64500, "net_class": "hosting", "attribution": "tcp_peer", "protected": false },
  "agent": { "family": "python-requests", "major": 2, "bot": false },
  "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"
}
```

- **Keine IP, kein Absender.** Felder wie `ip`, `client_ip`, `host`, `site`, `auth` oder `token` lehnen die Labs an jeder Stelle ab (`forbidden_field`), unbekannte Felder ebenso.
- **Authentifizierung außerhalb der Nutzlast** ([`auth.md`](../../contracts/auth.md)): im Prototyp und in der Alpha ein `site-key` je Website (eine Signatur je Umschlag, Zählung je Issuer); ab v1 Privacy-Pass-ARC mit offenem Issuer, eine unverkettbare Präsentation je `(epoch, request_sig)`.
- `time_bucket` (5–15 min, auf vollen 5 Minuten) statt Sekundenzeit erschwert Timing-Korrelation (15-H2).
- `ja4` ist optional, nur im Prototyp und in der Alpha; ob es bleibt, ist ZU PRÜFEN ([Prototyp-Verifikation](23-verifikation.md), E4).
- `kind` ist immer `tip`. `evidence` erzeugen nur Labs.

### 4.3 Rückmeldung und Regel-Metadaten

Rückmeldung `schild.feedback/0.2` ([`signal.md`](../../contracts/signal.md)), nur nach Entscheidung eines Menschen im Dashboard (K6), authentifiziert wie das Signal:

```json
{
  "schema": "schild.feedback/0.2",
  "id": "…uuid v4…",
  "time_bucket": "2026-10-26T11:50:00Z",
  "rule_id": "schild-2026-0412",
  "bundle_version": 42,
  "verdict": "false_positive",
  "decided_by": "operator",
  "local_action": "suspended",
  "match_shape": { "location": "ARGS:text", "content_type": "application/json", "len_bucket": "256-1k" }
}
```

Regel-Metadaten (Entwurf). Im Vertrag sind sie Felder jeder Regel im Regelstand ([`rule-bundle.schema.json`](../../contracts/rule-bundle.schema.json)), kein eigenes TUF-Target:

```yaml
# TUF target custom metadata for a distributed rule (no IPs, ever)
rule_id: schild-2026-0412
class: virtual_patch            # virtual_patch | heuristic | behavioral
target: { software: wp-plugin/gallery, versions: "<2.4.1", vendor_notified: 2026-10-24 }
evidence:
  reproduced_by: [lab-uni-x, lab-hoster-y]     # >= 2 operators, different kinds, required for block
  sensor_labs: 2
  tips: { issuers: 7, max_issuer_share: 0.29 }
gates:
  negative_corpus: { version: corpus-2026.10, matches: 0 }
  protected_endpoints: { touched: false }
  minimality: passed
  prevalence: { sites_with_software: ">=1000" }
rollout:
  stage: canary                  # shadow | canary | general
  max_action: challenge
  max_action_until: 2026-10-31T00:00Z
  max_match_share: 0.001         # local brake
feedback_policy: narrow_only     # narrow_only | auto_downgrade (heuristic/behavioral only)
expires: 2027-01-24T00:00Z
```

Der **Validator im Gateway** (Ergänzung zu 15-K7) lehnt Fernregeln ab, die `REMOTE_ADDR`, `@ipMatch*`, `@geoLookup` oder `SERVER_NAME`/`REQUEST_HEADERS:Host` enthalten, denen `class` fehlt oder deren `max_action` die Belegstufe übersteigt. Dazu kommt in `schild.yaml` (13):

```yaml
ingress:
  trusted_proxies: [127.0.0.1/32, ::1/128]
  xff_selftest: daily
  quic_0rtt: off
remote_rules:
  local_brake_max_match_share: 0.001
```

### 4.4 Neue Testfälle für [Testkonzept](14-testkonzept.md) (Vorschlag)

| ID | Szenario | Erwartung |
| --- | --- | --- |
| T27 | 5 Fake-Clients bei 1 Issuer melden Angriffe „von“ 50 Kunden-IPs einer Konkurrenz-Site | Kein Netzbeitrag (≥ 3 Issuers fehlen); bei Konkurrenz-Site null Prüfungen für unauffällige Requests |
| T28 | Wie T27, aber 3 Issuers (Kollusion) | Signale enthalten keine IPs → kein IP-Beitrag aus dem Netz; Sperren = 0 |
| T29 | Externer Angreifer sendet SQLi mit `X-Forwarded-For: <Opfer>` an Site mit falschem `trusted_proxies` | Selbsttest schlägt an; keine Signale, bis die Proxy-Kette stimmt; Opfer-IP nicht lokal gesperrt |
| T30 | HTTP/3-0-RTT mit gefälschter Quelladresse | Keine Opfer-IP in lokalem Event oder lokaler Sperre |
| T31 | Allergie: 2.000 SQLi-Requests alle an `/wp-json/contact-form-7/v1/…` mit festem harmlosen Parameter | Abgeleitete Regel fällt im Minimalitätstest durch; Plugin funktioniert |
| T32 | Sybil-Betreiber melden Checkout-Route als Angriff | Schutzliste lehnt ab; Kanarien-Markierung des Issuer-Kontexts |
| T33 | 200 „Fehlalarm“-Rückmeldungen gegen virtuellen Patch, danach Exploit | Regel bleibt `block`; Verengungsvorschlag im Lab; Exploit geblockt |
| T34 | On-Off: Client meldet 60 Tage korrekt, dann vergiftet | Keine Schwellenwirkung durch Ruf; Lab-Beleg fehlt → keine Regel |
| T35 | Böswilliges Lab erfindet Honeypot-Belege für `block` | Ohne Reproduktion durch 2. Lab-Betreiber höchstens `challenge` |
| T36 | Googlebot (FCrDNS) und Stripe-Webhook in Fake-Angriffs-Signalen | Kein Netzbeitrag, Signale verworfen, Issuer-Kontext markiert |
| T37 | Mehrere Labs signieren gemeinsam ein Paket, das den Bereich eines Werbe-Servers als „Bot“ oder „Zahlungsdienst“ ausweist | Gateway lehnt IP-Daten in Paketen ab; der Bereich wird normal bewertet; WAF-Regeln greifen auch bei lokal freigegebenen Absendern |
| T38 | Split View: ein Lab liefert einem Gateway einen abweichenden Log-Stand mit einer zusätzlichen Regel | Gateway erkennt den Widerspruch über die Gegenzeichnungen, übernimmt die Regel nicht, Dashboard warnt |
| T39 | Freeze: Relay und ein Lab liefern einem Gateway tagelang denselben alten Checkpoint | Nach Ablauf des Checkpoints Warnung im Dashboard; bestehende Regeln bleiben, keine neuen aus dem alten Stand |
| T40 | Log-Eintrag mit Domain, Signal-Menge pro Website oder IP-Adresse | Lab lehnt den Eintrag ab; nichts davon erscheint im öffentlichen Log |
| T41 | Logs eines Labs nicht erreichbar, während ein Zero-Day-Patch verteilt wird | Patch erreicht die Gateways über Spiegel und die Logs der anderen Labs; Grundschutz läuft weiter |

## 5. Offene Probleme (ehrlich)

1. **Sybil ist verschoben, nicht gelöst.** Wer bürgen darf und wie schnell widerrufen wird, sind Machtfragen wie bei Labs (15-H4). Selbstbetreiber ohne Hoster brauchen einen Bürgen-Weg jenseits von „Domain beweisen“. OFFEN.
2. **Privatheit gegen Rechenschaft.** Issuer-Rechenschaft trifft ehrliche Kund:innen eines Hosters mit. Einzelne Clients ließen sich nur über hinterlegte Identität aufdecken (Schwellwert-Entschlüsselung durch k Labs + Issuer), und das wäre ein Überwachungswerkzeug. OFFEN, Tendenz: nicht bauen.
3. **Mit OHTTP ist Vielfalt nach ASN nur Selbstauskunft.** Die „Mindestvielfalt nach ASN“ aus [04](04-technologie-und-security.md) kann dann nur der Issuer bezeugen, was die Anonymitätsmenge verkleinert. ZU PRÜFEN: Privacy Pass mit öffentlichen Metadaten.
4. **Verhaltensmuster sind nicht reproduzierbar.** Bei Credential Stuffing, Scan-Wellen und KI-Agenten-Schwärmen (17) bleiben nur vergiftbare Hinweise und Honeypots, deshalb nur `challenge`. Ob das gegen gut finanzierte Angreifer reicht, ist offen (17-1.4).
5. **Allergie-Angriffe durch echten Traffic** (B2) lassen sich nicht ganz ausschließen; der Minimalitätstest prüft nur Varianten, die wir uns ausdenken, und Paragraph zeigt, dass korrekt gelabelte Daten reichen. Forschungsthema für Labs.
6. **Der Negativkorpus ist nie repräsentativ.** Echter Client-Traffic wäre besser, ist aber datenschutzrechtlich heikel und vergiftbar (D6). Möglich: Lokale Probeläufe (03) melden aggregierte Trefferquoten per DAP/Prio, ZU PRÜFEN.
7. **Geschwindigkeit gegen Gates.** WordPress-Massenausnutzung beginnt im Median nach Stunden (17-2.3), Reproduktion in zwei Labs mit Freigabe in zwei Organisationen dauert länger. Der Schnellpfad (`challenge`) ist ein Kompromiss, kein Schutz gegen gezielte Angreifer.
8. **In der Alpha laufen nur unsere eigenen Labs.** Gegenmittel, die auf Unabhängigkeit beruhen (G2, D1, D2), greifen erst ab der Phase „Externe Labs“. Bis dahin: befreundete Betreiber, kein IP-Wissen aus dem Netz, Netzregeln nur `observe`/`challenge`. Das sagen wir offen.
9. **ARC und Rate-Limited Tokens sind IETF-Entwürfe**, Go-Bibliotheken ZU PRÜFEN. Fallback: Privacy-Pass-Tokens (RFC 9578) mit Kontingent pro Issuer, ohne Kontext-Dedup, also schwächer gegen C5.
10. **Robuste Aggregation ist kein Beweis** (Fang et al. 2020). Die Vertrauenswurzel bleibt die Lab-Reproduktion, auch wenn Labs später gemeinsam Modelle trainieren.
11. **Rechtsrahmen für Sanktionen** (UWG, StGB, Haftung der Bürgen, Datenweitergabe an Behörden): ZU PRÜFEN.

## Literatur (geprüft 25.10.2026)

- Douceur, *The Sybil Attack*, IPTPS 2002 – [Microsoft Research](https://www.microsoft.com/en-us/research/publication/the-sybil-attack/)
- Chung, Mok, *Allergy Attack Against Automatic Signature Generation*, RAID 2006 – [doi:10.1007/11856214_4](https://doi.org/10.1007/11856214_4)
- Newsome, Karp, Song, *Paragraph: Thwarting Signature Learning by Training Maliciously*, RAID 2006 – [PDF](https://intelli-sec.cs.berkeley.edu/papers/paragraph.pdf)
- Perdisci, Dagon, Lee, Fogla, Sharif, *Misleading Worm Signature Generators Using Deliberate Noise Injection*, IEEE S&P 2006 – [IEEE](https://ieeexplore.ieee.org/abstract/document/1623998)
- Nelson et al., *Exploiting Machine Learning to Subvert Your Spam Filter*, LEET 2008 – [USENIX](https://www.usenix.org/conference/leet-08/exploiting-machine-learning-subvert-your-spam-filter) (1 % vergiftete Trainingsdaten reichen; gezielte Angriffe gegen einzelne legitime Nachrichten – Analogie zu B1)
- Biggio, Nelson, Laskov, *Poisoning Attacks against Support Vector Machines*, ICML 2012 – [arXiv:1206.6389](https://arxiv.org/abs/1206.6389)
- Blanchard, El Mhamdi, Guerraoui, Stainer, *Machine Learning with Adversaries: Byzantine Tolerant Gradient Descent* (Krum), NeurIPS 2017 – [Proceedings](https://proceedings.neurips.cc/paper/2017/hash/f4b9ec30ad9f68f89b29639786cb62ef-Abstract.html)
- Yin, Chen, Ramchandran, Bartlett, *Byzantine-Robust Distributed Learning: Towards Optimal Statistical Rates*, ICML 2018 – [PMLR](https://proceedings.mlr.press/v80/yin18a.html)
- Fang, Cao, Jia, Gong, *Local Model Poisoning Attacks to Byzantine-Robust Federated Learning*, USENIX Security 2020 – [USENIX](https://www.usenix.org/conference/usenixsecurity20/presentation/fang)
- Cao, Fang, Liu, Gong, *FLTrust: Byzantine-robust Federated Learning via Trust Bootstrapping*, NDSS 2021 – [NDSS](https://www.ndss-symposium.org/ndss-paper/fltrust-byzantine-robust-federated-learning-via-trust-bootstrapping)
- Li, Meng, Kwok, On-Off-Angriffe auf CIDN, Future Internet 2018 – [doi:10.3390/fi10010006](https://doi.org/10.3390/fi10010006) (bereits in 16)
- CrowdSec, Konsens, Trust Rank, Honeypots, Kanarien – [FAQ](https://www.crowdsec.net/faq), [Our Data](https://crowdsec.net/our-data) (Herstellerangaben, Formel nicht öffentlich)
- AbuseIPDB: Konfidenz aus Zahl, Vielfalt und Alter der Meldungen; keine öffentliche Regel gegen koordinierte Falschmeldungen gefunden – ZU PRÜFEN ([Robtex-Zusammenfassung](https://robtex.com/en/sources/abuseipdb))
- Fail2ban Log-Injection: [CVE-2007-4321](https://osv.dev/vulnerability/CVE-2007-4321), [CVE-2013-2178](https://www.openwall.com/lists/oss-security/2013/06/12/4)
- Luckie, Beverly et al., CAIDA Spoofer, *Network Hygiene, Incentives, and Regulation*, CCS 2019 – [PDF](https://users.caida.org/~mjl/ccs-spoofer.pdf)
- Standards/Entwürfe: [RFC 6528](https://www.rfc-editor.org/rfc/rfc6528), [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576), [draft-ietf-privacypass-rate-limit-tokens](https://datatracker.ietf.org/doc/draft-ietf-privacypass-rate-limit-tokens/), [draft-yun-privacypass-arc](https://datatracker.ietf.org/doc/draft-yun-privacypass-arc/), [Web Bot Auth WG](https://datatracker.ietf.org/group/webbotauth/documents/), [Googlebot verifizieren](https://developers.google.com/search/docs/advanced/crawling/verifying-googlebot)

## Als Nächstes

- [ ] G1, G2, G4, G5, G8 als Entscheidungen nach Vorlage ([Offene Fragen, Annahmen und Risiken](11-offene-fragen-und-risiken.md)) aufnehmen; danach [04](04-technologie-und-security.md) (Autoverify, Signalbewertung, Sequenzdiagramm) und 13 (Signalformat, „Härtung, Bewertung und Neutralität“) anpassen.
- [ ] A7 klären: Nimmt Caddy/quic-go 0-RTT standardmäßig an, und mit welcher Absenderadresse loggt Coraza?
- [ ] Testfälle T27–T41 in [Testkonzept](14-testkonzept.md) übernehmen.
- [ ] Schutzliste für Endpunkte und Quellenkatalog für Absender-Etiketten als erstes öffentliches Repository anlegen; Quellen und Lizenzen ZU PRÜFEN.
- [ ] ARC/Rate-Limited Tokens: Go-Bibliotheken und Reifegrad prüfen; Bürgen-Verfahren entwerfen.
- [ ] Externes Review dieses Dokuments (Einladung an CIDS-/Adversarial-ML-Forschung, keine Zusage).
