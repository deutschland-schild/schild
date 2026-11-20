---
short: Stand der Technik
group: Wie
description: "Was es schon gibt (CrowdSec, MISP, Cloudflare …), was die Forschung sagt und welche Standards wir nutzen – mit ehrlicher Abgrenzung."
---

# Stand der Technik: Vorbilder, Forschung, Standards

**Status:** ENTWURF · Recherche Stand 24.10.2026 · Unsicheres ist mit ZU PRÜFEN markiert

**Kurz:**

- Recherche zu bestehenden Systemen (CrowdSec, AbuseIPDB, Spamhaus, MISP, Cloudflare, BunkerWeb u. a.), zur Forschung über kollaborative Erkennung und zu Standards.
- Technisch ist vieles schon gebaut, vor allem bei CrowdSec. Unser Unterschied ist die Governance: Konsens mehrerer Betreiber, offener Algorithmus, Transparenz-Log. Die HMAC-Pseudonymisierung von IPs ist mit E4 entfallen.
- Standards im Prototyp: Caddy + Coraza + OWASP CRS, Ed25519 mit TUF-Schwellen, Log nach CT-Muster (RFC 9162), nur JA4, Sperrseite nach RFC 9457.
- Risiken: Sybil-Clients, mehr Fehlalarme durch Zusammenarbeit, breite Wirkung schlechter Regeln, Neutralität und Geld. Konsequenz: kooperieren statt doppeln.

**Kernaussage:** Caddy-Bouncer, WAF mit Coraza und CRS und eine Community-Blocklist mit Konsens und Vertrauenswerten gibt es bei **CrowdSec** schon. Schild baut auf denselben offenen Bausteinen (Caddy, Coraza, CRS), koppelt sich aber nicht an CrowdSec und übernimmt keine CrowdSec-IP-Daten; die offenen CrowdSec-Funktionen deckt es selbst ab, Regeln aus dem CrowdSec Hub (MIT) nutzen die Labs als Kandidaten ([Quellen](22-quellen-cve-ip-crowdsec.md), §4). Unterscheiden wollen wir uns in der **Governance**: mehrere unabhängige Betreiber statt einer Firma, Neutralität in der Architektur, Entsperren als geregeltes Verfahren, gemeinnützig nach EU-Recht.

## Was es schon gibt

| System | Kurz | Gleich / anders | Was wir übernehmen |
| --- | --- | --- | --- |
| [CrowdSec](https://docs.crowdsec.net/docs/central_api/community_blocklist) | Agent + Bouncer (Engine MIT). Zentrale API bildet Konsens; *User Trust Score* je Melder, *Scenario Trust Score* je Szenario; eigene Honeypots als Wahrheitsquelle. Nur unveränderte Hub-Szenarien zählen. [AppSec mit Coraza/CRS](https://docs.crowdsec.net/docs/appsec/vpatch_and_crs), [Caddy-Bouncer](https://app.crowdsec.net/hub/author/hslatman/remediation-components/caddy-crowdsec-bouncer). | Technisch fast deckungsgleich. Aber: **eine Firma** berechnet Konsens und Vertrauen, Formel nicht öffentlich, Freemium. | Honeypots gegen Poisoning, nur Standard-Szenarien zählen, wer nicht beiträgt, bekommt weniger. Keine CrowdSec-kompatible Decision-API für IP-Entscheidungen, denn das wäre eine verteilte IP-Liste ([Quellen](22-quellen-cve-ip-crowdsec.md), Abschnitt 4). |
| [AbuseIPDB](https://robtex.com/en/sources/abuseipdb) | Nutzerberichte, „Confidence of Abuse“ 0–100. | Zentral, Formel nicht offen (ZU PRÜFEN). | Vielfalt der Melder und Zerfall sind Standard. |
| [Spamhaus](https://www.suped.com/learn/blocklists/how-can-i-get-delisted-from-spamhaus) | Kuratierte Listen; Delisting erst nach Behebung der Ursache. | Menschen statt Konsens. | Entsperren je nach Listentyp, an die Ursache gekoppelt. |
| [DShield/ISC](https://www.usenix.org/conference/17th-usenix-security-symposium/highly-predictive-blacklisting) | Freiwillige Firewall-Logs; „Highly Predictive Blacklisting“ erstellt **personalisierte** Listen. | Zentral, keine Abstimmung. | Personalisierte Empfehlungen senken Fehlalarme. |
| [blocklist.de](https://abusix.com/blog/abusix-to-take-over-the-operation-of-blocklist-de) | Fail2ban-Meldungen, Weitergabe an Abuse-Kontakte; seit 2022 bei Abusix. | Einfach, keine Vertrauensbewertung. | Abuse-Kontakt als Zusatzkanal. Gemeinnützige Projekte können den Besitzer wechseln; Governance absichern. |
| [MISP](https://circl.lu/doc/misp/warninglists/) | Teilen in Communities; *Warninglists* gegen Fehlalarme, *Sightings* („gesehen“, „Fehlalarm“). | Menschlicher Austausch, keine Durchsetzung. | Warninglists direkt übernehmen (CDNs, Crawler, CGNAT); MISP-Export für CERTs. |
| [Cloudflare](https://developers.cloudflare.com/fundamentals/reference/under-attack-mode/) | Under-Attack-Modus als „last resort“; Bot Management per ML; verifizierte Bots. | Zentral, proprietär, Datenmonopol. | Unsere Modi entsprechen dem; verifizierte gute Bots sind Pflicht. |
| [BunkerWeb](https://docs.bunkerweb.io/1.5.3/) | AGPL, nginx + ModSecurity/CRS, Antibot, CrowdSec-Plugin. | Keine Föderation. | Lokaler WAF-Proxy + CrowdSec ist schon Standardpaket. |
| [Project Honey Pot](https://www.projecthoneypot.org/httpbl.php) | Honeypot-Netz, http:BL mit Bedrohungsgrad und Alter. | Zentral. | Bedrohungsgrad + Alter statt Ja/Nein. |
| [Shadowserver](https://www.shadowserver.org/wp-content/uploads/2023/01/2022-01-18-Shadowserver_Fact_Sheet_v2.pdf) | Gemeinnützig, Tagesberichte für über 200 CSIRTs; EU-Förderung. 2020 [fiel die Hauptfinanzierung weg](https://krebsonsecurity.com/2020/03/the-webs-bot-containment-unit-needs-your-help/). | Berichtet, blockt nicht. | Finanzierungsrisiko ist real. Natürlicher Partner als Lab oder Datenquelle. |
| Blockchain-CIDS ([TU Darmstadt, CRITIS 2017](https://tubiblio.ulb.tu-darmstadt.de/104086/)) | Forschungsprototypen. | Kein nennenswerter Einsatz. | Transparenz-Log reicht; Blockchain bringt kaum Zusatznutzen. |

## Was die Forschung sagt

- **Zusammenarbeit erhöht Treffer und Fehlalarme.** Melis, Pyrgelis, De Cristofaro, „On Collaborative Predictive Blacklisting“, [ACM SIGCOMM CCR 2018](https://ccronline.sigcomm.org/2018/on-collaborative-predictive-blacklisting). Grundlage: Zhang, Porras, Ullrich, „Highly Predictive Blacklisting“, USENIX Security 2008.
- **Überblick CIDS:** Vasilomanolakis, Karuppayah, Mühlhäuser, Fischer, „Taxonomy and Survey of Collaborative Intrusion Detection“, ACM Computing Surveys 47(4), 2015.
- **Vertrauen und Sybil:** Fung, Zhang, Aib, Boutaba, [Dirichlet-based Trust Management für CIDN](https://personal.ntu.edu.sg/zhangj/paper/tnsm10.pdf), IEEE TNSM 2011. Li, Meng, Kwok, [On-Off-Angriffe auf CIDNs](https://doi.org/10.3390%2Ffi10010006), 2018: Ein Knoten ist zu einem Teil des Netzes ehrlich und behält so seinen Ruf; Vertrauenswerte allein reichen nicht.
- **Poisoning:** Ranade et al., [gefälschte CTI mit Transformern](https://mdsoar.org/handle/11603/21188), IJCNN 2021: Fachleute erkannten die Fälschungen nicht. Nguyen, Rieger, Miettinen, Sadeghi (TU Darmstadt), [Poisoning bei föderiertem IDS](https://www.ndss-symposium.org/wp-content/uploads/2020/04/diss2020-23003-paper.pdf), NDSS DISS 2020.
- **Datenschutzfreundlich teilen:** Freudiger, De Cristofaro, Brito, DIMVA 2015; Mokry et al., Secret Sharing + Differential Privacy, IEEE Big Data 2021; Veugen et al., Secure Aggregation, Frontiers in Big Data 2025. Besonders nah an uns: Thomas et al. (Google), [Robust, privacy-preserving, transparent, and auditable on-device blocklisting](https://arxiv.org/pdf/2304.02810), 2023, mit PSI, Signaturen und Merkle-Beweisen.
- **Deutsche Gruppen:** TU Darmstadt/ATHENE (Mühlhäuser, Vasilomanolakis; Sadeghi), Fraunhofer FIT (Koordination [SAPPAN](https://cordis.europa.eu/projects/833418), datenschutzfreundliches Teilen über MISP), Fraunhofer FKIE/Uni Bonn (MonIKA). Zu CISPA, KIT, Fraunhofer SIT nichts Passendes gefunden (ZU PRÜFEN).

## Standards, die wir nutzen

| Bereich | Prototyp | Später |
| --- | --- | --- |
| WAF | Caddy + Coraza + OWASP CRS (SecLang) | Eigene virtuelle Patches |
| Signaturen | Ed25519 (RFC 8032), mehrere Einzelsignaturen nach TUF-Schwellen | FROST (RFC 9591, nur Informational) |
| Regelverteilung | TUF (go-tuf), Probelauf (Schattenmodus), Canary, Rückzug aller Netzregeln mit k-von-n | – |
| Binärdateien | cosign/Rekor, SLSA, reproduzierbare Go-Builds, in-toto | – |
| Transparenz | Append-only-Log nach CT-Muster (RFC 9162) | SCITT (Architektur als RFC 9943, ZU PRÜFEN) |
| Signalformat | Eigenes kompaktes JSON mit Zuordnung zu STIX 2.1 *Sighting*; MISP-Export | TAXII 2.1 |
| Datenschutz | Keine Besucher-IPs in Signalen (E4), Positivliste, kurze Speicherdauer, ehrlich „pseudonym“, DSFA | OHTTP (RFC 9458), Privacy Pass/ARC, DAP/Prio (Draft) |
| Prüfung | PoW nach ALTCHA-Art (MIT, Go) | Privacy Pass (RFC 9577/9578) |
| Gute Bots | Forward-Confirmed Reverse DNS | Web Bot Auth (RFC 9421, IETF-Draft) |
| Fingerprints | Nur **JA4** (BSD) | JA4+ erst nach Lizenzklärung: FoxIO-Lizenz verbietet kommerzielle Nutzung |
| Sperrseite | RFC 9457 + `Retry-After` | – |

## Risiken, die die Recherche zeigt

1. **IPs lassen sich nicht wirksam pseudonymisieren.** Alle Clients bräuchten denselben HMAC-Schlüssel; wer ihn hat, probiert alle 2^32 IPv4-Adressen in Minuten durch. Rechtlich bleiben es personenbezogene Daten ([EDPB-Leitlinien 01/2025](https://edpb.europa.eu/news/news/2025/edpb-adopts-pseudonymisation-guidelines-and-paves-way-improve-cooperation_en), EuGH Breyer C-582/14). **Folge (E4, ENTSCHIEDEN 26.10.2026):** Besucher-IPs verlassen den Server gar nicht ([Prototyp-Verifikation](23-verifikation.md)). Land, ASN und Browser-Familie bleiben zusammen pseudonym: Rechtsgrundlage Art. 6 Abs. 1 lit. f DSGVO mit Erwägungsgrund 49, ab v1 OHTTP.
2. **Sybil-Clients.** Konsens zwischen Labs hilft gegen böse Labs, nicht gegen viele gefälschte Clients, die jedes Lab füttern. **Folge:** Hoster bürgen für Clients, Labs betreiben Honeypots, Mindestvielfalt nach ASN und Betreiberart.
3. **Mehr Fehlalarme durch Zusammenarbeit**, Kollateralschäden bei CGNAT, Mobilfunk, Tor, Cloud. **Folge:** personalisierte Empfehlungen, MISP-Warninglists, Autoverify statt Sperre bei geteilten Netzen, und messen ([Testkonzept](14-testkonzept.md)).
4. **Eine schlechte Regel schadet mehr als eine falsche IP**, weil sie per Konsens alle gleichzeitig trifft. **Folge:** Probelauf und Canary als Pflicht, Rückzug aller Netzregeln mit k-von-n, getrennte Schlüssel für Regeln und Binärdateien.
5. **Neutralität und Geld.** Gegen geheime Anordnungen hilft ein Log nur begrenzt; keine Betreiberart darf allein die Mehrheit haben. Gemeinnützige Infrastruktur kann am Geld scheitern (Shadowserver). Nach dem CRA (VO 2024/2847) wäre der Träger voraussichtlich *Open-Source-Steward* (Art. 24), ein Hoster, der den Schild verkauft, womöglich *Hersteller* (rechtlich ZU PRÜFEN).

## Name und Regulierung

- Der Cyber Solidarity Act (VO 2025/38) hieß im Entwurf „European Cyber Shield“, im beschlossenen Text „European Cybersecurity Alert System“. „Deutschland-Schild“ kann deshalb nach Staatsprogramm klingen und die Wahrnehmung als neutral gefährden.
- NIS2: Umsetzungsgesetz in Kraft seit 6.12.2025 (ZU PRÜFEN). Viele Hoster sind selbst betroffen; der Schild kann beim Nachweis helfen.

## Konsequenz

Coraza und CRS upstream stärken, MISP-Warninglists übernehmen, geprüfte Regeln an den CrowdSec Hub zurückgeben (offen); Shadowserver, DFN-CERT, TU Darmstadt/ATHENE und Fraunhofer FIT als Labs oder Gutachter ansprechen. Unser Beitrag ist eine **offene, föderierte Schicht für Konsens, Transparenz und Neutralität**.
