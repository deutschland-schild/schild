---
short: "Forschung: WAF & KI-Angriffe"
group: Wie
description: "Was die Forschung 2024–2026 über WAFs, Blocklisten, Bot-Abwehr und KI-Angreifer sagt – und was daraus für das Deutschland-Schild folgt."
---

# Forschung: WAF-Wirksamkeit und KI-Angriffe

**Status:** ENTWURF · Recherche Stand 25.10.2026 · Unsicheres ist mit **[unsicher]** markiert · Ergänzt [16 – Stand der Technik](16-stand-der-technik.md) (CrowdSec, MISP, CIDS-Literatur werden hier nicht wiederholt)

**Kurz:**

- Recherche (Stand 25.10.2026) zu WAF-Wirksamkeit, IP-Blocklisten, Bot-Abwehr und KI-Angreifern; ergänzt [Stand der Technik](16-stand-der-technik.md).
- Befund: OWASP CRS hält Massenangriffe ab; adaptive Angreifer, auch mit LLMs, finden fast immer Umgehungen. Größte Klasse: Parser-Unterschiede (WAFFLED).
- Acht Empfehlungen, u. a. gleichförmige Antworten ohne Regel-ID, HTTP-Normalisierung vor Coraza, Sitzungs-Score zusätzlich zum Request-Score.
- Virtuelle Patches aus Patch-Diffs mit Pflicht-Tests, Zielmarke unter 5 Stunden; kein LLM im Inline-Pfad, Täuschung nur passiv im Testlab.
- Noch zu prüfen: Volltexte (AutoWAFuzzer, SBSeg 2025, Patchstack 2026) und eigene CRS-Zahlen aus dem Testbed statt Herstellervergleichen.

**Kernaussage:** Wer die Antworten einer WAF auswertet, findet laut Forschung fast immer Umgehungen, inzwischen auch mit Sprachmodellen, und Lücken werden schneller ausgenutzt, als ein Patch-Zyklus dauert. Unser Konzept (Scoring, Proof of Work, Konsens mehrerer Labs, virtuelle Patches) stimmt im Kern. Es fehlen **Antworten, die Angreifern nichts verraten**, **Erkennung über Sitzungen** und **strikte HTTP-Normalisierung vor der WAF**.

## 1. Wie gut wirken WAFs und Autoblocking?

### 1.1 CRS: Fehlalarme und Paranoia-Level

- **Keine unabhängigen Fehlalarmquoten pro Paranoia-Level gefunden.** Die CRS-Doku sagt nur qualitativ, dass mit höherem Level Treffer und Fehlalarme steigen, und empfiehlt, im Blockiermodus mit sehr hoher Schwelle (bis 10000) zu starten und sie schrittweise zu senken ([CRS Anomaly Scoring](https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/), [Folini/netnea](https://www.netnea.com/cms/?p=1395)). Auf PL 4 erzeugt schon eine Standard-Drupal-Seite massenhaft Fehlalarme, auf PL 1 mit App-Ausnahmen fast keine ([netnea](https://www.netnea.com/cms/?p=1395)).
- **Herstellervergleiche sind befangen.** Das „WAF Comparison Project“ von open-appsec testet NGINX + ModSecurity mit CRS 4.20.0, stammt aber vom Hersteller eines Konkurrenzprodukts ([open-appsec 2026](https://www.openappsec.io/post/best-waf-solutions-in-2026-real-world-comparison)). Check Point berichtet daraus für Azure WAF (CRS 3.2) 97,5 % Erkennung bei **54,2 % Fehlalarmen** ([Check Point](https://blog.checkpoint.com/artificial-intelligence/waf-security-test-results-how-does-your-vendor-rate/)), vermutlich ohne Tuning **[unsicher]**, die Konfiguration ist nicht offengelegt.
- **ML über CRS-Regeln** verbessert das Verhältnis aus Erkennung und Fehlalarm und kommt mit über 30 % weniger Regeln aus (ModSec-Learn, [Scano et al. 2024](https://arxiv.org/abs/2406.13547)). Die handgesetzten CRS-Gewichte sind laut [ModSec-AdvLearn](https://arxiv.org/abs/2308.04964) suboptimal.
- **Das Regelwerk selbst hat Lücken.** [CVE-2026-21876](https://coreruleset.org/20260106/cve-2026-21876-critical-multipart-charset-bypass-fixed-in-crs-4.22.0-and-3.3.8/): Regel 922110 prüfte nur den letzten Teil eines Multipart-Requests; betroffen alle CRS-Versionen bis 4.21.0, auch mit Coraza, behoben in 4.22.0.

### 1.2 Umgehungsforschung

| Arbeit | Methode | Ergebnis gegen ModSecurity/CRS |
| --- | --- | --- |
| [WAF-A-MoLE](https://arxiv.org/abs/2001.01952) (Demetrio et al., SAC 2020) | Mutationen von SQLi, semantikerhaltend | Umgeht alle getesteten ML-WAFs; Wrapper für CRS vorhanden |
| [ModSec-AdvLearn](https://arxiv.org/abs/2308.04964) (Montaruli, Floris, Demetrio, Biggio u. a.) | WAF-A-MoLE gegen CRS | Standard-CRS ist **nicht robust** gegen iterative SQLi; Abhilfe: adversariales Training |
| [AutoSpear](https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-Qu-AutoSpear-Towards-Automatically-Bypassing-and-Inspecting-Web-Application-Firewalls.pdf) / [AdvSQLi](https://arxiv.org/abs/2401.02615) (Qu et al., IEEE TIFS 2024) | Syntaxbaum + Monte-Carlo-Baumsuche | Alle 7 WAF-as-a-Service verwundbar; wirksamste Mutationen: Inline-Kommentare, Whitespace, DML-Ersatz. ModSecurity lag laut Presse bei ca. 3 % Umgehung ([Dark Reading](https://www.darkreading.com/cloud-security/transforming-sql-queries-bypasses-waf-security)) **[unsicher]** |
| [WAFFLED](https://arxiv.org/abs/2503.10846) (Akhavani et al., ACSAC 2025) | Fuzzing von **Parser-Unterschieden** (JSON, Multipart, XML) zwischen WAF und Framework | **1207 Umgehungen** bei AWS, Azure, Cloud Armor, Cloudflare, ModSecurity. Über 90 % der Websites akzeptieren Form- und Multipart-Kodierung austauschbar. Abhilfe: **HTTP-Normalizer**-Proxy nach RFC |
| [GenXSS](https://arxiv.org/abs/2504.08176) (2025) | GPT-4o erzeugt XSS-Payloads | **80 % umgehen ModSecurity + CRS**; 15 neu erzeugte Regeln blocken danach 86 % |
| [AutoWAFuzzer](https://inseclab.uit.edu.vn/autowafuzzer-an-adaptive-framework-for-web-application-firewall-penetration-testing-with-multi-agent-system-and-rag-enabled-reinforcement-learning/) (ESWA 2026) | LLM-Agenten + Reinforcement Learning, WAF-Antwort als Belohnung | Laut Autoren deutlich höhere Umgehungsrate gegen ModSecurity, Naxsi u. a. **[unsicher]**, Zahlen nicht eingesehen |
| [Cloudflare, „We tested our own WAF with frontier AI models“](https://blog.cloudflare.com/adaptive-ai-waf-testing/) (29.09.2026) | Zwei LLM-Aufrufe schlagen nach jedem 403 die nächste Variante vor; CRS PL 3 + Managed Rules | 1107 Versuche, 49 WAF-relevante Funde nach Prüfung (fast alle Command Injection und SSRF). Typisch: 403 auf Metadaten-IP → Dezimal-, Oktal-, Punkt-Varianten |

**Lehre:** Signaturen verlieren gegen Angreifer, die unbegrenzt fragen dürfen und eine klare Ja/Nein-Antwort bekommen. Mehr als bessere Regeln helfen **Parser-Gleichheit** (WAFFLED) und **weniger Rückmeldung** an den Angreifer.

### 1.3 IP-Blocklisten und Kollateralschäden

- **CGNAT:** Hinter einer IPv4-Adresse können Hunderte bis Tausende Nutzer stehen. Bei Cloudflare werden CGNAT-IPs **etwa dreimal so oft gedrosselt** wie andere, weil Bot- und Firewall-Regeln legitimen Traffic mittreffen ([Cloudflare, 29.10.2025](https://blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage/)). Cloudflare erkennt CGNAT inzwischen per Klassifikator und kalibriert Regeln danach.
- **IP-Sperren im großen Stil:** Italiens „Piracy Shield“ sperrte im Juni 2025 10.918 IPv4-Adressen; RIPE-Messungen fanden 6.712 vollständig mitgesperrte Domains. Empfehlung dort: befristet, transparent, möglichst nicht IP-basiert ([RIPE Labs](https://labs.ripe.net/author/antonio-prado/live-event-blocking-at-scale-effectiveness-vs-collateral-damage-in-italys-piracy-shield/), [APNIC](https://blog.apnic.net/2025/10/17/an-italian-case-study-collateral-damage-from-live-event-site-blocking-with-piracy-shield/)).
- **Residential Proxies** machen IP-Reputation stumpf: [Mi et al., IEEE S&P 2019](https://cse.buffalo.edu/faculty/xmi/publication/resi_sp/) fanden 6 Mio. Proxy-IPs in über 52.000 ISPs, viele auf vermutlich kompromittierten Geräten (inkl. IoT). [Chiapponi, Dacier, Thonnard (EURECOM)](https://www.eurecom.edu/en/node/4900739) schlagen Listen verdächtiger /24-Netze vor.
- **CrowdSec unabhängig evaluiert?** Kein Paper, keine Abschlussarbeit, kein unabhängiger Benchmark gefunden; nur Herstellerzahlen, z. B. 91 % weniger Angriffe im Zwei-Server-Vergleich ([CrowdSec-Blog](https://www.crowdsec.net/blog/without-and-with-a-crowdsec-bouncer-a-tale-of-two-servers)). Diese **Forschungslücke** könnten unsere Labs füllen.

### 1.4 Bot-Abwehr, Proof of Work, Captchas

- **Bildcaptchas sind gebrochen:** reCAPTCHA v2 wird mit YOLO-Modellen zu 100 % gelöst; Menschen und Bots brauchen gleich viele Aufgaben. reCAPTCHA stützt sich stark auf Cookies und Browserverlauf ([Plesner, Vontobel, Wattenhofer, ETH Zürich 2024](https://arxiv.org/abs/2409.08831)).
- **Proof of Work (Anubis):** wirkt gegen billige Crawler ohne JavaScript, wie der Autor selbst sagt ([The Register, 09.07.2025](https://www.theregister.com/2025/07/09/anubis_fighting_the_llm_hordes/)). Kritiker rechnen vor, dass die Rechenkosten für große Scraper praktisch null sind ([fxgn.dev](https://fxgn.dev/blog/anubis)) **[unsicher]**, nicht unabhängig geprüft. Ein gelöstes Token lässt sich wiederverwenden.
- **Bot-Anteil:** 51 % des Web-Traffics 2024 automatisiert, davon 37 % „bad bots“ ([Imperva Bad Bot Report 2025](https://www.intelligentcio.com/me/2025/04/20/ai-fuels-hard-to-detect-bots-that-generate-half-of-internet-traffic-says-imperva/); Herstellerzahl). KI-Bots machten 2025 4,2 % der HTML-Requests bei Cloudflare aus ([Cloudflare Radar 2025, via SEJ](https://www.searchenginejournal.com/cloudflare-report-googlebot-tops-ai-crawler-traffic/563303/)).
- **robots.txt wird umgangen:** Cloudflare wirft Perplexity vor, nach Sperre mit Chrome-User-Agent, fremden IPs und wechselnden ASNs weiterzucrawlen ([Cloudflare, 04.08.2025](https://blog.cloudflare.com/perplexity-is-using-stealth-undeclared-crawlers-to-evade-website-no-crawl-directives/)); Perplexity bestreitet das ([TechRadar](https://www.techradar.com/pro/perplexity-hits-back-after-cloudflare-slams-its-online-scraping-tools)).

**Lehre:** Unsere Stufe 40–69 (PoW auf einer Zwischenseite, falls der Betreiber die Prüfung im Browser einschaltet, [Datenschutzkonzept](24-datenschutz.md), Abschnitt 10) bremst Masse, aber keine zahlungskräftigen Angreifer. PoW ist ein **Kostenaufschlag**, kein Mensch-Nachweis, und so kommunizieren wir es auch.

## 2. KI-Agenten als Angreifer

### 2.1 Forschung

| Arbeit | Kernergebnis |
| --- | --- |
| [Fang et al., „LLM Agents can Autonomously Hack Websites“](https://arxiv.org/abs/2402.06664) (2024) | GPT-4-Agent löst 73,3 % von 15 Web-Lücken (pass@5), u. a. blinde SQLi; offene Modelle damals nicht |
| [Fang et al., One-Day](https://arxiv.org/abs/2404.08144) (2024) | GPT-4 nutzt **87 %** von 15 echten CVEs aus, **wenn die CVE-Beschreibung vorliegt**; ohne nur 7 %. Agent: 91 Zeilen Code |
| [Teams of LLM Agents / HPTSA](https://arxiv.org/abs/2406.01637) (EACL 2026) | Planer + Spezialagenten: 42 % pass@5 bei Zero-Days (v2), bis 4,3× besser als Einzelagent; ZAP/Metasploit 0 % |
| [CVE-Bench](https://arxiv.org/abs/2503.17332) (ICML 2025) | 40 kritische Web-CVEs, Schwerpunkt **WordPress**-artige CMS; bester Agent damals bis 13 % |
| [Cybench](https://arxiv.org/abs/2408.08926) (2024) | 40 Profi-CTFs; Modelle lösen Aufgaben, für die Menschen bis 11 Minuten brauchten |
| [PentestGPT](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) (USENIX Sec 2024) | +228,6 % Aufgabenerfüllung ggü. GPT-3.5; Schwäche: Kontextverlust, Langzeitplanung |
| [AutoAttacker](https://arxiv.org/abs/2403.01038) (2024) | LLM für Post-Breach-Phase (Windows/AD, Linux); damals nur GPT-4 fähig |

Benchmarks veralten schnell; die Zahlen sind Untergrenzen für heutige Modelle **[unsicher]**.

### 2.2 Praxis 2025–2026

- **XBOW** stand im Q2 2025 auf Platz 1 der US-Rangliste von HackerOne; über 1.000 Meldungen, Menschen prüften vor Einreichung ([XBOW](https://xbow.com/blog/top-1-how-xbow-did-it/), [TechRepublic](https://www.techrepublic.com/article/news-ai-xbow-tops-hackerone-us-leaderboad/)).
- **Google Big Sleep** fand CVE-2025-6965 in SQLite, laut Google bevor Angreifer sie nutzten ([SecurityWeek](https://www.securityweek.com/google-says-ai-agent-thwarted-exploitation-of-critical-vulnerability/)); Details nicht offengelegt.
- **DARPA AIxCC Finale (08/2025):** 54 künstlich eingebaute Lücken gefunden, 43 gepatcht; 18 echte Lücken, durchschnittlich 152 $ pro Aufgabe ([DARPA](https://darpa.mil/news/2025/aixcc-results)). Vier Systeme Open Source.
- **Anthropic, GTG-1002 (11/2025):** chinesische Staatsgruppe ließ Claude Code 80–90 % einer Spionagekampagne gegen ca. 30 Ziele ausführen; Menschen nur an 4–6 Entscheidungspunkten. Grenze: halluzinierte Zugangsdaten ([Anthropic](https://www.anthropic.com/news/disrupting-AI-espionage)).
- **Anthropic, Bericht September 2026:** Agenten-Schwärme mit Lead-Agent und Gedächtnis; eine autonome Pipeline testete Injection, XSS, Auth-Bypass und SSRF ohne Aufsicht; Einbrüche in **2–3 Stunden**. Eine Gruppe nutzte eine **WordPress-Race-Condition bei der Neuinstallation** für einen Admin-Account und tarnte eine Webshell als Font-Datei. Fazit: Signaturbasierte Erkennung allein kostet Angreifer, die Umgehung automatisieren, zu wenig ([Anthropic, 09/2026](https://anthropic.com/threat-intelligence-report-september-2026)).
- **OpenAI (10/2025):** Angreifer bauen KI meist in bestehende Werkzeugketten ein, statt neue zu erfinden ([SiliconANGLE](https://siliconangle.com/2025/10/07/openai-details-expanding-efforts-disrupt-malicious-use-ai-new-report/)).
- **Google GTIG:** 11/2025 erste Malware, die zur Laufzeit LLMs fragt (PROMPTSTEAL bei APT28, PROMPTFLUX experimentell) ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools)). 05/2026 erster mutmaßlich KI-entwickelter Zero-Day im Einsatz ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access)). 09/2026: Wachstum vor allem durch schnellere **n-Day-Ausnutzung** per Patch-Analyse mit LLMs; mutmaßlich KI-gefundene Lücken führen in 50 % zu RCE (sonst 26 %) ([Help Net Security](https://www.helpnetsecurity.com/2026/10/01/google-ai-discovered-vulnerabilities-remote-code-execution/)).
- **Echte KI-Agenten im Netz bisher selten:** Palisades LLM-Honeypot sah in drei Monaten 8,1 Mio. Angriffsversuche, davon 8 mögliche KI-Agenten ([Reworr, Volkov 2024/25](https://arxiv.org/abs/2410.13919)).

### 2.3 Was das für die Verteidigung heißt

Die Zeit bis zur Ausnutzung schrumpft: 28,96 % der KEV-Lücken 2025 wurden am Tag der CVE-Veröffentlichung oder früher ausgenutzt ([VulnCheck 2026](https://www.vulncheck.com/blog/state-of-exploitation-2026)). Bei WordPress vergehen im gewichteten Median **5 Stunden** bis zur Massenausnutzung; 2025 gab es 11.334 neue Lücken, 91 % davon in Plugins ([Patchstack 2026](https://www.patchstack.com/whitepaper/state-of-wordpress-security-in-2026/); Detailzahlen aus Sekundärquellen **[unsicher]**). Dazu kommen polymorphe Payloads (GenXSS umgeht CRS zu 80 %, PROMPTFLUX lässt sich stündlich neu verschleiern, die Funktion ist noch deaktiviert), Angreifer, die aus jedem 403 lernen (Cloudflare-Test, AutoWAFuzzer), Low-and-slow über Millionen Residential-Proxy-IPs und LLM-Crawler, die als Browser auftreten und robots.txt teils ignorieren.

## 3. KI auf der Verteidigungsseite

### 3.1 LLM-Klassifikation und Regelgenerierung

- **Transformer auf HTTP-Requests** erreichen auf Labordaten sehr hohe F1-Werte, generalisieren aber schlecht: Ein BERT-Modell fiel bei unbekannten Angriffstypen auf F1 61,5 % ([CNSM 2023](https://dl.ifip.org/db/conf/cnsm/cnsm2023/1570932667.pdf)). Bei WAMM schlägt XGBoost mit Mikrosekunden-Latenz die tiefen Modelle ([arXiv 2512.23610](https://arxiv.org/abs/2512.23610)). Inline sind LLMs zu langsam und zu teuer.
- **Prompt Injection über Payloads:** LLM-basierte Klassifikatoren lassen sich mit Zeichen-Injektion und adversarialem ML umgehen, teils zu 100 % ([Hackett et al. 2025](https://arxiv.org/abs/2504.11168)). Ein LLM, das Angreifer-Payloads liest, ist selbst Angriffsfläche.
- **LLM erzeugt WAF-Regeln:** GenXSS zeigt den Nutzen (15 Regeln, 86 % geblockt). Eine Studie vergleicht fünf LLMs für ModSecurity-Regeln ([SBSeg 2025](https://sol.sbc.org.br/index.php/sbseg/article/cite/36669/AbntCitationPlugin)) **[unsicher]**, nur Metadaten gesehen. Ein Praxisbericht: Regeln nur aus dem CVE-Text sind schwach, und Fehlalarme sind oft schlimmer als keine Regel ([Miggo](https://www.miggo.io/post/from-cve-to-waf-rule-in-minutes-what-we-learned-building-an-ai-pipeline-that-ships), Herstellerblog).
- **Sitzungs- statt Request-Erkennung:** Kaum aktuelle Forschung zu mehrstufigen Web-Angriffen über Sitzungen gefunden; vorhanden sind ältere Sequenzmodelle und eine Masterarbeit zu Clustering von Sitzungen ([PoliTo 2025](https://webthesis.biblio.polito.it/38691)). **Forschungslücke.**

### 3.2 Täuschung gegen KI-Agenten

- **Cloudflare AI Labyrinth (03/2025):** Verdächtige Crawler bekommen vorab erzeugte Köderseiten statt eines Blocks, weil ein Block dem Bot verrät, dass er erkannt wurde. Wer vier Ebenen tief folgt, ist mit großer Wahrscheinlichkeit ein Bot; das dient als Signal für die Erkennung ([The Register](https://www.theregister.com/2025/03/21/cloudflare_ai_labyrinth/)).
- **Nepenthes:** Teergrube mit endlosen Links und Markov-Text; laut Autor fängt sie fast alle großen Crawler (nicht unabhängig geprüft) ([404 Media](https://www.404media.co/developer-creates-infinite-maze-to-trap-ai-crawlers-in/)).
- **Prompt Injection als Abwehr (Mantis):** Köderdienste antworten mit Injektionen, die angreifende LLM-Agenten stören oder in Schleifen schicken ([Pasquini et al. 2024](https://arxiv.org/abs/2410.20911)). Die „Hack-back“-Variante (Reverse Shell beim Angreifer) ist in Deutschland rechtlich nicht vertretbar (§ 202a ff. StGB); in Frage kommt nur die passive.
- **Erkennung von Agenten:** Palisade nutzt eingebettete Prompt Injection plus Antwortzeiten (unter 1,5 s) ([arXiv 2410.13919](https://arxiv.org/abs/2410.13919)).

## 4. Folgen für unser Konzept

### 4.1 Empfehlungen

1. **Antworten ohne Information.** Kein sprechender 403 mit Regel-ID. Ab Score ≥ 70 eine einheitliche, neutrale Antwort, die sich nicht von anderen Fehlern unterscheidet; Details nur im lokalen Log. Bei Verdacht auf iteratives Testen (viele Varianten eines Payloads) **verzögern und gleich antworten**, statt sofort zu sperren. Die Bypass-Schleifen (Cloudflare-Test, AutoWAFuzzer, AdvSQLi) brauchen genau dieses Signal.
2. **HTTP-Normalisierung vor Coraza.** Mehrdeutige Requests (doppelte Header, gemischte Content-Types, exotische Charsets, Multipart-Sonderfälle) normalisieren oder abweisen, bevor die WAF prüft, nach dem Vorbild von WAFFLEDs HTTP-Normalizer. In den Labs WAFFLED-Fuzzing gegen unseren Stack (Caddy → Coraza → PHP) als festen Test aufnehmen.
3. **Sitzungs-Score zusätzlich zum Request-Score.** Pro Client (Token, TLS-/HTTP-Fingerprint, nicht nur IP) über ein Zeitfenster zählen: geblockte Varianten, Breite der getesteten Parameter, Tempo. „Viele knapp unter 40“ muss eskalieren. Das hilft gegen Low-and-slow und adaptive Agenten. Weil es dazu kaum Literatur gibt, ist es ein eigenes Forschungsthema für die Labs.
4. **IP nur als schwaches, lokales Signal.** Aus dem Netz kommt kein Wissen über IPs, Besucher-IPs verlassen den Server nicht (E4); Labs bewerten Muster, nicht Absender. Lokal (eigene Ratenbegrenzung, eigene Sperren, selbst gewählte Listen wie Spamhaus DROP) gilt bei CGNAT/Mobilfunk standardmäßig höchstens „Proof of Work“ statt „Block“, Sperren nur kurz. Das bestätigt unseren Ansatz mit Warninglists und verschärft ihn.
5. **Patch-to-Rule-Pipeline mit Pflicht-Tests.** Labs leiten virtuelle Patches aus Patch-Diffs ab, nicht nur aus CVE-Text, LLM-gestützt. Verteilt wird erst nach Positiv-/Negativtests (go-ftw, Traffic-Mitschnitte) und **14 Tagen Beobachtungsmodus**; bei kritischen WordPress-Lücken gibt es einen Schnellpfad mit „nur loggen + PoW“ statt Block. Zielmarke unter 5 Stunden, weil die Massenausnutzung bei WordPress so schnell beginnt.
6. **Täuschung nur im Testlab und passiv.** Labs betreiben Köder-WordPress-Instanzen mit Mantis-artigen passiven Injektionen und Teergruben, um KI-Agenten zu erkennen und ihre Muster in Signale zu übersetzen. Kein Hack-back. Im Produktiv-Proxy höchstens optional ein Labyrinth für bekannte Crawler, nicht standardmäßig (Last, Fehlalarme).
7. **Kein LLM im Inline-Pfad.** Inline klassifizieren CRS und schlanke Modelle. LLMs laufen nur offline in den Labs (Regelvorschläge, Log-Auswertung) und behandeln Payloads als Daten (Sandbox, keine Werkzeugrechte), weil Payloads Prompt Injection enthalten können.
8. **WordPress/PHP-Profil.** Positive Regeln für typische Angriffsflächen: `wp-admin/install.php` und `setup-config.php` nach der Installation sperren, Uploads mit PHP-Code in Bild-/Font-Pfaden blocken, `xmlrpc.php` drosseln, REST-Nutzeraufzählung begrenzen. Genau diese Wege zeigt der Anthropic-Bericht vom September 2026 in echten Angriffen.

### 4.2 Was neu ist und was das Konzept bestätigt

| Befund | Bestätigt | Neu für uns |
| --- | --- | --- |
| CRS ist bei Massenangriffen gut, gegen adaptive Angreifer nicht robust | Scoring statt Ja/Nein, Labs mit Exploit-Forschung | Fester Umgehungstest (WAF-A-MoLE, AdvSQLi, GenXSS) im Lab |
| Parser-Unterschiede sind die größte Umgehungsklasse | – | **Normalisierung vor der WAF** (Empf. 2) |
| Blocks liefern Angreifern Feedback | PoW-Zwischenseite in 40–69 (ab Werk aus) | **Uninformative, gleichförmige Antworten** (Empf. 1) |
| CGNAT/Residential Proxies machen IP-Sperren teuer und stumpf | Warninglists, Fail-open, Entsperrverfahren | IP nur als schwaches, lokales Signal (Empf. 4) |
| Time-to-Exploit in Stunden | Virtuelles Patchen durch Labs | Zielmarke unter 5 Stunden, Patch-Diff statt CVE-Text (Empf. 5) |
| Captchas gebrochen, PoW nur Kostenaufschlag | PoW statt Captcha | PoW ehrlich als Bremse kommunizieren |
| KI-Agenten selten, aber schnell wachsend | KI-Forschung in den Labs | Köder und Agenten-Erkennung (Empf. 6) |
| LLM-Klassifikatoren sind angreifbar und langsam | – | Kein LLM inline (Empf. 7) |
| CrowdSec nicht unabhängig evaluiert | Offener Algorithmus, Transparenz-Log | Eigene, veröffentlichte Evaluation als Beitrag der Labs |

**ZU PRÜFEN:** Volltexte von AutoWAFuzzer, SBSeg 2025 und Patchstack 2026; aktuelle CRS-Zahlen aus dem eigenen Testbed ([Testkonzept](14-testkonzept.md)) statt Herstellervergleichen.
