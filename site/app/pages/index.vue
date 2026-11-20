<script setup lang="ts">
import type { FaqGroup } from '~/components/FaqList.vue'
import { ISSUES_URL, RELEASES_URL, RELEASE_VERSION, REPO_URL } from '~/utils/release'

// Start page: one product, the Schild Gateway, and one primary action, installing it. Order: hero with "Warum jetzt?" →
// how it works → what it does → dashboard → install (with what happens afterwards and how the gateway itself is secured) → comparison → small teaser for the network → FAQ → contact. The
// former page for operators and admins (/betreiber) is part of this page now. Labs, relays and the roadmap live on /netz.
// Every claim here has to hold for the gateway as built, without labs. Terms: docs/brand/01-marke.md, "Glossar".

// Hero "Warum jetzt?": the problem in three short points. Time to exploit: GTI/Mandiant (15.10.2024): average 63 days
// (2018–2019) → 5 days (2023); GTI (30.09.2026): zero-days are 62 % of exploited vulnerabilities (Jan–Aug 2026). Attackers
// use LLMs to weaponize n-days from patches; one example exploited 4 days after disclosure. The exploitation figure
// (10.5/month in 2025 → 18/month in 2026, +71 %) is shown once, with the comparison (`figures`). AI analysis in the Labs is planned, not built (see /netz#labs).
const whyNow = [
  { title: 'Angriffe mit KI', text: 'Angreifer lassen KI Updates und Sicherheitshinweise auswerten und haben schneller einen fertigen Angriff. Die Zahl tatsächlich ausgenutzter Lücken steigt deutlich.', src: 'https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era' },
  { title: 'Tage statt Monate', text: 'Früher lagen zwischen einer bekannten Lücke und ersten Angriffen im Schnitt zwei Monate, 2023 waren es noch fünf Tage. Heute bauen Angreifer aus neuen Updates oft in wenigen Tagen fertige Angriffe. Wer erst am Wochenende reagiert, ist zu spät.', src: 'https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023', src2: 'https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era' },
  { title: 'Ein Schild vor deiner Website', text: 'Schild prüft jede Anfrage, bevor sie deine Website erreicht, und erkennt typische Angriffsversuche auch dann, wenn dein Update noch aussteht. Das ersetzt kein Update, aber es verschafft dir Zeit.', src: '' },
]

// Two figures with sources, shown with the comparison.
const figures = [
  { figure: '+71 %', text: 'mehr tatsächlich ausgenutzte Lücken pro Monat (Januar bis August 2026 gegenüber 2025)', src: 'https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era' },
  { figure: '1 von 3', text: 'PHP-Websites läuft auf PHP 7 oder älter, ohne Sicherheitsupdates vom PHP-Projekt', src: 'https://w3techs.com/technologies/details/pl-php' },
]

// Comparison columns: fail2ban, CrowdSec, Cloudflare WAF, Schild. Fair; claims about others link to `compareSources`.
// The Schild column names only what the released gateway does (D72): no planned parts.
const compare = [
  ['Läuft', 'auf deinem Server', 'auf deinem Server, ab Werk verbunden mit dem Dienst der Firma', 'beim Anbieter, dein Traffic läuft über ihn', 'auf deinem Server, vor deiner Anwendung'],
  ['Prüft', 'Logzeilen, nach der Anfrage', 'Logzeilen; mit der AppSec-Komponente auch die Anfrage', 'jede Anfrage, beim Anbieter entschlüsselt', 'jede Anfrage, bevor sie deine Anwendung erreicht'],
  ['Verlässt den Server', 'ab Werk nichts', 'ab Werk Meldungen mit angreifender IP-Adresse, Szenario und Zeit; abschaltbar', 'der gesamte Traffic', 'nichts aus deinem Traffic'],
  ['Regeln von außen', 'keine', 'IP-Blocklisten (gratis 3.000 bis 15.000 Adressen) und virtuelle Patches aus dem Hub', 'im Free-Tarif das Free Managed Ruleset; der volle Satz und das OWASP Core Ruleset ab Pro', 'OWASP Core Rule Set eingebaut; dazu virtuelle Patches aus dem öffentlichen CrowdSec Hub, ab Werk auf „Erkennen“'],
  ['Selbst anpassen', 'Konfigurationsdateien', 'Szenarien und Regeln (YAML)', 'im Free-Tarif 5 eigene Regeln, Regex ab Business', 'eigene Regeln als Datei; Ausnahmen, Schwellen und Limits im Dashboard'],
]
const compareSources = [
  ['fail2ban, Projektseite', 'https://github.com/fail2ban/fail2ban'],
  ['CrowdSec Docs, AppSec-Komponente', 'https://docs.crowdsec.net/docs/next/appsec/intro'],
  ['CrowdSec Hub, AppSec-Regeln (vpatch-*)', 'https://github.com/crowdsecurity/hub/tree/master/appsec-rules/crowdsecurity'],
  ['CrowdSec Docs, Central API (was die Engine sendet)', 'https://docs.crowdsec.net/docs/next/central_api/intro'],
  ['CrowdSec Docs, Community Blocklist (Lite und Community)', 'https://docs.crowdsec.net/docs/next/central_api/community_blocklist'],
  ['Cloudflare Docs, wie Cloudflare arbeitet (Proxy)', 'https://developers.cloudflare.com/fundamentals/concepts/how-cloudflare-works/'],
  ['Cloudflare Docs, Managed Rules (voller Managed Ruleset ab Pro-Tarif)', 'https://developers.cloudflare.com/waf/managed-rules/'],
  ['Cloudflare Docs, Custom Rules (Limits je Tarif)', 'https://developers.cloudflare.com/waf/custom-rules/'],
]

const steps = [
  { title: 'Installieren', text: 'Als Docker-Container oder Linux-Binary: Nutzt du Caddy, bekommst du Caddy inkl. Schild – mit deinem Caddyfile und deinen Zertifikaten. Sonst läuft Schild hinter nginx, Apache oder deinem Load Balancer. Deine Anwendung bleibt unverändert.' },
  { title: 'Hinschauen', text: 'Ab dem Start sperrt Schild bekannte Angriffe. Im Dashboard siehst du an deinem echten Traffic, was gestoppt und was nur erkannt wurde. Bei einer empfindlichen Anwendung lässt du die Regeln die ersten Tage nur erkennen.' },
  { title: 'Feinjustieren', text: 'Vier Szenarien (u. a. Login-Schutz) sperren nach 14 Tagen Lernzeit selbstständig. Limits und weitere Regeln schaltest du bei Bedarf einzeln dazu – jede Sperre lässt sich mit einem Klick zurücknehmen.' },
]

// Built and on hand without labs; see gateway/README.md and docs/gateway. Promises that are still planned stay off this list.
const features = [
  { title: 'Web Application Firewall', text: 'Das OWASP Core Rule Set erkennt SQL-Injection-Versuche, Cross-Site-Scripting und andere typische Angriffsversuche. Geprüft wird direkt auf deinem Server.' },
  { title: 'Login-Schutz', text: 'Schild erkennt massenhafte Login-Versuche bei WordPress, TYPO3, Joomla, Drupal, Nextcloud und Laravel. Nach 14 Tagen Lernzeit sperrt der Login-Schutz von selbst – jede Sperre läuft automatisch wieder ab.' },
  { title: 'Dashboard', text: 'Besucher, Angriffsversuche, Vorfälle und Regeln an einem Ort. Erreichbar nur lokal, per SSH-Tunnel oder VPN, Anmeldung mit Passwort.' },
  { title: 'Server-Check', text: 'Liest nur mit und prüft Updates, offene Ports, Firewall, SSH und Zertifikate. Schild selbst ändert dabei nichts.' },
  { title: 'Eigene IPs', text: 'Schalte dich und dein Team dauerhaft oder befristet frei, damit du dich nicht aussperrst.' },
  { title: 'Daten bleiben bei dir', text: 'Nichts aus deinem Traffic verlässt den Server. Schild holt nur öffentliche Regeln und Listen ab.' },
]

// Real screenshots of the gateway dashboard in mock mode (component DashboardShots). Sidebar as in the gateway without
// labs: no Verbund, no approvals or signals.
const gatewayShots = [
  {
    src: '/img/dashboards/gateway-website.webp',
    title: 'Alle Websites',
    summary: 'Status, Anfragen und Alarme auf einen Blick',
    text: 'Alle Websites deines Servers in einer Übersicht: Anfragen pro Sekunde, gestoppter Anteil, Antwortzeit und aktive Hinweise.',
    benefit: 'Du siehst sofort, ob Grundschutz aktiv ist und welche Website gerade Aufmerksamkeit braucht.',
    alt: 'Schild Dashboard, Alle Websites: Grundschutz aktiv, Karten für verein.example, praxis.example, shop.example und blog.example mit Anfragen pro Sekunde, gestopptem Anteil und Antwortzeit, darunter Alarme auf mehreren Websites. Testdaten.',
  },
  {
    src: '/img/dashboards/gateway-requests.webp',
    title: 'Zugriffe & Bots',
    summary: 'Menschen, Suchmaschinen und KI-Crawler trennen',
    text: 'Jede Website für sich: Länder, Anteil von Menschen, Bots, Suchmaschinen und KI-Crawlern, Top-Seiten und Herkunft.',
    benefit: 'Alle Zahlen entstehen und bleiben lokal auf deinem Server – ohne externen Tracker.',
    alt: 'Schild Dashboard, Zugriffe für verein.example: Weltkarte und Liste der Länder, Anteil von Menschen, Bots, Suchmaschinen und KI-Crawlern, Top-Seiten, Herkunft und neue oder wiederkehrende Besucher. Testdaten.',
  },
  {
    src: '/img/dashboards/gateway-attacks.webp',
    title: 'Ereignisse & Vorfälle',
    summary: 'Jede Sperre mit Vorfallnummer nachvollziehen',
    text: 'Alle gestoppten und erkannten Anfragen der letzten Tage mit Vorfallnummer, Angriffsart, Pfad, Land und Netzart.',
    benefit: 'Bei einem Fehlalarm findest du den Vorfall sofort und legst mit einem Klick eine eng begrenzte Ausnahme an.',
    alt: 'Schild Dashboard, Ereignisse für verein.example: Vorfälle der letzten 7 Tage mit Vorfallnummer, versuchtem Angriff, Pfad, Land und Netzart, teils mit dem Hinweis, dass mehrere Websites betroffen sind. Testdaten.',
  },
  {
    src: '/img/dashboards/gateway-server.webp',
    title: 'Server-Zustand',
    summary: 'Last, Ressourcen und konkrete App-Hinweise',
    text: 'CPU, Arbeitsspeicher, Festplatte, Netzwerk und Antwortzeiten deiner Anwendung direkt neben dem Firewall-Status.',
    benefit: 'Du erkennst sofort, ob ein Problem von einem Angriff oder von einer trägen Anwendung kommt.',
    alt: 'Schild Dashboard, Server web-1: Grundschutz aktiv, Kacheln für Anfragen pro Sekunde, Gestoppt, Antwortzeit, CPU, Arbeitsspeicher, Festplatte und Netzwerk, darunter zwei Hinweise zu Fehlern und langsamen Antworten der App. Testdaten.',
  },
]

// Compact facts for the install section; full details live in /doku/gateway/00-installieren and 02-betrieb.
const installRules = [
  'Docker-Image oder statisches Linux-Binary (amd64 und arm64) – kein Abo, keine Cloud.',
  'Prüfbare Releases: Signatur mit cosign, SHA-256-Prüfsummen, Stückliste (SBOM) und Herkunftsnachweis.',
  'Ab Werk sperrt das OWASP Core Rule Set bekannte Angriffe; vier der fünf Szenarien sperren nach 14 Tagen Lernzeit.',
  'Keine automatischen Zwangs-Updates, und in einer Minute wieder vollständig rückbaubar.',
]

// How the gateway itself is secured. Only facts that can be checked in the repository or on a running gateway
// (gateway/README.md, gateway/Dockerfile, the release workflow).
const selfSecurity = [
  { title: 'Dashboard nur auf dem Server selbst', text: 'Es hört auf 127.0.0.1. Von außen kommst du nur per SSH-Tunnel oder VPN hinein.' },
  { title: 'Kein Standardpasswort', text: 'Das erste Passwort setzt du mit einem Einmal-Code aus dem Log. Nach fünf falschen Versuchen ist eine Viertelstunde Pause.' },
  { title: 'Ohne Root im Container', text: 'Im Image läuft Schild als Benutzer ohne Root-Rechte. Die mitgelieferte Compose-Datei macht das Dateisystem schreibgeschützt und nimmt dem Container alle Sonderrechte.' },
  { title: 'Nie ungeprüft durchlassen', text: 'Dauert eine Prüfung zu lange oder bricht sie ab, antwortet Schild mit 503 statt die Anfrage ungeprüft durchzulassen.' },
  { title: 'Prüfbare Releases', text: 'Du kannst nachprüfen, dass Image und Archive unverändert aus dem öffentlichen Quellcode gebaut wurden (Signatur mit cosign, Prüfsummen, Herkunftsnachweis). Eine Stückliste (SBOM) nennt alle enthaltenen Bibliotheken.' },
  { title: 'Offener Quellcode', text: 'Der gesamte Code liegt offen auf GitHub. Findest du eine Sicherheitslücke, meldest du sie dort vertraulich statt als öffentliches Issue.' },
]

// What holds without any configuration lives in docs/gateway/02-betrieb.md.

// FAQ: questions the sections above do not answer. The second group is for operators and admins; every answer holds
// for the gateway as built (docs/gateway).
const faq: FaqGroup[] = [
  {
    group: 'Allgemein',
    items: [
      { q: 'Was ist der Deutschland-Schild?', a: 'Der Name des Projekts. Was du installierst, heißt Schild Gateway. Langfristig soll daraus ein Netz unabhängiger Labs wachsen, die neue Angriffsversuche gemeinsam prüfen und Regeln an alle verteilen.' },
      { q: 'Was kostet das?', a: 'Nichts. Der Grundschutz soll dauerhaft kostenlos bleiben, gemeinnützig finanziert: kein Abo, kein Geschäft mit Daten.' },
      { q: 'Was verlässt meinen Server, und sieht jemand meine Besucher?', a: 'Nichts aus deinem Traffic. Schild holt nur öffentliche Regeln und Listen ab. Erst wenn du später Labs anbindest (geplant), gehen kurze Hinweise raus: welche Regel angeschlagen hat und welche Art Angriff, dazu grob Land, Netzbetreiber und Netzart des Absenders. Keine Inhalte, keine Formulardaten und keine IP-Adressen, auch nicht gehasht oder als Pseudonym.' },
      { q: 'Kann Schild meine Website lahmlegen?', a: 'Jede Sperre hat eine Vorfallnummer und lässt sich mit einem Klick zurücknehmen. Willst du erst zusehen, stellst du die Regeln auf „erkennen“, dann sperren sie nichts. Nur Anfragen, die sich gar nicht prüfen lassen, etwa ein viel zu großer Upload, lehnt Schild weiter ab. Bei einem Ausfall kommt es darauf an, wie Schild eingebaut ist. Hinter nginx kann der Webserver davor direkt an deine Anwendung weiterreichen, wenn Schild nicht antwortet; die Vorlage dafür steht in der Doku. Nutzt du Schild als Caddy-Distribution, ist es selbst der Webserver: Läuft es nicht, ist deine Website nicht erreichbar, bis du deinen bisherigen Caddy wieder startest. Das dauert eine Minute, und Caddys Zertifikate liegen unverändert bereit.' },
      { q: 'Meine Website ist klein. Bringt das überhaupt etwas?', a: 'Ja. Automatisierte Angriffe suchen nach verwundbarer Software, nicht nach bekannten Namen. Eine kleine Website mit dem betroffenen Plugin wird genauso getroffen wie eine große.' },
      { q: 'Wie weit ist Schild?', a: `Das Schild Gateway ist als Alpha veröffentlicht (Version ${RELEASE_VERSION}). Es hat die Prüfung im Testlabor bestanden und läuft bei uns im Live-Betrieb. Alpha heißt: Befehle, Konfiguration und Dashboard können sich noch ändern, und Fehler sind möglich. Labs und Relays sind geplant und noch nicht gebaut.` },
      { q: 'Ist das der IT-Grundschutz des BSI?', a: 'Nein. „Grundschutz“ meint hier einen Basisschutz für Websites. Schild ist kein Standard des BSI, keine Zertifizierung und keine Partnerschaft.' },
    ],
  },
  {
    group: 'Im Alltag',
    items: [
      { q: 'Kann ich meine eigenen IPs freischalten, und was, wenn ich mich aussperre?', a: 'Ja. Im Dashboard unter „Eigene IPs“ oder per SSH mit schild allow --mine schaltest du Adressen, Bereiche oder DynDNS-Namen frei, dauerhaft oder befristet. Standard ist „nie sperren“: Schild prüft und protokolliert weiter, sperrt aber nicht. Freischaltungen gelten nur auf deinem Server.' },
      { q: 'Was mache ich, wenn Schild echte Eingaben sperrt?', a: 'Mit der Vorfallnummer von der Sperrseite findest du den Vorfall im Dashboard und lässt die Person mit „Durchlassen“ wieder durch. Damit es nicht wieder passiert, legst du im Ereignis mit „Ausnahme anlegen“ eine eng begrenzte Ausnahme an, etwa nur für eine Regel und ein Feld. Das kann auch dein KI-Agent über die Agent-API.' },
      { q: 'Kann ich Bereiche mit Passwort schützen?', a: 'Ja. Du schließt eine ganze Website oder Pfade wie /staging/* mit einem gemeinsamen Passwort, nur für eigene Adressen oder mit beidem; dann muss beides zutreffen. Gespeichert wird nur ein Hash. Der Schutz bleibt an, bis du ihn aufhebst.' },
      { q: 'Kann ich KI-Crawler sperren?', a: 'Ja, pro Website. Crawler sind nach Zweck gruppiert, etwa KI-Training, KI-Suche und Suchmaschinen; KI-Training blockst du mit einem Klick. Gibt sich jemand als Googlebot aus, kommt aber nicht aus Googles Adressbereichen, kann Schild ihn als Fälschung blocken. Crawler, die sich nicht zu erkennen geben, erfasst das nicht.' },
      { q: 'Wie ist das Dashboard abgesichert?', a: 'Ab Werk lauscht es nur auf dem Server selbst. Du kommst per SSH-Tunnel oder VPN hinein. Das erste Passwort setzt du mit einem Einmal-Code aus dem Log, und nach fünf falschen Versuchen ist eine Viertelstunde Pause.' },
      { q: 'Gibt es Pakete für apt oder dnf?', a: 'Noch nicht, sie sind geplant. Heute gibt es Schild als Docker-Image und als statisches Binary für Linux amd64 und arm64, mit systemd-Unit im Archiv. Neue Versionen installierst du selbst. Schild aktualisiert sich nie von allein.' },
      { q: 'Wie komme ich auf eine neue Version?', a: 'Du lädst das neue Image oder Binary und startest Schild neu. Die Datenbank passt Schild beim Start selbst an und legt vorher eine Sicherungskopie an. Was sich geändert hat, steht bei jedem Release auf GitHub.' },
      { q: 'Was ist, wenn ich einen Fehler finde?', a: 'Dann hilft uns ein Issue auf GitHub, mit der Ausgabe von schild version und den Schritten, die zum Fehler führen. Eine Sicherheitslücke meldest du bitte nicht öffentlich, sondern auf dem Weg aus SECURITY.md.' },
    ],
  },
]

const faqMore = [
  { to: '/doku/gateway/01-funktionen', label: 'Alle Funktionen in der Dokumentation' },
  { to: '/netz#faq', label: 'Fragen zum Schild-Netz' },
]
</script>

<template>
  <div class="bg-white">
    <!-- HERO: one sentence, one action, the product. -->
    <section class="overflow-hidden border-b border-line bg-mist" aria-labelledby="hero-title">
      <div class="mx-auto max-w-6xl px-5 pt-14 sm:px-8 md:pt-20">
        <div class="mx-auto max-w-4xl text-center">
          <!-- Small pointer to the agent block; the headline itself stays short. -->
          <a href="#ki-agent" class="mb-6 inline-flex items-center gap-2 rounded-full bg-white py-1 pr-3 pl-1 text-sm font-semibold text-ink shadow-sm ring-1 ring-mist-line transition hover:ring-ink/30">
            <span class="rounded-full bg-signal px-2 py-0.5 text-xs text-on-signal">Neu</span>
            Regeln per KI-Agent anpassen
            <span aria-hidden="true">→</span>
          </a>
          <h1 id="hero-title" class="text-4xl leading-[1.05] font-bold tracking-tight text-balance sm:text-6xl">
            Die kostenlose Firewall für deine Website.
          </h1>
          <p class="mx-auto mt-5 max-w-2xl text-lg leading-relaxed text-pretty text-slate sm:text-xl">
            Open Source auf deinem eigenen Server: Schild prüft jede Anfrage vor deiner Anwendung und zeigt dir im Dashboard, was auf deinen Websites los ist. Deine Daten bleiben bei dir.
          </p>
          <div class="mt-7">
            <NuxtLink to="#installieren" class="btn-primary">Schild Gateway installieren</NuxtLink>
          </div>
        </div>
        <!-- Real dashboard with its mock data (`pnpm dev:mock`), page "Zugriffe" of verein.example, sidebar as in the gateway
             without labs; the alt text says it is test data. The negative
             margin cuts the cards open, so the shot runs on past the edge of the section. -->
        <figure class="mt-10 overflow-hidden rounded-t-xl shadow-xl ring-1 ring-line md:mt-12">
          <picture>
            <source media="(max-width: 639px)" srcset="/img/dashboards/gateway-hero-mobile.webp">
            <img
              src="/img/dashboards/gateway-hero.webp"
              srcset="/img/dashboards/gateway-hero-1100.webp 1100w, /img/dashboards/gateway-hero-1600.webp 1600w, /img/dashboards/gateway-hero-2200.webp 2200w, /img/dashboards/gateway-hero.webp 2880w"
              sizes="(min-width: 1216px) 1152px, calc(100vw - 4rem)"
              alt="Schild Dashboard, Zugriffe für verein.example: Grundschutz aktiv, Kennzahlen zu Besuchern, Seitenaufrufen, Anfragen, gestoppten Anfragen, Antwortzeit und Fehlerquote, darunter der Verlauf über 24 Stunden mit einer Angriffswelle und die letzten Alarme. Testdaten."
              width="2880" height="1424" fetchpriority="high" decoding="async" class="-mb-[5%] block w-full sm:-mb-[1.5%]"
            >
          </picture>
        </figure>
      </div>
    </section>

    <section id="warum-jetzt" class="border-b border-line" aria-labelledby="warum-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="warum-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Warum jetzt?</h2>
        <ul class="mt-8 grid gap-x-10 gap-y-6 md:grid-cols-3">
          <li v-for="w in whyNow" :key="w.title" class="border-t border-line pt-4">
            <h3 class="font-semibold">{{ w.title }}</h3>
            <p class="mt-1 text-sm leading-relaxed text-pretty text-slate">
              {{ w.text }}
              <a v-if="w.src" :href="w.src" target="_blank" rel="noopener" class="underline decoration-line underline-offset-2 hover:text-ink">Quelle</a>
              <template v-if="w.src2">· <a :href="w.src2" target="_blank" rel="noopener" class="underline decoration-line underline-offset-2 hover:text-ink">Quelle</a></template>
            </p>
          </li>
        </ul>
      </div>
    </section>

    <section id="so-funktioniert-es" class="scroll-mt-16 border-b border-line bg-mist" aria-labelledby="how-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">So funktioniert es</p>
        <h2 id="how-title" class="h2 mt-3">Schild steht zwischen dem Internet und deiner Website.</h2>
        <!-- Same build for all three boxes (icon, title, text), so they line up; white on mist, the gateway carries the ink ring. -->
        <ol class="mt-10 grid gap-3 text-center md:grid-cols-[1fr_auto_1fr_auto_1fr]" aria-label="Weg einer Anfrage">
          <li class="flex flex-col items-center rounded-xl bg-white p-6 shadow-sm ring-1 ring-mist-line">
            <svg class="mb-3 size-10 text-slate" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3Z" /></svg>
            <p class="font-semibold">Internet</p>
            <p class="mt-1 text-sm text-balance text-slate">Besucher, Bots, Angriffsversuche</p>
          </li>
          <li class="flex items-center justify-center text-xl text-slate max-md:rotate-90" aria-hidden="true">→</li>
          <li class="flex flex-col items-center rounded-xl bg-white p-6 shadow-lg ring-2 ring-ink">
            <BrandMark class="mb-3 h-10 w-auto" />
            <p class="font-semibold">Schild Gateway</p>
            <p class="mt-1 text-sm text-balance text-slate">prüft jede Anfrage und entscheidet auf deinem Server</p>
          </li>
          <li class="flex items-center justify-center text-xl text-slate max-md:rotate-90" aria-hidden="true">→</li>
          <li class="flex flex-col items-center rounded-xl bg-white p-6 shadow-sm ring-1 ring-mist-line">
            <svg class="mb-3 size-10 text-slate" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 8.5h18M6 6.3h.01M8.5 6.3h.01M7 12.5h10M7 16h6" /></svg>
            <p class="font-semibold">Deine Website</p>
            <p class="mt-1 text-sm text-balance text-slate">bekommt nur, was durchgelassen wird</p>
          </li>
        </ol>
        <ol class="mt-14 grid gap-8 md:grid-cols-3">
          <li v-for="(s, i) in steps" :key="s.title">
            <span class="step-nr">{{ i + 1 }}</span>
            <h3 class="mt-3 font-semibold">{{ s.title }}</h3>
            <p class="mt-1 text-sm leading-relaxed text-slate">{{ s.text }}</p>
          </li>
        </ol>
        <div class="mt-10">
          <NuxtLink to="#installieren" class="btn-primary">Schild Gateway installieren</NuxtLink>
        </div>
      </div>
    </section>

    <section id="dashboard" class="scroll-mt-16 border-b border-line" aria-labelledby="dashboard-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Einblick ins Dashboard</p>
        <h2 id="dashboard-title" class="h2 mt-3">Alles im Blick – direkt auf deinem Server.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Besucher, Bots, Angriffsversuche, Vorfälle und Server-Zustand an einem Ort. Das Dashboard läuft lokal auf deinem Server, ohne externe Dienste.
        </p>
        <DashboardShots class="mt-10" label="Ansichten des Schild Dashboards" :shots="gatewayShots" caption="Echte Screenshots des Gateway-Dashboards vom 19.11.2026, mit Testdaten (nur IP-Adressen aus Dokumentationsbereichen)." />
      </div>
    </section>

    <section id="funktionen" class="border-b border-line bg-mist" aria-labelledby="features-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="features-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Was das Gateway mitbringt</h2>
        <!-- Agent API (MVP-28, D54/D55): built, off by default, loopback listener only. -->
        <div id="ki-agent" class="mt-8 grid scroll-mt-20 gap-6 rounded-xl border border-mist-line bg-white p-6 shadow-xs sm:p-8 lg:grid-cols-[1fr_1.4fr] lg:gap-10">
          <div>
            <p class="kicker">KI-native</p>
            <h3 class="mt-2 text-xl font-bold tracking-tight sm:text-2xl">Dein Agent passt die Firewall an deine Anwendung an.</h3>
          </div>
          <div class="space-y-3 leading-relaxed text-slate">
            <p>Über die interne Agent-API prüft dein Coding-Agent Beispielanfragen gegen alle Regeln und legt bei Bedarf eng begrenzte Ausnahmen für einzelne Felder an.</p>
            <p>Die API ist ab Werk aus, hört nur lokal auf dem Server und protokolliert jede Änderung nachvollziehbar.</p>
          </div>
        </div>
        <ul class="mt-10 grid gap-x-10 gap-y-6 md:grid-cols-2 lg:grid-cols-3">
          <li v-for="f in features" :key="f.title" class="border-t border-line pt-4">
            <h3 class="font-semibold">{{ f.title }}</h3>
            <p class="mt-1 text-sm leading-relaxed text-slate">{{ f.text }}</p>
          </li>
        </ul>
        <p class="mt-8 text-sm text-slate">
          Alle Funktionen im Detail:
          <NuxtLink to="/doku/gateway/01-funktionen" class="font-semibold text-link hover:underline">Dokumentation zum Gateway <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="installieren" class="scroll-mt-16 border-b border-line" aria-labelledby="installieren-title">
      <span id="betreiber" /><span id="nach-der-installation" />
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <div class="max-w-3xl">
          <p class="kicker">Installieren</p>
          <h2 id="installieren-title" class="h2 mt-3">In wenigen Minuten auf deinem Server.</h2>
          <p class="mt-4 leading-relaxed text-slate">
            Such dir den Weg aus, der zu deinem Setup passt. Alle Details, Prüf-Befehle und der Weg zurück stehen übersichtlich in der Dokumentation.
          </p>
          <p class="mt-2 text-sm text-slate">
            Aktuelle Alpha: Version {{ RELEASE_VERSION }} ·
            <a :href="RELEASES_URL" target="_blank" rel="noopener" class="font-semibold text-link hover:underline">Releases</a> ·
            <a :href="REPO_URL" target="_blank" rel="noopener" class="font-semibold text-link hover:underline">Quellcode auf GitHub</a>
          </p>
        </div>

        <InstallPicker class="mt-8" />

        <ul class="mt-8 grid gap-x-8 gap-y-2.5 sm:grid-cols-2">
          <li v-for="r in installRules" :key="r" class="flex gap-3 text-sm leading-relaxed text-slate"><span class="text-signal-deep" aria-hidden="true">✓</span>{{ r }}</li>
        </ul>

        <div id="sicherheit" class="mt-14 scroll-mt-20 border-t border-line pt-12">
          <h3 class="text-xl font-bold tracking-tight">Wie das Gateway selbst abgesichert ist</h3>
          <p class="mt-2 max-w-2xl text-sm leading-relaxed text-slate">
            Alles hier kannst du im offenen Code und am laufenden Gateway nachprüfen.
          </p>
          <ul class="mt-6 grid gap-x-10 gap-y-6 md:grid-cols-2 lg:grid-cols-3">
            <li v-for="f in selfSecurity" :key="f.title" class="border-t border-line pt-4">
              <h4 class="font-semibold">{{ f.title }}</h4>
              <p class="mt-1 text-sm leading-relaxed text-slate">{{ f.text }}</p>
            </li>
          </ul>
          <p class="mt-6 text-sm text-slate">
            Fehler gefunden?
            <a :href="ISSUES_URL" target="_blank" rel="noopener" class="font-semibold text-link hover:underline">Issue auf GitHub anlegen <span aria-hidden="true">→</span></a>
          </p>
        </div>
      </div>
    </section>

    <section id="vergleich" class="border-b border-line bg-mist" aria-labelledby="cmp-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <span id="fail2ban" /><span id="abgrenzung" /><span id="cloudflare" /><span id="crowdsec" />
        <h2 id="cmp-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Warum Schild, und warum nicht fail2ban, CrowdSec oder Cloudflare?</h2>
        <div class="mt-3 grid gap-10 lg:grid-cols-[1.2fr_0.8fr]">
          <p class="max-w-2xl leading-relaxed text-slate">
            fail2ban wertet Logs aus, also erst nach der Anfrage. CrowdSec meldet ab Werk angreifende IP-Adressen an den Dienst der Firma, bei Cloudflare läuft dein Traffic über den Anbieter und wird dort entschlüsselt.
            Schild ist Open Source und kostenlos, prüft jede Anfrage auf deinem Server, und deine Daten bleiben dort.
          </p>
          <dl class="grid gap-x-8 gap-y-6 sm:grid-cols-2">
            <div v-for="f in figures" :key="f.figure" class="border-t border-line pt-4">
              <dt class="text-3xl font-bold tracking-tight">{{ f.figure }}</dt>
              <dd class="mt-1 text-sm leading-relaxed text-slate">
                {{ f.text }} (<a :href="f.src" target="_blank" rel="noopener" class="underline decoration-line underline-offset-2 hover:text-ink">Quelle</a>)
              </dd>
            </div>
          </dl>
        </div>
        <div class="mt-8 overflow-x-auto">
          <table class="w-full min-w-[56rem] text-left text-sm">
            <thead>
              <tr class="text-slate">
                <th class="py-2 pr-4 font-semibold" />
                <th class="py-2 pr-4 font-semibold">fail2ban</th>
                <th class="py-2 pr-4 font-semibold">CrowdSec</th>
                <th class="py-2 pr-4 font-semibold">Cloudflare WAF</th>
                <th class="py-2 font-semibold text-signal-deep">Schild</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in compare" :key="row[0]" class="border-t border-line align-top">
                <th class="py-3 pr-4 font-semibold">{{ row[0] }}</th>
                <td class="py-3 pr-4 text-slate">{{ row[1] }}</td>
                <td class="py-3 pr-4 text-slate">{{ row[2] }}</td>
                <td class="py-3 pr-4 text-slate">{{ row[3] }}</td>
                <td class="py-3 text-ink">{{ row[4] }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <details class="mt-6 text-xs text-slate">
          <summary class="cursor-pointer font-semibold">Quellen</summary>
          <ul class="mt-2 space-y-1">
            <li v-for="[label, url] in compareSources" :key="url"><a :href="url" target="_blank" rel="noopener" class="underline decoration-line underline-offset-2 hover:text-ink">{{ label }}</a></li>
          </ul>
        </details>
        <p class="mt-6 text-sm text-slate">
          Warum wir es so bauen, mit Quellen aus der Forschung:
          <NuxtLink to="/doku/konzept/16-stand-der-technik" class="font-semibold text-link hover:underline">Stand der Technik <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="schild-netz" class="border-b border-line" aria-labelledby="teaser-title">
      <div class="mx-auto max-w-6xl px-5 py-14 sm:px-8">
        <p class="kicker">Geplant, optional</p>
        <h2 id="teaser-title" class="mt-2 text-xl font-bold tracking-tight">Das Schild-Netz</h2>
        <p class="mt-2 max-w-2xl leading-relaxed text-slate">
          Das Gateway läuft allein. Später sollst du es an unabhängige Labs anbinden können, die neue Angriffsversuche gemeinsam prüfen und Regeln verteilen.
          Dieses Netz ist die Idee hinter dem Namen Deutschland-Schild.
        </p>
        <NuxtLink to="/netz" class="mt-4 inline-block font-semibold text-link hover:underline">Wie das Netz funktioniert →</NuxtLink>
      </div>
    </section>

    <!-- FAQ: general questions, then everyday questions of operators and admins; the details live in the docs -->
    <section id="faq" class="border-b border-line bg-mist" aria-labelledby="faq-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="faq-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Häufige Fragen</h2>
        <FaqList class="mt-8" :groups="faq" />
        <ul class="mt-8 flex flex-col gap-x-8 gap-y-2 text-sm sm:flex-row sm:flex-wrap">
          <li v-for="l in faqMore" :key="l.to"><NuxtLink :to="l.to" class="font-semibold text-link hover:underline">{{ l.label }} →</NuxtLink></li>
        </ul>
      </div>
    </section>

    <MitmachenSection />
  </div>
</template>