<script setup lang="ts">
import type { DashboardShot } from '~/components/DashboardShots.vue'
import { SHOTS_DATE } from '~/utils/shots'

// Features shown as worked examples: what a visitor sees, what the operator sees, with real screenshots, each
// labelled by its topic.
// This page shows; how to set things up lives in docs/gateway/01-funktionen.md, and every example links there.
// Every claim has to hold for the gateway as built, without labs.
// Screenshots: retaken with `npm run shots` (site/scripts/shots.mjs), dashboard in mock mode at 1440×900; block page and login
// page are the HTML the gateway serves (gateway/internal/blockpage, gateway/internal/accesslock). IP addresses are
// blurred at capture time: they are documentation addresses, but a reader cannot tell that from the picture.
// The basic protection and the login protection show the switches as they come (docs: "Ab Werk"); the mock data
// starts with some of them changed, so site/scripts/shots.mjs puts them back first (factory()). The crawler example
// shows a website with AI training blocked.
// The cluster example shows three gateways: the page and a server's details with everything in order (mock scenario
// `group-ok`), the hints with one gateway not reached (`group`). The cluster is experimental and
// in no release yet (docs/gateway/03-cluster.md): the section says so, and it claims only what that guide states.

useHead({ title: 'Funktionen – Deutschland-Schild' })
useSeoMeta({ description: 'Was das Schild Gateway abwehrt, an Beispielen mit Screenshots: Grundschutz ab Werk, SQL-Injection, Login-Schutz, KI-Crawler, sensible Bereiche und Cluster.' })

const DOCS = '/doku/gateway/01-funktionen'
const CLUSTER_DOCS = '/doku/gateway/03-cluster'
// The cluster screenshots were taken on their own (`npm run shots -- funktionen-cluster`), so they carry their own
// date until the next full run of the script, which dates every screenshot alike (SHOTS_DATE).
const CLUSTER_SHOTS_DATE = '22.11.2026'
// Same for the basic protection, the login protection and the crawlers (`npm run shots -- funktionen-grundschutz`,
// `funktionen-login`, `funktionen-crawler`).
const BASICS_SHOTS_DATE = '23.11.2026'

const basicsShots: DashboardShot[] = [
  {
    src: '/img/dashboards/funktionen-grundschutz-regeln.webp',
    title: '1. Regeln',
    summary: 'Drei Quellen, je ein Schalter',
    text: 'Unter „Regeln“ steht jede Quelle mit ihrem Schalter: Aus, Erkennen oder Sperren. Ab Werk sperren das OWASP Core Rule Set und deine eigenen Regeln, der CrowdSec Hub erkennt nur.',
    benefit: 'Ein Schalter wirkt sofort, ohne Neustart. Willst du erst zusehen, stellst du eine Quelle auf „Erkennen“.',
    alt: 'Schild Dashboard, Regeln: Karten für OWASP CRS (Sperrt), CrowdSec Hub (Erkennt nur) und Eigene Regeln und Ausnahmen (Sperrt), jede mit der Zahl ihrer Regeln, darunter Szenarien und Limits mit 4 von 5 Szenarien, die sperren. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-grundschutz-crs.webp',
    title: '2. OWASP Core Rule Set',
    summary: 'Punkte bis zur Sperre',
    text: 'Das Core Rule Set erkennt typische Angriffsversuche wie SQL-Injection, Cross-Site-Scripting oder Zugriffe auf Dateien außerhalb der Website. Jeder Treffer zählt Punkte. Ab Werk sperrt Schild ab 5 Punkten, bei Strenge 1 von 4.',
    benefit: 'Strenge und Schwelle stellst du hier ein. Jede Regel lässt sich einzeln abschalten, die Liste zeigt ihre Treffer der letzten 24 Stunden.',
    alt: 'Schild Dashboard, OWASP CRS: Schalter auf Sperren, Strenge Stufe 1 von 4, sperrt ab 5 Punkten, Version 4.30.0, Knopf Strenge und Schwelle anpassen, darunter die Liste der Regeln mit Status Aktiv, Wirkung Sperrt und den Treffern der letzten 24 Stunden. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-grundschutz-crowdsec.webp',
    title: '3. CrowdSec Hub',
    summary: 'Patches gegen bekannte Lücken',
    text: 'Rund 200 Regeln gegen bekannte Lücken in verbreiteter Software, jede nach ihrer CVE benannt. Schild holt neue Regeln jede Stunde. Ein CrowdSec-Konto brauchst du dafür nicht, und Schild schickt nichts an CrowdSec.',
    benefit: 'Neue Regeln erkennen zuerst 24 Stunden lang nur. Steht der Hub auf „Sperren“, sperren sie danach von selbst.',
    alt: 'Schild Dashboard, CrowdSec Hub: Schalter auf Erkennen, auf dem neuesten Stand, Knöpfe Jetzt prüfen und Auf den Stand des Images zurücksetzen, darunter Regeln, die nach ihrer CVE benannt sind, zwei davon mit dem Status Wartet noch. Testdaten.',
  },
]

const loginShots: DashboardShot[] = [
  {
    src: '/img/dashboards/funktionen-login-szenarien.webp',
    title: '1. Szenarien',
    summary: 'Muster über mehrere Anfragen',
    text: 'Passwort-Raten schlägt ab Werk bei 5 Fehlversuchen in einer Minute an, das Ausprobieren von Zugangsdaten bei 10 verschiedenen Benutzernamen in 10 Minuten. Vier von fünf Szenarien stehen ab Werk auf „Sperren“.',
    benefit: 'Jede Schwelle passt du mit „Schwelle anpassen“ an. Bist du unsicher, stellst du ein Szenario erst auf „Beobachten“ und siehst, wen es gesperrt hätte.',
    alt: 'Schild Dashboard, Szenarien und Limits, Reiter Szenarien: Alle Schalter stehen auf der Empfehlung. Passwort-Raten, Ausprobieren von Zugangsdaten und Suche nach Schwachstellen stehen auf Sperren, jeweils mit ihrer Schwelle und dem Knopf Schwelle anpassen. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-login-limits.webp',
    title: '2. Limits',
    summary: 'Grenzen pro Pfad',
    text: 'Ein Limit begrenzt, wie viele Anfragen eine Adresse an einen Pfad schicken darf, etwa 10 Anmeldungen pro Minute an wp-login.php. Limits wirken sofort, ohne Lernzeit.',
    benefit: 'Eigene Limits legst du hier an. Ein Probelauf über die letzten 24 Stunden zeigt vorher, wen sie getroffen hätten.',
    alt: 'Schild Dashboard, Szenarien und Limits, Reiter Limits: WordPress-Anmeldung und WordPress XML-RPC mit 10 pro Minute auf Begrenzen (empfohlen), dazu Limits für die Suche und ein Kontaktformular, jeweils mit den Anfragen der letzten 24 Stunden. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-login-sperren.webp',
    title: '3. Sperren',
    summary: 'Wer gerade gesperrt ist',
    text: 'Unter „Sperren“ steht jede gesperrte Adresse mit Grund und Dauer. Eine Sperre läuft von selbst ab, beim ersten Mal nach 15 Minuten, bei Wiederholung später.',
    benefit: 'Gesperrte sehen eine ruhige Seite mit Vorfallnummer. Trifft es jemanden zu Unrecht, hebst du die Sperre hier mit einem Klick auf.',
    alt: 'Schild Dashboard, Sperren: eine gesperrte Adresse aus einem Rechenzentrum, Grund Passwort-Raten, gesperrt für 15 Minuten, Knopf Sperre aufheben, darüber der Hinweis, dass gesperrte Adressen ohne angebundene Firewall die Sperrseite bekommen. Die IP-Adresse ist unkenntlich gemacht. Testdaten.',
  },
]

const crawlerShots: DashboardShot[] = [
  {
    src: '/img/dashboards/funktionen-crawler-ki.webp',
    title: '1. Vorlage',
    summary: 'KI-Training mit einem Klick blocken',
    text: '„KI-Training blocken“ blockt alle Crawler, die Inhalte für das Training von KI-Modellen sammeln. Alle anderen Kategorien bleiben erlaubt. Der Schalter darunter blockt falsche Crawler.',
    benefit: 'Deine robots.txt ändert Schild dabei nicht. Adressen aus „Eigene IPs“ blockt eine Crawler-Regel nie.',
    alt: 'Schild Dashboard, KI-Crawler für verein.example: KI-Training ist geblockt, alle anderen Kategorien sind erlaubt, Knopf KI-Training wieder erlauben, Schalter Falsche Crawler blocken eingeschaltet. Darunter die Kategorien, KI-Training auf Blocken, KI-Suche, KI-Assistent, Suchmaschine, Vorschau/Social und Feed-Reader auf Erlauben. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-crawler-liste.webp',
    title: '2. Einzelne Crawler',
    summary: 'Wer kommt und wie oft',
    text: 'Ein Klick auf eine Kategorie zeigt ihre Crawler mit den Anfragen der letzten 24 Stunden und ob sie sich an deine robots.txt halten.',
    benefit: 'Eine Regel für einen einzelnen Crawler geht der Regel seiner Kategorie vor.',
    alt: 'Schild Dashboard, KI-Crawler, Kategorie KI-Training aufgeklappt: GPTBot, Bytespider, ClaudeBot und CCBot, alle geblockt, jeweils mit Anfragen, ob sie sich an die robots.txt halten, und der Regel Wie Kategorie, Erlauben oder Blocken. Darunter die übrigen Kategorien auf Erlauben. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-crawler-pruefung.webp',
    title: '3. Prüfung im Browser',
    summary: 'Für alle, die sich nicht melden',
    text: 'Unter „Zugriffsschutz“ schaltest du eine kurze Rechenaufgabe im Browser vor, bei Auffälligkeiten oder für jeden neuen Seitenaufruf. Sie läuft nur auf deinem Server, ohne Drittanbieter und ohne Tracking. Ab Werk ist sie aus.',
    benefit: 'Für den akuten Fall gilt „Under Attack“ sofort und endet nach 1, 4, 12 oder 24 Stunden von selbst.',
    alt: 'Schild Dashboard, Zugriffsschutz für verein.example: Wartungsmodus aus, darunter die Karte Browser-Prüfung & Under Attack mit dem regulären Modus Aus, Bei Auffälligkeiten und Immer und dem Knopf Under Attack aktivieren, wahlweise nur für Admin- und Login-Seiten. Testdaten.',
  },
]

const sqliShots: DashboardShot[] = [
  {
    src: '/img/dashboards/funktionen-sqli-blockpage.webp',
    title: '1. Sperrseite',
    summary: 'Was der Absender zu sehen bekommt',
    frame: 'blog.example/produkte/',
    text: 'Schild beantwortet die Anfrage selbst mit dem Code 403 und einer Vorfallnummer. Deine Anwendung bekommt die Anfrage nicht zu sehen.',
    benefit: 'Trifft es einmal eine echte Person, nennt sie dir die Nummer, und du findest den Vorfall sofort.',
    alt: 'Sperrseite des Schild Gateway: Fehlercode 403, Anfrage angehalten, Vorfallnummer RN9T-F36Q und der Hinweis, die Nummer bei einem Irrtum an die Betreiber:innen der Website zu schicken. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-sqli-event.webp',
    title: '2. Ereignis',
    summary: 'Wer es war und was geschickt wurde',
    text: 'Im Dashboard steht dieselbe Vorfallnummer am Ereignis: Herkunft, Netzart, die Anfrage im Wortlaut und das Programm, das sie geschickt hat.',
    benefit: 'Von hier aus lässt du die Anfrage durch oder sperrst die Adresse für 7 Tage.',
    alt: 'Schild Dashboard, Ereignis mit Vorfallnummer RN9T-F36Q: gesperrte Anfrage an /produkte/ auf blog.example aus einem Rechenzentrum in Singapur, IP-Adresse unkenntlich gemacht, Anfragezeile mit SQL-Injection im Parameter id, Programm sqlmap, Knöpfe Durchlassen, Kontext und IP für 7 Tage sperren. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-sqli-why.webp',
    title: '3. Begründung',
    summary: 'Welche Regel angeschlagen hat',
    text: 'Unter „Warum“ steht die Regel aus dem OWASP Core Rule Set, das Feld, in dem sie etwas gefunden hat, und wie die Punkte zur Sperre geführt haben.',
    benefit: 'War es ein Fehlalarm, legst du gleich daneben eine Ausnahme nur für dieses Feld an.',
    alt: 'Schild Dashboard, Ereignis, Abschnitt Warum: Versuchter Datenbank-Angriff (SQL-Injection), OWASP CRS Regel 942100, gefunden im Feld id, Knopf Ausnahme anlegen, darunter die Entscheidung mit Score 85 von 100 über der Sperrschwelle von 40 und der Verlauf der Sitzung. Testdaten.',
  },
]

const adminShots: DashboardShot[] = [
  {
    src: '/img/dashboards/funktionen-admin-dialog.webp',
    title: '1. Einrichten',
    summary: 'Pfade und Zugang im Dashboard wählen',
    text: 'Unter „Zugriffsschutz“ trägst du die Pfade ein und hakst an, was gelten soll: ein gemeinsames Passwort, bestimmte Adressen, deine eigenen IPs.',
    benefit: 'Hakst du mehreres an, muss alles zutreffen. Der Rest der Website bleibt offen.',
    alt: 'Schild Dashboard, Dialog Zugriffsschutz für verein.example: Nur bestimmte Bereiche, Pfade /wp-admin/* und /wp-login.php, Zugang mit Passwort und Eigene IPs angehakt, Knopf Schutz aktivieren. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-admin-active.webp',
    title: '2. Aktiv',
    summary: 'Der Schutz gilt sofort',
    text: 'Das Dashboard zeigt, welche Pfade wie geschlossen sind. Der Schutz bleibt an, bis du ihn aufhebst.',
    benefit: 'Hast du dich ausgesperrt, hebt „schild lock“ auf dem Server den Schutz wieder auf.',
    alt: 'Schild Dashboard, Zugriffsschutz für verein.example: Zugang Passwort und Eigene IPs, gilt für /wp-admin/* und /wp-login.php, Knöpfe Ändern und Aufheben, Meldung „Zugriffsschutz für verein.example ist aktiv“. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-admin-login.webp',
    title: '3. Anmeldeseite',
    summary: 'Was vor dem Bereich steht',
    frame: 'verein.example/wp-admin/',
    text: 'Wer von einer deiner Adressen kommt, sieht diese Seite und kommt mit dem Passwort weiter. Erst danach erreicht die Anfrage die Anmeldung deiner Anwendung.',
    benefit: 'Alle anderen sehen nur „Kein Zugriff“, ohne Formular.',
    alt: 'Anmeldeseite des Schild Gateway: Anmeldung nötig, für diesen Bereich brauchst du ein Passwort, Feld Passwort und Knopf Anmelden.',
  },
]

const clusterShots: DashboardShot[] = [
  {
    src: '/img/dashboards/funktionen-cluster-seite.webp',
    title: '1. Cluster-Seite',
    summary: 'Alle Server auf einen Blick',
    text: 'Die Seite „Cluster“ zeigt jeden Server unter dem Internet: ob er Anfragen annimmt, wie viele er gerade bedient und wie ausgelastet er ist. Darüber stehen die Summen aller Server.',
    benefit: 'Oben wählst du, ob Zahlen und Diagramme alle Server zusammen zeigen oder einen einzelnen.',
    alt: 'Schild Dashboard, Seite Cluster: Abgleich aktiv, alle 3 Server haben denselben Stand. 3 von 3 Servern bereit, 124 Anfragen pro Sekunde, 2 laufende Sperren. Darunter eine Karte mit dem Internet und den drei Servern web-1, web-2 und web-3, die alle Anfragen annehmen. Oben die Auswahl „Zahlen von: Alle Server“. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-cluster-server.webp',
    title: '2. Ein Server',
    summary: 'Die Details eines Servers',
    text: 'Ein Klick auf einen Server öffnet seine Details: Auslastung, Start, letzter Kontakt, Version, Uhr und ob sein Stand mit dem dieses Servers übereinstimmt.',
    benefit: 'Weicht ein Server ab, siehst du das hier, ohne dich auf jedem einzeln anzumelden.',
    alt: 'Schild Dashboard, Details des Servers web-2: nimmt Anfragen an, 38,9 Anfragen pro Sekunde, CPU 34 %, Arbeitsspeicher 52 %, Festplatte 41 %, gestartet vor 5 Stunden, letzter Kontakt gerade eben, Uhr, Stand und Konfiguration gleich. IP-Adresse unkenntlich gemacht. Testdaten.',
  },
  {
    src: '/img/dashboards/funktionen-cluster-hinweis.webp',
    title: '3. Hinweis',
    summary: 'Wenn ein Server fehlt',
    text: 'Erreicht ein Server einen anderen nicht oder laufen die Server mit unterschiedlicher Konfiguration, steht das in jedem Dashboard unter „Einstellungen“ und als Zeile über jeder Seite.',
    benefit: 'Die übrigen Server bedienen weiter und gleichen ab, sobald der fehlende zurück ist.',
    alt: 'Schild Dashboard, Einstellungen: Grundschutz aktiv, eingeschränkt. Zwei Hinweise: Ein Server des Clusters ist von hier aus nicht erreichbar, und die Server des Clusters laufen mit unterschiedlicher Konfiguration, jeweils mit dem Knopf Ansehen. Darüber die Zeile, dass Daten von web-3 fehlen. Testdaten.',
  },
]

// The link cards at the top, in the order of the sections: what runs from the start first, the cluster last.
const examples = [
  { to: '#grundschutz', kicker: 'Regeln', title: 'Grundschutz, ohne etwas einzustellen' },
  { to: '#sql-injection', kicker: 'Angriffe', title: 'Ein SQL-Injection-Versuch wird gestoppt' },
  { to: '#login-schutz', kicker: 'Logins', title: 'Login-Schutz mit Szenarien und Limits' },
  { to: '#ki-crawler', kicker: 'Bots', title: 'Bots und KI-Crawler pro Website steuern' },
  { to: '#sensible-bereiche', kicker: 'Zugriffsschutz', title: 'Sensible Bereiche einfach zusätzlich absichern' },
  { to: '#cluster', kicker: 'Hochverfügbarkeit', title: 'Mehrere Gateways als Cluster betreiben' },
]

// Built features without a worked example yet; each links to its section in the docs.
const more = [
  { title: 'Ausnahmen bei Fehlalarm', text: 'Eng begrenzt auf einzelne Regeln und ein Feld auf einer Seite.', to: `${DOCS}#ausnahmen` },
  { title: 'Verteilte Angriffe', text: 'Wellen über viele Adressen erkennt Schild am Ziel, etwa viele Fehlversuche auf ein Konto. Ab Werk beobachtet es nur.', to: `${DOCS}#verteilte-angriffe` },
  { title: 'Eigene IPs', text: 'Dich und dein Team freischalten, dauerhaft oder befristet.', to: `${DOCS}#eigene-ips` },
  { title: 'Wartungsmodus', text: 'Alle sehen eine Wartungsseite, nur deine eigenen IPs kommen durch.', to: `${DOCS}#wartungsmodus` },
  { title: 'Server-Check', text: 'Prüft Updates, offene Ports, Firewall, SSH und Zertifikate, ohne etwas zu ändern.', to: `${DOCS}#server-check` },
  { title: 'Traffic und Server', text: 'Besucher, Seiten, Länder und Bots, dazu CPU, Speicher und Festplatten. Ohne Tracking-Skript und ohne Cookie.', to: `${DOCS}#traffic-und-server-im-blick` },
]
</script>

<template>
  <div class="bg-white">
    <section class="border-b border-line bg-mist" aria-labelledby="funktionen-title">
      <div class="mx-auto max-w-6xl px-5 py-14 sm:px-8 md:py-20">
        <p class="kicker">Funktionen</p>
        <h1 id="funktionen-title" class="mt-3 max-w-3xl text-4xl leading-[1.05] font-bold tracking-tight text-balance sm:text-5xl">
          Was Schild abwehrt und wie du es einstellen kannst
        </h1>
        <p class="mt-5 max-w-2xl text-lg leading-relaxed text-pretty text-slate">
          Sechs Beispiele, Schritt für Schritt: was ab Werk läuft, was ein Angreifer zu sehen bekommt, was du im Dashboard siehst und was du mit ein paar Klicks einstellst.
        </p>
        <ul class="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <li v-for="c in examples" :key="c.to">
            <a :href="c.to" class="block h-full rounded-xl bg-white p-5 shadow-sm ring-1 ring-mist-line transition hover:ring-ink/30">
              <span class="kicker">{{ c.kicker }}</span>
              <span class="mt-1 block font-semibold">{{ c.title }}</span>
            </a>
          </li>
        </ul>
      </div>
    </section>

    <section id="grundschutz" class="scroll-mt-16 border-b border-line" aria-labelledby="grundschutz-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Regeln</p>
        <h2 id="grundschutz-title" class="h2 mt-3">Grundschutz, ohne etwas einzustellen.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Nach der Installation prüft Schild jede Anfrage mit Regeln aus drei Quellen. Das OWASP Core Rule Set ist eingebaut und sperrt von Anfang an. Dazu kommen rund 200 virtuelle Patches aus dem CrowdSec Hub gegen bekannte Lücken in verbreiteter Software, ab Werk auf „Erkennen“, und deine eigenen Regeln, wenn du welche schreibst. Alles läuft auf deinem Server, und in der Übersicht des Dashboards steht „Grundschutz aktiv“. Stellst du das Core Rule Set auf „Erkennen“ oder „Aus“, ist der Grundschutz eingeschränkt, und das Dashboard sagt es dir.
        </p>
        <DashboardShots class="mt-10" label="Grundschutz ab Werk in drei Schritten" :shots="basicsShots" eager :caption="`Echte Screenshots vom ${BASICS_SHOTS_DATE} mit Testdaten. Im Dashboard stehen nur wenige Beispielregeln, auf einem echten Gateway sind es deutlich mehr.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="`${DOCS}#regeln`" class="font-semibold text-link hover:underline">Regeln <span aria-hidden="true">→</span></NuxtLink>
          <span class="mx-2" aria-hidden="true">·</span>
          <NuxtLink :to="`${DOCS}#owasp-core-rule-set`" class="font-semibold text-link hover:underline">OWASP Core Rule Set <span aria-hidden="true">→</span></NuxtLink>
          <span class="mx-2" aria-hidden="true">·</span>
          <NuxtLink :to="`${DOCS}#virtuelle-patches-aus-dem-crowdsec-hub`" class="font-semibold text-link hover:underline">CrowdSec Hub <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="sql-injection" class="scroll-mt-16 border-b border-line bg-mist" aria-labelledby="sqli-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Angriffe</p>
        <h2 id="sqli-title" class="h2 mt-3">Ein SQL-Injection-Versuch wird gestoppt.</h2>
        <div class="mt-4 grid gap-6 lg:grid-cols-[1.1fr_0.9fr] lg:gap-10">
          <p class="leading-relaxed text-slate">
            Ein Programm probiert automatisch aus, ob sich über die Adresszeile Befehle an deine Datenbank schicken lassen. Solche Anfragen kommen ungefragt, auch bei kleinen Websites. Das OWASP Core Rule Set im Gateway erkennt das Muster, und Schild stoppt die Anfrage, bevor sie deine Anwendung erreicht. Einstellen musst du dafür nichts.
          </p>
          <div>
            <p class="text-sm font-semibold">Die Anfrage</p>
            <pre class="codeblock mt-2 overflow-x-auto px-4 py-3 font-mono text-sm text-ink"><code>GET /produkte/?id=1' OR 1=1--</code></pre>
            <p class="mt-2 text-sm leading-relaxed text-slate">
              Geschickt vom Werkzeug sqlmap aus einem Rechenzentrum. Der Teil nach <span class="code">id=</span> soll die Abfrage deiner Datenbank verändern.
            </p>
          </div>
        </div>
        <DashboardShots class="mt-10" label="Ein gestoppter SQL-Injection-Versuch in drei Schritten" :shots="sqliShots" :caption="`Echte Screenshots vom ${SHOTS_DATE} mit Testdaten, IP-Adresse unkenntlich gemacht. Die Sperrseite ist die Seite, die das Gateway ausliefert.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="`${DOCS}#regeln`" class="font-semibold text-link hover:underline">Regeln <span aria-hidden="true">→</span></NuxtLink>
          <span class="mx-2" aria-hidden="true">·</span>
          <NuxtLink :to="`${DOCS}#sperrseite-und-warteseite`" class="font-semibold text-link hover:underline">Sperrseite <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="login-schutz" class="scroll-mt-16 border-b border-line" aria-labelledby="login-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Logins</p>
        <h2 id="login-title" class="h2 mt-3">Login-Schutz mit Szenarien und Limits.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Wer Passwörter durchprobiert, schickt viele Anfragen, die einzeln harmlos aussehen. Schild beobachtet deshalb, wie sich ein Absender über mehrere Anfragen verhält; Passwörter und Formularinhalte liest es dabei nie. Limits für die üblichen Login-Pfade von WordPress, Joomla, Drupal, Nextcloud, TYPO3 und Laravel gelten ab dem Start. Die Szenarien sperren nach einer Lernzeit von 14 Tagen, bis dahin zeigt das Dashboard, wen sie gesperrt hätten. Adressen aus Mobilfunk, Carrier-NAT und Tor sperrt Schild nie, weil sich dort viele Menschen eine Adresse teilen.
        </p>
        <DashboardShots class="mt-10" label="Login-Schutz mit Szenarien und Limits in drei Schritten" :shots="loginShots" :caption="`Echte Screenshots vom ${BASICS_SHOTS_DATE} mit Testdaten, IP-Adresse unkenntlich gemacht. Die Schalter stehen wie ab Werk.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="`${DOCS}#szenarien-und-limits`" class="font-semibold text-link hover:underline">Szenarien und Limits <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="ki-crawler" class="scroll-mt-16 border-b border-line bg-mist" aria-labelledby="crawler-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Bots</p>
        <h2 id="crawler-title" class="h2 mt-3">Bots und KI-Crawler pro Website steuern.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Neben Menschen rufen Suchmaschinen, Vorschau-Dienste und die Crawler von KI-Firmen deine Seiten ab. Für jede Website legst du fest, wer davon durchkommt: nach Zweck, etwa KI-Training, KI-Suche oder Suchmaschine, oder für jeden Crawler einzeln. Gibt sich jemand als Googlebot oder GPTBot aus, kommt aber nicht aus den Adressbereichen, die der Betreiber veröffentlicht, kann Schild ihn als Fälschung blocken. Crawler, die sich nicht mit Namen melden, erfasst diese Einstellung nicht. Halten sie sich nicht an deine Vorgaben, schaltest du eine kurze Prüfung im Browser vor.
        </p>
        <DashboardShots class="mt-10" label="Bots und KI-Crawler steuern in drei Schritten" :shots="crawlerShots" :caption="`Echte Screenshots vom ${BASICS_SHOTS_DATE} mit Testdaten. Im Beispiel ist KI-Training für verein.example geblockt.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="`${DOCS}#bots-und-ki-crawler`" class="font-semibold text-link hover:underline">Bots und KI-Crawler <span aria-hidden="true">→</span></NuxtLink>
          <span class="mx-2" aria-hidden="true">·</span>
          <NuxtLink :to="`${DOCS}#kurze-prüfung-im-browser-und-under-attack`" class="font-semibold text-link hover:underline">Kurze Prüfung im Browser und Under Attack <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="sensible-bereiche" class="scroll-mt-16 border-b border-line" aria-labelledby="admin-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Zugriffsschutz</p>
        <h2 id="admin-title" class="h2 mt-3">Sensible Bereiche einfach zusätzlich absichern.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Die Anmeldung deines CMS, eine Staging-Seite oder eine alte Anwendung, die keine Updates mehr bekommt: Vieles davon ist für alle im Internet erreichbar. Mit dem Zugriffsschutz stellst du eine zweite Tür davor, für einen Pfad, für mehrere oder für die ganze Website. Sie öffnet sich nur mit einem gemeinsamen Passwort, nur von deinen Adressen aus oder nur mit beidem. Im Beispiel sind es <span class="code">/wp-admin/*</span> und <span class="code">/wp-login.php</span>. Schild speichert vom Passwort nur einen Hash.
        </p>
        <DashboardShots class="mt-10" label="Sensible Bereiche absichern in drei Schritten" :shots="adminShots" :caption="`Echte Screenshots vom ${SHOTS_DATE} mit Testdaten. Die Anmeldeseite ist die Seite, die das Gateway ausliefert.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="`${DOCS}#zugriffsschutz-mit-passwort-und-eigenen-ips`" class="font-semibold text-link hover:underline">Zugriffsschutz mit Passwort und eigenen IPs <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="cluster" class="scroll-mt-16 border-b border-line bg-mist" aria-labelledby="cluster-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Hochverfügbarkeit</p>
        <h2 id="cluster-title" class="h2 mt-3">Mehrere Gateways als Cluster betreiben.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Läuft ein einzelnes Gateway vor deinen Websites, hängen sie alle an diesem einen Server. Mit einem Cluster stellst du zwei bis sechzehn Gateways nebeneinander, zum Beispiel hinter einen Loadbalancer. Sie teilen Sperren, Einstellungen, Logins, Zertifikate, Zähler, Ereignisse und Anfragen direkt untereinander. Eine Datenbank oder einen Cache daneben betreibst du dafür nicht. Fällt ein Server aus, bedienen die anderen weiter. Eine Sperre, die du auf einem Server setzt, gilt nach etwa einer Sekunde auf jedem.
        </p>
        <DashboardShots class="mt-10" label="Ein Cluster aus drei Gateways im Dashboard in drei Schritten" :shots="clusterShots" :caption="`Echte Screenshots vom ${CLUSTER_SHOTS_DATE} mit Testdaten, IP-Adressen unkenntlich gemacht. Im Beispiel ist einer von drei Servern nicht erreichbar.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="CLUSTER_DOCS" class="font-semibold text-link hover:underline">Mehrere Gateways als Cluster betreiben <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section class="border-b border-line" aria-labelledby="mehr-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="mehr-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Was das Gateway außerdem kann</h2>
        <ul class="mt-8 grid gap-x-10 gap-y-6 md:grid-cols-2 lg:grid-cols-3">
          <li v-for="m in more" :key="m.title" class="border-t border-line pt-4">
            <h3 class="font-semibold">
              <NuxtLink :to="m.to" class="hover:underline">{{ m.title }} <span aria-hidden="true">→</span></NuxtLink>
            </h3>
            <p class="mt-1 text-sm leading-relaxed text-slate">{{ m.text }}</p>
          </li>
        </ul>
        <div class="mt-10 flex flex-wrap items-center gap-x-6 gap-y-3">
          <NuxtLink to="/#installieren" class="btn-primary">Schild Gateway installieren</NuxtLink>
          <NuxtLink :to="DOCS" class="text-sm font-semibold text-link hover:underline">Alle Funktionen in der Dokumentation <span aria-hidden="true">→</span></NuxtLink>
        </div>
      </div>
    </section>
  </div>
</template>
