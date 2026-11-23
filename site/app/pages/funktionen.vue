<script setup lang="ts">
import type { DashboardShot } from '~/components/DashboardShots.vue'
import { SHOTS_DATE } from '~/utils/shots'

// Features shown as worked examples: what a visitor sees, what the operator sees, with real screenshots. Two groups:
// what the gateway does on its own ("Ab Werk") and what the operator switches on ("Nach Bedarf").
// This page shows; how to set things up lives in docs/gateway/01-funktionen.md, and every example links there.
// Every claim has to hold for the gateway as built, without labs.
// Screenshots: retaken with `npm run shots` (site/scripts/shots.mjs), dashboard in mock mode at 1440×900; block page and login
// page are the HTML the gateway serves (gateway/internal/blockpage, gateway/internal/accesslock). IP addresses are
// blurred at capture time: they are documentation addresses, but a reader cannot tell that from the picture.
// The cluster example shows three gateways: the page and a server's details with everything in order (mock scenario
// `group-ok`), the hints with one gateway not reached (`group`). The cluster is experimental and
// in no release yet (docs/gateway/03-cluster.md): the section says so, and it claims only what that guide states.

useHead({ title: 'Funktionen – Deutschland-Schild' })
useSeoMeta({ description: 'Was das Schild Gateway abwehrt und wie du es einstellen kannst, an Beispielen mit Screenshots: ein gestoppter SQL-Injection-Versuch, sensible Bereiche hinter Passwort und eigenen IPs und mehrere Gateways als Cluster.' })

const DOCS = '/doku/gateway/01-funktionen'
const CLUSTER_DOCS = '/doku/gateway/03-cluster'
// The cluster screenshots were taken on their own (`npm run shots -- funktionen-cluster`), so they carry their own
// date until the next full run of the script, which dates every screenshot alike (SHOTS_DATE).
const CLUSTER_SHOTS_DATE = '22.11.2026'

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

// Built features without a worked example yet; each links to its section in the docs.
const more = [
  { title: 'Login-Schutz', text: 'Ein Limit für Login-Seiten gilt ab dem Start. Wer Passwörter durchprobiert, wird nach 14 Tagen Lernzeit gesperrt.', to: `${DOCS}#szenarien-und-limits` },
  { title: 'Ausnahmen bei Fehlalarm', text: 'Eng begrenzt auf einzelne Regeln und ein Feld auf einer Seite.', to: `${DOCS}#ausnahmen` },
  { title: 'KI-Crawler', text: 'Pro Website festlegen, welche Crawler deine Seiten abrufen dürfen.', to: `${DOCS}#bots-und-ki-crawler` },
  { title: 'Eigene IPs', text: 'Dich und dein Team freischalten, dauerhaft oder befristet.', to: `${DOCS}#eigene-ips` },
  { title: 'Wartungsmodus', text: 'Alle sehen eine Wartungsseite, nur deine eigenen IPs kommen durch.', to: `${DOCS}#wartungsmodus` },
  { title: 'Server-Check', text: 'Prüft Updates, offene Ports, Firewall, SSH und Zertifikate, ohne etwas zu ändern.', to: `${DOCS}#server-check` },
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
          Drei Beispiele, Schritt für Schritt: was ein Angreifer zu sehen bekommt, was du im Dashboard siehst und was du mit ein paar Klicks einstellst.
        </p>
        <ul class="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <li>
            <a href="#sql-injection" class="block rounded-xl bg-white p-5 shadow-sm ring-1 ring-mist-line transition hover:ring-ink/30">
              <span class="kicker">Ab Werk</span>
              <span class="mt-1 block font-semibold">Ein SQL-Injection-Versuch wird gestoppt</span>
            </a>
          </li>
          <li>
            <a href="#sensible-bereiche" class="block rounded-xl bg-white p-5 shadow-sm ring-1 ring-mist-line transition hover:ring-ink/30">
              <span class="kicker">Nach Bedarf</span>
              <span class="mt-1 block font-semibold">Sensible Bereiche einfach zusätzlich absichern</span>
            </a>
          </li>
          <li>
            <a href="#cluster" class="block rounded-xl bg-white p-5 shadow-sm ring-1 ring-mist-line transition hover:ring-ink/30">
              <span class="kicker">Nach Bedarf · experimentell</span>
              <span class="mt-1 block font-semibold">Mehrere Gateways als Cluster betreiben</span>
            </a>
          </li>
        </ul>
      </div>
    </section>

    <section id="sql-injection" class="scroll-mt-16 border-b border-line" aria-labelledby="sqli-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Ab Werk</p>
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
        <DashboardShots class="mt-10" label="Ein gestoppter SQL-Injection-Versuch in drei Schritten" :shots="sqliShots" eager :caption="`Echte Screenshots vom ${SHOTS_DATE} mit Testdaten, IP-Adresse unkenntlich gemacht. Die Sperrseite ist die Seite, die das Gateway ausliefert.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="`${DOCS}#regeln`" class="font-semibold text-link hover:underline">Regeln <span aria-hidden="true">→</span></NuxtLink>
          <span class="mx-2" aria-hidden="true">·</span>
          <NuxtLink :to="`${DOCS}#sperrseite-und-warteseite`" class="font-semibold text-link hover:underline">Sperrseite <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="sensible-bereiche" class="scroll-mt-16 border-b border-line bg-mist" aria-labelledby="admin-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Nach Bedarf</p>
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

    <section id="cluster" class="scroll-mt-16 border-b border-line" aria-labelledby="cluster-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Nach Bedarf · experimentell</p>
        <h2 id="cluster-title" class="h2 mt-3">Mehrere Gateways als Cluster betreiben.</h2>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Läuft ein einzelnes Gateway vor deinen Websites, hängen sie alle an diesem einen Server. Mit einem Cluster stellst du zwei bis sechzehn Gateways nebeneinander, zum Beispiel hinter einen Loadbalancer. Sie teilen Sperren, Einstellungen, Logins, Zertifikate, Zähler, Ereignisse und Anfragen direkt untereinander. Eine Datenbank oder einen Cache daneben betreibst du dafür nicht. Fällt ein Server aus, bedienen die anderen weiter. Eine Sperre, die du auf einem Server setzt, gilt nach etwa einer Sekunde auf jedem.
        </p>
        <p class="mt-4 max-w-2xl leading-relaxed text-slate">
          Der Cluster ist experimentell und noch in keinem Release enthalten. Gemessen ist er bisher mit virtuellen Servern, nicht im Betrieb mit echten Besucher:innen. Die Grenzen stehen in der Dokumentation.
        </p>
        <DashboardShots class="mt-10" label="Ein Cluster aus drei Gateways im Dashboard in drei Schritten" :shots="clusterShots" :caption="`Echte Screenshots vom ${CLUSTER_SHOTS_DATE} mit Testdaten, IP-Adressen unkenntlich gemacht. Im Beispiel ist einer von drei Servern nicht erreichbar.`" />
        <p class="mt-6 text-sm text-slate">
          Einrichtung und Details:
          <NuxtLink :to="CLUSTER_DOCS" class="font-semibold text-link hover:underline">Mehrere Gateways als Cluster betreiben <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section class="border-b border-line bg-mist" aria-labelledby="mehr-title">
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
