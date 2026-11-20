<script setup lang="ts">
import type { FaqGroup } from '~/components/FaqList.vue'
import type { ScrollyScene } from '~/components/IsoScrolly.vue'

// The network around the gateway, moved off the start page so that it can stay about the Schild Gateway. Order: intro →
// the four levels → two worked examples (<IsoScrolly>) → decentralised virtual patching → Labs → network walkthrough →
// state and roadmap → FAQ. Section ids stayed the same. Terms: docs/brand/01-marke.md, "Glossar".
useHead({ title: 'Das Schild-Netz – Deutschland-Schild' })
useSeoMeta({ description: 'Wie Gateways, unabhängige Labs und Relays neue Angriffe gemeinsam prüfen und Regeln verteilen, ohne Daten von Besuchern zu teilen. Geplant.' })

// status: what exists today (the gateway) and what is planned (StatusBadge). Labs and relays run in the test lab only.
const parts = [
  { level: 'Level 1', status: 'live' as const, name: 'Schild Gateway', where: 'auf deinem Server', text: 'Reverse-Proxy mit WAF (Caddy, Coraza, OWASP CRS). Prüft jede Anfrage, bevor sie deine Anwendung erreicht, und entscheidet immer lokal.', stack: 'Go 1.27, Caddy 2.11, Coraza 3.8, OWASP CRS 4.30, Dashboard in Vue 3' },
  { level: 'Level 2', status: 'planned' as const, name: 'Labs', where: 'bei unabhängigen Betreibern', text: 'Bündeln Signale vieler Gateways, schlagen Regeln vor, testen sie und geben sie frei. Eine Regel gilt erst, wenn mehrere Labs mitzeichnen (k von n). Dazu kommen lokale Open-Weights-KI-Modelle für ultraschnelle Analyse, Tests und Abwehr, auf eigener Hardware im Lab (geplant, im Prototyp noch nicht gebaut).', stack: 'Go, Signaturen mit Ed25519 (DSSE), öffentliches Log' },
  { level: 'Level 3', status: 'planned' as const, name: 'Relays', where: 'beliebig viele', text: 'Bringen die Signale zu den Labs, jede Website über andere Relays: Ein Relay sieht, wer sendet, aber nicht was; ein Lab sieht was, aber nicht von wem (ab v1; im Prototyp im Testlabor gingen Signale noch direkt an die Labs). Dazu verteilen Relays die signierten Regeln. Ändern können sie nichts.', stack: 'Go, Server-Sent Events' },
  { level: 'Level 4', status: 'planned' as const, name: 'Managed Schild', where: 'bei deinem Hoster', text: 'Hoster betreiben Schild Gateways als Dienst für ihre Kund:innen, ähnlich wie Cloudflare, nur dezentral bei vielen unabhängigen Hostern. Selbst betreiben geht weiterhin.', stack: '' },
]

// Example 1: a zero-day. No advisory, no update; the network notices the new request shape at many sites and answers
// with a narrow virtual patch on the vulnerable endpoint, which also covers variants the Core Rule Set missed.
const zeroDay = [
  { who: 'Angriff', text: 'Angreifer nutzen eine Lücke in einem WordPress-Plugin, die noch niemand kennt. Es gibt keine Warnung und kein Update. Die Anfragen gehen an einen REST-Endpunkt des Plugins und schmuggeln ein PHP-Objekt in einen Parameter.' },
  { who: 'Gateways', text: 'Das Core Rule Set fängt einige Varianten ab (PHP Object Injection), andere rutschen durch, weil die Angreifer die Anfrage ständig abwandeln. Jedes Gateway meldet die neue Anfrageform über wechselnde Relays an mehrere Labs: Methode, Pfadvorlage, Parameternamen und Regel-IDs als Hash. Keine IP, kein datenschutzkritischer Payload.' },
  { who: 'Lab, automatisch', text: 'Dieselbe Form kommt binnen Minuten von vielen Websites verschiedener Betreiber, und kein Advisory passt dazu: Verdacht auf einen Zero-Day. Den Angriff selbst sehen die Labs in eigenen Honeypots, die dieselbe Anfrageform treffen. Vorschlag für einen virtuellen Patch: an genau diesem Endpunkt keine serialisierten Objekte mehr annehmen. Probelauf gegen die bekannten Angriffsvarianten (muss blocken) und gegen harmlosen Traffic (keine Fehlalarme).' },
  { who: 'Lab, Mensch', text: 'Jemand liest Regel und Testbericht und gibt frei. Das dauert Minuten, nicht Tage.' },
  { who: 'Netz', text: 'Zeichnen genug Labs mit, ist die Regel ein signiertes Paket. Relays verteilen es in Sekunden, alles steht im öffentlichen Log.' },
  { who: 'Gateways', text: 'Alle Websites mit dem Plugin sind abgeschirmt, auch gegen die Varianten, die das Core Rule Set nicht erkannt hat. Im Dashboard: „Neuer Angriff auf ein Plugin, das du nutzt. Schild blockt ihn mit einem virtuellen Patch, ein Update gibt es noch nicht.“' },
  { who: 'Später', text: 'Der Hersteller veröffentlicht Warnung und Update. Die Labs hängen die CVE-Nummer an die Regel, und das Dashboard bittet dich, das Update einzuspielen. Bis dahin hat der virtuelle Patch die Lücke abgeschirmt.' },
]

const pluginCve = [
  { who: 'Tag 0', text: 'Eine Lücke wird bekannt: Das Laravel-Package „beispiel/laravel-medialib“ bis 2.3.1 erlaubt Datei-Uploads ohne Login über POST /medialib/upload.' },
  { who: 'Gateways', text: 'Das Core Rule Set schlägt teilweise an (PHP-Code im Upload, Regel 933110). Mehrere Websites melden dieselbe Anfrageform über verschiedene Relays an die Labs: Methode, Pfadvorlage, Parameternamen und Regel-IDs, als Hash und ohne Inhalt.' },
  { who: 'Lab, automatisch', text: 'Dieselbe Form kommt von mindestens 3 Websites bei 2 Betreibern. Abgleich mit Advisory-Feeds (OSV, GitHub Security Advisories, CISA KEV). Vorschlag für einen virtuellen Patch: Uploads ausführbarer Dateien an genau diesem Pfad blocken. Probelauf gegen den Exploit (muss blocken) und gegen harmlosen Traffic (keine Fehlalarme).' },
  { who: 'Lab, Mensch', text: 'Jemand liest Regel und Testbericht und gibt frei. Das dauert Minuten, nicht Tage.' },
  { who: 'Netz', text: 'Zeichnen genug Labs mit, ist die Regel ein signiertes Paket. Relays verteilen es in Sekunden, alles steht im öffentlichen Log.' },
  { who: 'Gateway', text: 'Websites im Modus „Beobachten“ zählen „hätte 12 Anfragen geblockt“, aktive Websites blocken. Im Dashboard: „beispiel/laravel-medialib 2.3.1: betroffen, abgefedert – bitte per composer auf 2.3.2 aktualisieren.“' },
]

// Scenes for the two examples (<IsoScrolly>): one frame per step. Principle illustration with made-up data.
// No visitor IP anywhere in the network part (E4): signals carry patterns only.
const LAB_COLORS = { uni: '#6366F1', hoster: '#0EA5E9', cert: '#14B8A6' }
const W = ['w1', 'w2', 'w3']
const L = ['labA', 'labB', 'labC']
// Signals go over different relays (each website its own), so no relay sees all senders and no lab sees a sender's IP.
const SR = ['sr1', 'sr2', 'sr3']

const zeroDayScene: ScrollyScene = {
  title: 'Prinzip-Darstellung: ein Zero-Day in einem WordPress-Plugin, drei Websites mit Schild, drei Labs, Relays und ein öffentliches Log.',
  width: 640,
  height: 520,
  nodes: [
    { id: 'atk', type: 'botnet', x: 70, y: 440, scale: 1.1, label: 'Angreifer' },
    { id: 'w1', type: 'website', x: 195, y: 350, label: 'Website A' },
    { id: 'w2', type: 'website', x: 275, y: 395, label: 'Website B' },
    { id: 'w3', type: 'website', x: 355, y: 440, label: 'Website C' },
    { id: 'dash', type: 'dashboard', x: 475, y: 480, label: 'Dashboard' },
    { id: 'r1', type: 'relay', x: 505, y: 320, label: 'Relay' },
    { id: 'r2', type: 'relay', x: 600, y: 345, label: 'Relay' },
    { id: 'review', type: 'dashboard', x: 245, y: 160, label: 'Freigabe' },
    { id: 'sr1', type: 'relay', x: 250, y: 268, scale: 0.8, label: 'Relay' },
    { id: 'sr2', type: 'relay', x: 330, y: 290, scale: 0.8, label: 'Relay' },
    { id: 'sr3', type: 'relay', x: 410, y: 300, scale: 0.8, label: 'Relay' },
    { id: 'adv', type: 'advisory', x: 75, y: 220, label: 'Advisory' },
    { id: 'labA', type: 'lab', x: 370, y: 190, accent: LAB_COLORS.uni, label: 'Hochschul-Lab' },
    { id: 'labB', type: 'lab', x: 460, y: 165, accent: LAB_COLORS.hoster, label: 'Hoster-Lab' },
    { id: 'labC', type: 'lab', x: 545, y: 200, accent: LAB_COLORS.cert, label: 'CERT-Lab' },
    { id: 'log', type: 'log', x: 610, y: 255, label: 'Log' },
  ],
  links: [
    ...W.map(w => ({ id: `atk-${w}`, from: 'atk', to: w })),
    ...W.map((w, i) => ({ id: `${w}-${SR[i]}`, from: w, to: SR[i]! })),
    ...SR.flatMap(r => L.map(l => ({ id: `${r}-${l}`, from: r, to: l }))),
    { id: 'adv-labA', from: 'adv', to: 'labA' },
    { id: 'review-labA', from: 'review', to: 'labA' },
    { id: 'labA-labB', from: 'labA', to: 'labB' },
    { id: 'labB-labC', from: 'labB', to: 'labC' },
    { id: 'labA-labC', from: 'labA', to: 'labC' },
    { id: 'labC-log', from: 'labC', to: 'log' },
    { id: 'labC-r1', from: 'labC', to: 'r1' },
    { id: 'labC-r2', from: 'labC', to: 'r2' },
    { id: 'r1-w1', from: 'r1', to: 'w1' },
    { id: 'r1-w2', from: 'r1', to: 'w2' },
    { id: 'r2-w3', from: 'r2', to: 'w3' },
    { id: 'w3-dash', from: 'w3', to: 'dash' },
  ],
  frames: [
    {
      aria: 'Angreifer schicken Anfragen an eine unbekannte Lücke in einem WordPress-Plugin, an mehrere Websites. Es gibt keine Warnung und kein Update.',
      focus: ['atk', ...W],
      states: { w1: 'attacked', w2: 'attacked', w3: 'attacked' },
      flows: W.map((w, i) => ({ link: `atk-${w}`, kind: 'attack' as const, delay: i * 0.2 })),
      tags: [
        { at: 'atk', text: 'unbekannte Lücke', tone: 'red', dx: 30 },
        { at: 'w2', text: 'keine Warnung, kein Update', tone: 'slate', dx: -10 },
      ],
    },
    {
      aria: 'Einige Varianten blockt das Core Rule Set, andere nicht. Jede Website meldet die neue Anfrageform über ein anderes Relay an die Labs, ohne IP und ohne Inhalt.',
      focus: ['atk', ...W, ...SR, ...L],
      states: { w1: 'pending', w2: 'pending', w3: 'pending' },
      flows: [
        { link: 'atk-w1', kind: 'attack', stop: true },
        { link: 'atk-w2', kind: 'attack', delay: 0.2 },
        { link: 'atk-w3', kind: 'attack', delay: 0.4 },
        ...W.map((w, i) => ({ link: `${w}-${SR[i]}`, kind: 'signal' as const, delay: 0.9 + i * 0.2 })),
        ...SR.flatMap((r, i) => L.map((l, j) => ({ link: `${r}-${l}`, kind: 'signal' as const, delay: 1.5 + i * 0.2 + j * 0.1 }))),
      ],
      tags: [
        { at: 'w1', text: 'neue Anfrageform', tone: 'amber', dx: -30 },
      ],
    },
    {
      aria: 'Ein Lab sieht dieselbe Form bei vielen Websites, findet kein passendes Advisory und schlägt einen virtuellen Patch vor. Der Probelauf läuft.',
      focus: [...L],
      states: { labA: 'pending' },
      busy: ['labA'],
      tags: [
        { at: 'labA', text: 'kein Advisory: Zero-Day?', tone: 'amber' },
        { at: 'labA', text: 'Vorschlag: virtueller Patch', tone: 'blue' },
      ],
    },
    {
      aria: 'Ein Mensch liest Regel und Testbericht und gibt den Patch frei.',
      focus: ['review', 'labA'],
      states: { labA: 'active', review: 'active' },
      flows: [{ link: 'review-labA', kind: 'rule' }],
      tags: [{ at: 'review', text: 'Mensch gibt frei', tone: 'green', dx: -20 }],
    },
    {
      aria: 'Mehrere Labs zeichnen mit. Das signierte Paket steht im öffentlichen Log, Relays verteilen es.',
      focus: [...L, 'log', 'r1', 'r2'],
      states: { labA: 'active', labB: 'active', labC: 'active', log: 'active', r1: 'active', r2: 'active' },
      flows: [
        { link: 'labA-labB', kind: 'vote' },
        { link: 'labB-labC', kind: 'vote', delay: 0.2 },
        { link: 'labA-labC', kind: 'vote', delay: 0.4 },
        { link: 'labC-log', kind: 'rule', delay: 0.8 },
        { link: 'labC-r1', kind: 'rule', delay: 1 },
        { link: 'labC-r2', kind: 'rule', delay: 1 },
      ],
      tags: [
        { at: 'labB', text: 'k von n: signiert', tone: 'blue' },
        { at: 'log', text: 'öffentlich: + Patch', tone: 'green', dx: -30 },
      ],
    },
    {
      aria: 'Alle Gateways bekommen den Patch und blocken jetzt jede Variante des Angriffs. Das Dashboard meldet: abgeschirmt, noch kein Update.',
      focus: ['atk', ...W, 'r1', 'r2', 'dash'],
      states: { w1: 'active', w2: 'active', w3: 'active', r1: 'active', r2: 'active', dash: 'active' },
      flows: [
        { link: 'r1-w1', kind: 'rule' },
        { link: 'r1-w2', kind: 'rule' },
        { link: 'r2-w3', kind: 'rule' },
        { link: 'atk-w1', kind: 'attack', stop: true, delay: 0.3 },
        { link: 'atk-w2', kind: 'attack', stop: true, delay: 0.3 },
        { link: 'atk-w3', kind: 'attack', stop: true, delay: 0.3 },
        { link: 'w3-dash', kind: 'check', delay: 0.8 },
      ],
      tags: [
        { at: 'w2', text: 'virtueller Patch blockt', tone: 'green', dx: -20 },
        { at: 'dash', text: 'Abgeschirmt, noch kein Update', tone: 'ink', dx: 20 },
      ],
    },
    {
      aria: 'Später erscheinen Warnung und Update. Die Regel bekommt die CVE-Nummer, das Dashboard bittet um das Update.',
      focus: ['adv', 'labA', 'dash', 'w3'],
      states: { adv: 'active', labA: 'active', dash: 'active', w3: 'active' },
      flows: [
        { link: 'adv-labA', kind: 'check' },
        { link: 'w3-dash', kind: 'check', delay: 0.6 },
      ],
      tags: [
        { at: 'adv', text: 'Warnung und Update da', tone: 'blue', dx: 40 },
        { at: 'dash', text: 'Bitte Update einspielen', tone: 'ink', dx: 20 },
      ],
    },
  ],
}

const pluginCveScene: ScrollyScene = {
  title: 'Prinzip-Darstellung: eine Lücke in einem Laravel-Package, drei Websites mit Schild, drei Labs, Relays und ein öffentliches Log.',
  width: 640,
  height: 520,
  nodes: [
    { id: 'adv', type: 'advisory', x: 75, y: 180, label: 'Advisory' },
    { id: 'atk', type: 'botnet', x: 70, y: 440, scale: 1.1, label: 'Angreifer' },
    { id: 'w1', type: 'website', x: 195, y: 350, label: 'Website A' },
    { id: 'w2', type: 'website', x: 275, y: 395, label: 'Website B' },
    { id: 'w3', type: 'website', x: 355, y: 440, label: 'Website C' },
    { id: 'dash', type: 'dashboard', x: 475, y: 480, label: 'Dashboard' },
    { id: 'r1', type: 'relay', x: 505, y: 320, label: 'Relay' },
    { id: 'r2', type: 'relay', x: 600, y: 345, label: 'Relay' },
    { id: 'review', type: 'dashboard', x: 245, y: 160, label: 'Freigabe' },
    { id: 'sr1', type: 'relay', x: 250, y: 268, scale: 0.8, label: 'Relay' },
    { id: 'sr2', type: 'relay', x: 330, y: 290, scale: 0.8, label: 'Relay' },
    { id: 'sr3', type: 'relay', x: 410, y: 300, scale: 0.8, label: 'Relay' },
    { id: 'labA', type: 'lab', x: 370, y: 190, accent: LAB_COLORS.uni, label: 'Hochschul-Lab' },
    { id: 'labB', type: 'lab', x: 460, y: 165, accent: LAB_COLORS.hoster, label: 'Hoster-Lab' },
    { id: 'labC', type: 'lab', x: 545, y: 200, accent: LAB_COLORS.cert, label: 'CERT-Lab' },
    { id: 'log', type: 'log', x: 610, y: 255, label: 'Log' },
  ],
  links: [
    { id: 'adv-labA', from: 'adv', to: 'labA' },
    ...W.map(w => ({ id: `atk-${w}`, from: 'atk', to: w })),
    ...W.map((w, i) => ({ id: `${w}-${SR[i]}`, from: w, to: SR[i]! })),
    ...SR.flatMap(r => L.map(l => ({ id: `${r}-${l}`, from: r, to: l }))),
    { id: 'review-labA', from: 'review', to: 'labA' },
    { id: 'labA-labB', from: 'labA', to: 'labB' },
    { id: 'labB-labC', from: 'labB', to: 'labC' },
    { id: 'labA-labC', from: 'labA', to: 'labC' },
    { id: 'labC-log', from: 'labC', to: 'log' },
    { id: 'labC-r1', from: 'labC', to: 'r1' },
    { id: 'labC-r2', from: 'labC', to: 'r2' },
    { id: 'r1-w1', from: 'r1', to: 'w1' },
    { id: 'r1-w2', from: 'r1', to: 'w2' },
    { id: 'r2-w3', from: 'r2', to: 'w3' },
    { id: 'w3-dash', from: 'w3', to: 'dash' },
  ],
  frames: [
    {
      aria: 'Ein Advisory erscheint: Das Laravel-Package beispiel/laravel-medialib bis 2.3.1 erlaubt Uploads ohne Login.',
      focus: ['adv'],
      states: { adv: 'attacked' },
      tags: [{ at: 'adv', text: 'medialib ≤ 2.3.1: Upload ohne Login', tone: 'red', dx: 50 }],
    },
    {
      aria: 'Angriffe treffen mehrere Websites. Jede meldet dieselbe Anfrageform über ein anderes Relay an die Labs, ohne IP und ohne Inhalt.',
      focus: ['atk', ...W, ...SR, ...L],
      states: { w1: 'pending', w2: 'pending', w3: 'pending' },
      flows: [
        ...W.map((w, i) => ({ link: `atk-${w}`, kind: 'attack' as const, delay: i * 0.2 })),
        ...W.map((w, i) => ({ link: `${w}-${SR[i]}`, kind: 'signal' as const, delay: 0.9 + i * 0.2 })),
        ...SR.flatMap((r, i) => L.map((l, j) => ({ link: `${r}-${l}`, kind: 'signal' as const, delay: 1.5 + i * 0.2 + j * 0.1 }))),
      ],
      tags: [
        { at: 'w1', text: 'gleiche Anfrageform', tone: 'amber', dx: -30 },
      ],
    },
    {
      aria: 'Ein Lab gleicht die Meldungen mit Advisories ab, schlägt einen virtuellen Patch vor und testet ihn im Probelauf.',
      focus: ['adv', 'labA'],
      states: { labA: 'pending' },
      busy: ['labA'],
      flows: [{ link: 'adv-labA', kind: 'check' }],
      tags: [
        { at: 'labA', text: 'Probelauf läuft', tone: 'amber' },
        { at: 'labA', text: 'Vorschlag: virtueller Patch', tone: 'blue' },
      ],
    },
    {
      aria: 'Ein Mensch liest Regel und Testbericht und gibt den Patch frei.',
      focus: ['review', 'labA'],
      states: { labA: 'active', review: 'active' },
      flows: [{ link: 'review-labA', kind: 'rule' }],
      tags: [{ at: 'review', text: 'Mensch gibt frei', tone: 'green', dx: -20 }],
    },
    {
      aria: 'Mehrere Labs zeichnen mit. Das signierte Paket steht im öffentlichen Log, Relays verteilen es.',
      focus: [...L, 'log', 'r1', 'r2'],
      states: { labA: 'active', labB: 'active', labC: 'active', log: 'active', r1: 'active', r2: 'active' },
      flows: [
        { link: 'labA-labB', kind: 'vote' },
        { link: 'labB-labC', kind: 'vote', delay: 0.2 },
        { link: 'labA-labC', kind: 'vote', delay: 0.4 },
        { link: 'labC-log', kind: 'rule', delay: 0.8 },
        { link: 'labC-r1', kind: 'rule', delay: 1 },
        { link: 'labC-r2', kind: 'rule', delay: 1 },
      ],
      tags: [
        { at: 'labB', text: 'k von n: signiert', tone: 'blue' },
        { at: 'log', text: 'öffentlich: + Patch', tone: 'green', dx: -30 },
      ],
    },
    {
      aria: 'Alle Gateways bekommen den Patch. Website A beobachtet und zählt, B und C blocken. Das Dashboard bittet um das Update auf 2.3.2.',
      focus: ['atk', ...W, 'r1', 'r2', 'dash'],
      states: { w1: 'pending', w2: 'active', w3: 'active', r1: 'active', r2: 'active', dash: 'active' },
      flows: [
        { link: 'r1-w1', kind: 'rule' },
        { link: 'r1-w2', kind: 'rule' },
        { link: 'r2-w3', kind: 'rule' },
        { link: 'atk-w1', kind: 'attack', delay: 0.3 },
        { link: 'atk-w2', kind: 'attack', stop: true, delay: 0.3 },
        { link: 'atk-w3', kind: 'attack', stop: true, delay: 0.3 },
        { link: 'w3-dash', kind: 'check', delay: 0.8 },
      ],
      tags: [
        { at: 'w1', text: 'hätte 12 geblockt', tone: 'amber', dx: -30 },
        { at: 'w3', text: 'blockt', tone: 'green', dx: -20 },
        { at: 'dash', text: 'Bitte auf 2.3.2 aktualisieren', tone: 'ink', dx: 20 },
      ],
    },
  ],
}

// Decentralised virtual patching, step by step. Facts from contracts/rule-bundle.schema.json and concept 21.
const vpatch = [
  { title: 'Eng statt breit', text: 'Ein virtueller Patch trifft genau den Angriffsweg einer Lücke: Pfad, Methode, Parameter, Dateityp. Nie eine IP-Adresse, nie ganze Länder. Alles andere läuft normal weiter.' },
  { title: 'Getestet vor der Freigabe', text: 'Das Lab spielt den Exploit gegen die Regel (muss blocken) und harmlosen Traffic (darf nicht blocken). Ohne bestandenen Probelauf keine Unterschrift.' },
  { title: 'k von n statt einer Zentrale', text: 'Ein Regelpaket gilt erst mit Unterschriften mehrerer Labs von verschiedenen Betreibern, mindestens zwei. Ein einzelnes Lab, das sich irrt oder gekapert wird, kann nichts ausrollen.' },
  { title: 'Öffentlich nachvollziehbar', text: 'Jedes Paket steht im öffentlichen Transparenz-Log: wer unterschrieben hat, wann, mit welchem Testbericht.' },
  { title: 'Dein Gateway prüft selbst', text: 'Relays liefern nur aus. Dein Gateway prüft die Unterschriften der Labs, denen du vertraust, lehnt ältere Versionen ab und lässt abgelaufene Pakete verfallen.' },
  { title: 'Erst beobachten, dann blocken', text: 'Eine neue Regel kann zuerst „hätte geblockt“ zählen. Du siehst im Dashboard, was sie tun würde, bevor sie blockt.' },
]

const labWork = {
  auto: ['Signale bündeln, Wellen erkennen, mit Advisories abgleichen', 'Regel vorschlagen, Probelauf gegen echten Traffic, Test auf Fehlalarme', 'Mitzeichnen, verteilen, ins öffentliche Log schreiben'],
  human: ['Eine Regel freigeben (Minuten pro Regel)', 'Betrieb, Updates, Schlüssel', 'Optional: tiefere Forschung wie Patch-Diffing oder Exploits nachbauen'],
}

// Levels (initiator, 2026-10-29): 1 = gateway (self-run, Grundschutz without labs), 2 = labs (one lab for own gateways,
// or several together), 3 = relays (connect many gateways and labs), 4 = Managed Schild (hosters run gateways as a service).
// Rollout along the levels (initiator, 2026-10-29). "Stufe" only means the prototype verification stages of concept 23:
// stage 2 passed in the test lab; level 1 live with own servers and partners we are looking for (no confirmed
// partnership) is stage 3. Same images as tested. Level 1 has no mode line until the autoblock wording is decided.
const rollout = [
  { nr: 1, when: 'Jetzt', title: 'Level 1: Schild Gateway', text: 'Das Gateway läuft allein, ohne Labs. Es ist als Alpha veröffentlicht und läuft auf unseren eigenen Servern. Jetzt suchen wir Partner und alle, die es ausprobieren wollen. Wir messen Fehlalarme und Last und veröffentlichen früh und oft.', mode: '' },
  { nr: 2, when: 'Danach', title: 'Level 2: Labs', text: 'Ein eigenes Lab für die eigenen Gateways, dann mehrere Labs, die ihr Wissen bündeln. Lokale Open-Weights-KI-Modelle helfen bei Analyse und Tests.', mode: 'Modus: beobachten, selbst freigeben' },
  { nr: 3, when: 'Mit v1', title: 'Level 3: Relays', text: 'Relays verbinden viele Gateways und Labs. Hoster, Hochschulen und Sicherheitsteams betreiben Labs. Erst dann wird automatisches Sperren Standard.', mode: 'Modus: automatisch sperren' },
  { nr: 4, when: 'Ziel', title: 'Level 4: Managed Schild', text: 'Hoster betreiben Schild Gateways als Dienst, ähnlich wie Cloudflare, nur bei vielen unabhängigen Hostern. Für alle: selbst installiert, beim Hoster eingeschaltet oder als gemeinnütziger Reverse-Proxy.', mode: '' },
]

const faq: FaqGroup[] = [
  {
    items: [
      { q: 'Muss ich beim Netz mitmachen?', a: 'Nein. Das Schild Gateway läuft allein. Ob du es später an Labs anbindest und welchen du vertraust, entscheidest du selbst.' },
      { q: 'Was, wenn eine Regel aus dem Netz schiefgeht?', a: 'Dann können die Labs alle Netzregeln zurückziehen. Der Grundschutz auf deinem Server bleibt aktiv.' },
      { q: 'Was, wenn ihr selbst gehackt werdet oder unter Druck geratet?', a: 'Auch wir betreiben nur ein Lab unter mehreren und haben keinen Generalschlüssel. Eine Regel gilt erst, wenn mindestens zwei unabhängige Betreiber zustimmen, und jede Website wählt selbst, welchen Labs sie vertraut. Fällt unsere Technik aus, schützt Schild mit den lokalen Regeln weiter.' },
    ],
  },
]
</script>

<template>
  <div class="bg-white">
    <section class="border-b border-line bg-mist" aria-labelledby="netz-page-title">
      <div class="mx-auto grid max-w-6xl gap-12 px-5 py-20 sm:px-8 lg:grid-cols-[1.15fr_0.85fr] lg:items-center lg:gap-16 lg:py-24">
        <div>
          <p class="kicker">Geplant</p>
          <h1 id="netz-page-title" class="h2 mt-3">Das Schild-Netz</h1>
          <p class="mt-5 max-w-2xl text-lg leading-relaxed text-slate">
            Der Deutschland-Schild ist das Ziel hinter dem Gateway: Sieht eine Website einen neuen Angriffsversuch,
            prüfen ihn mehrere unabhängige Labs, und alle bekommen die geprüfte Regel, ohne dass jemand Daten seiner Besucher teilt.
          </p>
          <p class="mt-4 max-w-2xl leading-relaxed text-slate">
            Das Netz gibt es noch nicht im Betrieb, Labs und Relays laufen bisher nur im Testlabor.
            Für das Schild Gateway brauchst du das alles nicht. Es läuft allein auf deinem Server, und damit kannst du heute anfangen.
          </p>
          <div class="mt-8">
            <NuxtLink to="/#installieren" class="btn-primary">Schild Gateway installieren</NuxtLink>
          </div>
        </div>
        <div class="mx-auto w-full max-w-md">
          <SchildKarte :caption="false" />
        </div>
      </div>
    </section>

    <section id="so-arbeitet-schild" class="scroll-mt-16 border-b border-line" aria-labelledby="technik-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Schild erklärt in 5 Minuten</p>
        <h2 id="technik-title" class="h2 mt-3">So arbeitet der Deutschland-Schild – zwei Beispiele aus der Praxis.</h2>
        <p class="mt-5 max-w-2xl text-lg leading-relaxed text-slate">
          Vier Level. <strong class="font-semibold text-ink">Level 1</strong> ist das Gateway: Jede:r betreibt es selbst,
          und es bringt ab dem ersten Start einen Grundschutz mit, auch ganz ohne Labs.
          <strong class="font-semibold text-ink">Level 2</strong> sind Labs: Ein Lab kannst du nur für deine eigenen Gateways betreiben,
          oder mehrere Labs bündeln ihr Wissen und prüfen neue Muster gemeinsam.
          <strong class="font-semibold text-ink">Level 3</strong> sind Relays: Sie verbinden viele Gateways und Labs, damit geprüfte Regeln allen zur Verfügung stehen.
          <strong class="font-semibold text-ink">Level 4</strong> ist Managed Schild: Hoster betreiben Schild Gateways als Dienst für ihre Kund:innen.
          Geteilt werden Muster, keine Besucherdaten.
        </p>
        <ul class="mt-10 grid gap-x-10 gap-y-6 md:grid-cols-2 lg:grid-cols-4">
          <li v-for="p in parts" :key="p.name" class="border-t border-line pt-4">
            <p class="flex items-center gap-2 text-xs font-semibold tracking-widest text-signal-deep uppercase">{{ p.level }} <StatusBadge :status="p.status" short /></p>
            <h3 class="mt-1 font-semibold">{{ p.name }} <span class="text-sm font-normal text-slate">· {{ p.where }}</span></h3>
            <p class="mt-1 text-sm leading-relaxed text-slate">{{ p.text }}</p>
            <p v-if="p.stack" class="mt-2 text-xs text-slate"><span class="font-semibold">{{ p.status === 'live' ? 'Gebaut mit' : 'Prototyp im Testlabor' }}:</span> {{ p.stack }}</p>
          </li>
        </ul>
      </div>
    </section>

    <section id="zero-day" class="overflow-x-clip border-b border-line bg-mist" aria-labelledby="zd-title">
      <span id="brute-force" />
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Beispiel 1</p>
        <h2 id="zd-title" class="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">Ein Zero-Day in einem WordPress-Plugin</h2>
        <p class="mt-3 max-w-2xl leading-relaxed text-slate">Noch gibt es keine Warnung und kein Update. Das Netz bemerkt den Angriff und antwortet mit einem virtuellen Patch.</p>
        <div class="mt-8">
          <IsoScrolly :steps="zeroDay" :scene="zeroDayScene" numbered bg="mist" />
        </div>
        <div class="mt-12 grid gap-10 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] lg:gap-12">
          <div class="space-y-4 text-sm leading-relaxed text-ink lg:pt-2">
            <p>
              Der Patch richtet sich gegen den verwundbaren Endpunkt, nicht gegen eine einzelne Angriffsvariante.
              Deshalb hilft er auch dort, wo das Core Rule Set nur einen Teil erkannt hat.
            </p>
            <p class="text-slate">
              <strong class="text-ink">Grenze:</strong> Schlägt keine einzige Regel an, entsteht auch kein Signal.
              Einen Angriff, der für alle Gateways völlig harmlos aussieht, sieht auch das Netz nicht.
            </p>
          </div>
          <div class="min-w-0">
            <div class="codeblock">
              <p class="codeblock-title">Das komplette Signal (Contract schild.signal/0.3)</p>
              <pre><code>{
  "schema": "schild.signal/0.3",
  "kind": "tip",
  "time_bucket": "2026-10-26T11:55:00Z",
  "action_sig": "php-object-injection/wp-rest",
  "request_sig": "sha256:707c7f…63e5e3d",
  "waf_rules": [933170],
  "score": 46,
  "category": "php-object-injection",
  "origin": { "country": "BR", "asn": 64501,
              "net_class": "residential" },
  "agent": { "family": "curl",
             "major": 8, "bot": false }
}</code></pre>
            </div>
            <p class="mt-3 text-xs leading-relaxed text-slate">
              request_sig ist ein Hash aus Methode, Pfadvorlage, Parameternamen, Content-Type und Regel-IDs. Unbekannte Felder und alles,
              was nach einer Adresse aussieht, lehnen die Labs ab. Signiert, an mindestens drei Labs.
            </p>
            <p class="mt-2 text-xs leading-relaxed text-slate">
              <strong class="text-ink">Kein Payload, mit Absicht:</strong> Formulare und Uploads können Daten deiner Besucher enthalten.
              Den Angriff selbst holen sich die Labs aus eigenen Honeypots mit derselben Anfrageform und spielen ihn dort nach.
              Ein Signal ist nur ein Hinweis, nie ein Beleg. Zum Sperren müssen zwei Lab-Betreiber den Angriff nachgestellt haben.
            </p>
          </div>
        </div>
      </div>
    </section>

    <section id="plugin-luecke" class="overflow-x-clip border-b border-line" aria-labelledby="cve-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Beispiel 2</p>
        <h2 id="cve-title" class="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">Eine neue Lücke in einem Laravel-Package</h2>
        <p class="mt-3 max-w-2xl leading-relaxed text-slate">Diesmal ist die Lücke bekannt und das Update schon da. Der virtuelle Patch schirmt alle Websites ab, bis es überall eingespielt ist.</p>
        <div class="mt-8">
          <IsoScrolly :steps="pluginCve" :scene="pluginCveScene" numbered />
        </div>
      </div>
    </section>

    <section id="virtuelles-patchen" class="border-b border-line bg-mist" aria-labelledby="vp-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <p class="kicker">Dezentral</p>
        <h2 id="vp-title" class="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">Virtuelles Patchen ohne Zentrale</h2>
        <p class="mt-3 max-w-2xl leading-relaxed text-slate">
          Ein virtueller Patch ist eine WAF-Regel, die Angriffe auf eine bekannte Lücke abfängt, bevor sie deine Anwendung erreichen.
          Große Anbieter machen das für ihre Kunden: Gegen die PHP-Lücken „php2shell“ hatte Cloudflare im Oktober 2026 schon Stunden vor der Veröffentlichung
          WAF-Regeln für alle Tarife ausgerollt (<a href="https://blog.cloudflare.com/php-vulnerabilities-waf-protection/" target="_blank" rel="noopener" class="underline decoration-line underline-offset-2 hover:text-ink">Cloudflare-Blog</a>).
          CrowdSec veröffentlichte eigene virtuelle Patches und zählte in den ersten 24 Stunden über 450 Angreifer. Für rund die Hälfte der PHP-Websites gibt es
          laut CrowdSec kein vollständiges offizielles Update, weil sie auf älteren PHP-Versionen laufen
          (<a href="https://www.crowdsec.net/blog/php2shell-virtual-patching" target="_blank" rel="noopener" class="underline decoration-line underline-offset-2 hover:text-ink">CrowdSec-Blog</a>).
          Entschieden wird jeweils bei einem Unternehmen. Bei Schild entsteht derselbe Schutz ohne Zentrale:
        </p>
        <ul class="mt-8 grid gap-x-10 gap-y-6 md:grid-cols-2 lg:grid-cols-3">
          <li v-for="v in vpatch" :key="v.title" class="border-t border-line pt-4">
            <h3 class="font-semibold">{{ v.title }}</h3>
            <p class="mt-1 text-sm leading-relaxed text-slate">{{ v.text }}</p>
          </li>
        </ul>
        <p class="mt-8 max-w-2xl text-sm leading-relaxed text-ink">
          <strong>Was ein virtueller Patch nicht kann:</strong> die Lücke schließen. Er verschafft Zeit bis zum Update und deckt nur den bekannten Angriffsweg ab.
          Das Dashboard erinnert dich deshalb weiter an das Update.
        </p>
        <p class="mt-6 text-sm text-slate">
          Das Gateway gibt es schon heute:
          <NuxtLink to="/#installieren" class="font-semibold text-link hover:underline">Installieren <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="labs" class="border-b border-line bg-mist" aria-labelledby="labs-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="labs-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Was in den Labs automatisch läuft und was Menschen tun</h2>
        <div class="mt-8 grid gap-6 md:grid-cols-2">
          <div class="rounded-xl border border-line bg-white p-6">
            <h3 class="font-semibold">Automatisch</h3>
            <ul class="mt-4 space-y-2 text-sm text-slate">
              <li v-for="x in labWork.auto" :key="x" class="flex gap-2"><span class="text-signal-deep" aria-hidden="true">→</span>{{ x }}</li>
            </ul>
          </div>
          <div class="rounded-xl border border-line bg-white p-6">
            <h3 class="font-semibold">Menschen</h3>
            <ul class="mt-4 space-y-2 text-sm text-slate">
              <li v-for="x in labWork.human" :key="x" class="flex gap-2"><span class="text-signal-deep" aria-hidden="true">→</span>{{ x }}</li>
            </ul>
          </div>
        </div>
        <dl class="mt-10 grid gap-x-10 gap-y-6 md:grid-cols-3">
          <div class="border-t border-line pt-4">
            <dt class="font-semibold">Im Prototyp gebaut</dt>
            <dd class="mt-1 text-sm leading-relaxed text-slate">Bündeln, Regelvorschlag, Probelauf, menschliche Freigabe, Mitzeichnung und Verteilung, im Testlabor gemessen. Die erste Version des Schild Gateways nimmt keine Regeln aus dem Netz an. Das Netz kommt später als weitere Regelquelle dazu.</dd>
          </div>
          <div class="border-t border-line pt-4">
            <dt class="font-semibold">Noch nicht gebaut</dt>
            <dd class="mt-1 text-sm leading-relaxed text-slate">Exploits automatisch in der Sandbox nachstellen und KI-gestützte Analyse. Bis dahin prüfen Menschen die Vorschläge mit den Testberichten.</dd>
          </div>
          <div class="border-t border-line pt-4">
            <dt class="font-semibold">Aufwand und Finanzierung</dt>
            <dd class="mt-1 text-sm leading-relaxed text-slate">Wie viel Zeit ein Lab pro Woche braucht, messen wir im Betrieb auf eigenen Projekten. Labs betreiben Organisationen mit eigenem Interesse wie Hoster, Hochschulen und CERTs, dazu kommt ein Referenz-Lab des Trägers. Wegen k von n muss nicht jedes Lab rund um die Uhr wach sein.</dd>
          </div>
        </dl>
        <p class="mt-8 text-sm text-slate">
          Mehr zu den Lab-Servern (geplant):
          <NuxtLink to="/doku#labs" class="font-semibold text-link hover:underline">Dokumentation <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>
    <section id="netz" class="border-b border-line" aria-labelledby="netz-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="netz-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Das Netz in Aktion</h2>
        <p class="mt-3 max-w-2xl leading-relaxed text-slate">
          Was passiert, wenn eine Website ein neues Muster sieht, zum Durchklicken. Mit erfundenen Beispieldaten.
        </p>
        <div class="mt-10">
          <SchildNetwork />
        </div>
        <p class="mt-6 text-sm text-slate">
          Lokale Vertrauenslisten, signierte Bewertungen, Föderation zwischen Labs, Nachrichtenformate:
          <NuxtLink to="/doku/konzept/21-architektur-v1" class="font-semibold text-link hover:underline">Architektur V1 im Detail</NuxtLink>
        </p>
        <p class="mt-2 text-sm text-slate">
          Architektur und Bedrohungsmodell:
          <NuxtLink to="/doku/konzept/18-manipulation-und-poisoning" class="font-semibold text-link hover:underline">Manipulation und Poisoning <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <!-- STATE AND ROADMAP -->
    <section id="fahrplan" class="border-b border-line bg-mist" aria-labelledby="fahrplan-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="fahrplan-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Stand und Fahrplan</h2>
        <p class="mt-3 max-w-2xl leading-relaxed text-pretty text-slate">
          Das Schild Gateway ist als Alpha veröffentlicht und läuft bei uns im Live-Betrieb. Labs und Relays gibt es bisher nur als Prototyp im Testlabor.
          Für die Alpha suchen wir Partner, die das Gateway auf eigenen Servern ausprobieren: Hoster, Agenturen, Open-Source-Projekte und alle, die selbst Websites betreiben.
        </p>
        <ol class="mt-10 grid gap-px overflow-hidden rounded-xl border border-line bg-line md:grid-cols-2 lg:grid-cols-4">
          <li v-for="r in rollout" :key="r.nr" class="flex flex-col bg-white p-6" :class="r.nr === 1 ? 'bg-signal-tint' : ''">
            <p class="flex items-center gap-2 text-sm font-semibold" :class="r.nr === 1 ? 'text-signal-deep' : 'text-slate'">
              <span v-if="r.nr === 1" class="size-2 rounded-full bg-signal" aria-hidden="true" />{{ r.when }}
            </p>
            <h3 class="mt-2 text-lg font-semibold">{{ r.title }}</h3>
            <p class="mt-2 flex-1 text-sm leading-relaxed text-pretty text-slate">{{ r.text }}</p>
            <p v-if="r.mode" class="mt-4 font-mono text-xs text-slate">{{ r.mode }}</p>
          </li>
        </ol>
        <p class="mt-8 text-sm text-slate">
          Was bisher gebaut und gemessen wurde, Schritt für Schritt:
          <NuxtLink to="/ueber#changelog" class="font-semibold text-link hover:underline">Was bisher geschah →</NuxtLink>
        </p>
        <p class="mt-2 text-sm text-slate">
          Was wir jetzt brauchen:
          <NuxtLink to="#kontakt" class="font-semibold text-link hover:underline">Mitmachen <span aria-hidden="true">→</span></NuxtLink>
        </p>
      </div>
    </section>

    <section id="faq" class="border-b border-line" aria-labelledby="faq-title">
      <div class="mx-auto max-w-6xl px-5 py-20 sm:px-8 lg:py-24">
        <h2 id="faq-title" class="text-2xl font-bold tracking-tight sm:text-3xl">Fragen zum Netz</h2>
        <FaqList class="mt-8" :groups="faq" />
      </div>
    </section>

    <MitmachenSection />
  </div>
</template>
