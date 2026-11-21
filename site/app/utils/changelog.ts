// Public changelog shown as a timeline on /ueber. Newest first. Only facts that are built, measured or decided –
// no partners, no amounts, nothing private. Milestones only, one line of detail each.
import { RELEASE_URL, RELEASE_VERSION } from './release'

// link: where the full text of an entry stands, for a release its notes on GitHub (they are CHANGELOG.md, in English).
export type ChangelogEntry = { date: string, title: string, items: string[], link?: { href: string, label: string } }

export const CHANGELOG: ChangelogEntry[] = [
  {
    date: '2026-11-20',
    title: `Schild Gateway ${RELEASE_VERSION} veröffentlicht`,
    items: [
      'Das Schild Gateway ist Open Source unter MIT: Code, Doku und Tests auf GitHub, dazu ein Docker-Image und ein Binary für Linux.',
      'Neu in dieser Version: die Kurze Prüfung im Browser mit Under-Attack-Modus, einstellbare Schwellen für Szenarien und ein eigener Schalter für jedes Limit.',
      '0.1.0-alpha.2 folgt am selben Tag. Sie härtet die Prüfung von Anfragen, die Erkennung von Anmeldeversuchen und die Übergabe der Sperren an die Firewall.',
      '0.1.0-alpha.3 bringt Pakete für Debian und Ubuntu: Jedes Release enthält jetzt eine .deb-Datei für amd64 und arm64.',
      '0.1.0-alpha.4 folgt am 21. November: Die Prüfsummen eines Release sind mit cosign signiert, und die Anleitung beschreibt die Installation als Paket über apt.',
    ],
    link: { href: RELEASE_URL, label: 'Alle Änderungen auf GitHub' },
  },
  {
    date: '2026-11-18',
    title: 'Sperren erreichen die Firewall des Servers',
    items: [
      'Alle gesperrten Adressen stehen in einer Liste. Auf Wunsch übernimmt Schild sie in die Firewall des Servers (nftables).',
    ],
  },
  {
    date: '2026-11-06',
    title: 'Regeln aus drei Quellen',
    items: [
      'OWASP CRS, öffentliche virtuelle Patches aus dem CrowdSec Hub und eigene Regeln, jede Quelle mit eigenem Schalter.',
      'Die erste Version des Gateways kommt ohne Labs und Relays aus. Beide sind geplant.',
    ],
  },
  {
    date: '2026-11-02',
    title: 'Erster Live-Betrieb',
    items: [
      'Das Gateway läuft vor einem eigenen Projekt des Initiators, zuerst nur beobachtend.',
    ],
  },
  {
    date: '2026-10-28',
    title: 'Prototyp im Testlabor gemessen',
    items: [
      'Gateway, Lab und Relay laufen als Docker-Images im Testlabor. Gemessen wird getrennt vom Bau, mit festen Eingaben und einem Befehl je Messung.',
    ],
  },
  {
    date: '2026-10-23',
    title: 'Landingpage online',
    items: [
      'Konzept v1 und diese Website mit lebendiger Dokumentation online.',
    ],
  },
]
