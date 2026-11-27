// Public changelog shown as a timeline on /ueber. Newest first. Only facts that are built, measured or decided –
// no partners, no amounts, nothing private. Milestones and releases, one or two sentences each.
import { REPO_URL } from './release'

// link: where the full text of an entry stands, for a release its notes on GitHub (they are CHANGELOG.md, in English).
export type ChangelogEntry = { date: string, title: string, items: string[], link?: { href: string, label: string } }

// One entry per release of the gateway: the version, one or two sentences on what it brings, its notes on GitHub.
const release = (date: string, version: string, text: string): ChangelogEntry => ({
  date,
  title: `Schild Gateway ${version}`,
  items: [text],
  link: { href: `${REPO_URL}/releases/tag/v${version}`, label: 'Änderungen auf GitHub' },
})

export const CHANGELOG: ChangelogEntry[] = [
  release('2026-11-27', '0.1.0-alpha.7', 'Im Cluster ist jede Sperre ein eigener Eintrag unter ihrer Vorfallnummer, und eine Freigabe gilt auf allen Servern. Zertifikate lassen sich per DNS-Challenge bei Hetzner holen, auch Wildcards. Sperren im Cluster sind nicht mit 0.1.0-alpha.6 verträglich.'),
  release('2026-11-23', '0.1.0-alpha.6', 'Zwei bis sechzehn Gateways laufen als Cluster und teilen Sperren, Einstellungen, Logins, Zertifikate und Zähler direkt untereinander. Ein einzelnes Gateway läuft wie bisher.'),
  release('2026-11-21', '0.1.0-alpha.5', 'Der Server-Check richtet sich mit einem Befehl ein, und seine Befunde stehen in einer durchsuchbaren Liste. Die Agent-API ist ab Werk an und hat einen Schalter im Dashboard.'),
  release('2026-11-21', '0.1.0-alpha.4', 'Die Prüfsummen eines Release sind mit cosign signiert, und die Anleitung beschreibt die Installation als Paket über apt.'),
  release('2026-11-20', '0.1.0-alpha.3', 'Jedes Release enthält jetzt Pakete für Debian und Ubuntu, für amd64 und arm64.'),
  release('2026-11-20', '0.1.0-alpha.2', 'Die Prüfung von Anfragen, die Erkennung von Anmeldeversuchen und die Übergabe der Sperren an die Firewall sind gehärtet.'),
  {
    date: '2026-11-20',
    title: 'Schild Gateway 0.1.0-alpha.1: Open Source',
    items: [
      'Das Schild Gateway ist Open Source unter MIT: Code, Doku und Tests auf GitHub, dazu ein Docker-Image und ein Binary für Linux.',
      'Neu in dieser Version: die Kurze Prüfung im Browser mit Under-Attack-Modus, einstellbare Schwellen für Szenarien und ein eigener Schalter für jedes Limit.',
    ],
    link: { href: `${REPO_URL}/releases/tag/v0.1.0-alpha.1`, label: 'Änderungen auf GitHub' },
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
