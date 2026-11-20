# Schild Gateway – Dokumentation

Die Doku zum Schild Gateway, dem Teil von Deutschland-Schild, den es heute schon gibt. Die Website zeigt diese Dateien unter `/doku/gateway/<datei>`, als ersten Abschnitt der Dokumentation (Reihenfolge in `site/app/utils/hub.ts`).

| Datei | Inhalt |
| --- | --- |
| [00-installieren.md](00-installieren.md) | Voraussetzungen, die zwei Fälle (Schild als Caddy-Distribution oder hinter nginx, Apache oder einem Load Balancer) auf drei Wegen (Docker, Binary mit systemd, Docker Compose), erste Schritte bis zum Dashboard, der Weg wieder heraus |
| [01-funktionen.md](01-funktionen.md) | Was das Gateway kann, Funktion für Funktion, mit den drei Regel-Repositories (OWASP CRS, CrowdSec Hub, eigene Regeln) |
| [02-betrieb.md](02-betrieb.md) | Einbauen, Konfiguration und Dashboard, aktualisieren, Agent-API einschalten, was sperrt, Regeln einstellen, Ausfall und Rückbau, Daten, Befehle, bekannte Grenzen |

**Regeln für diese Dateien:**

- Hier steht nur, was gebaut ist und im Gateway ohne Labs läuft. Quelle der Wahrheit ist [gateway/README.md](../../gateway/README.md); ändert sich dort etwas, wird es hier nachgezogen.
- Geplantes steht nur im Abschnitt „Geplant“ am Ende von `01-funktionen.md`, klar als geplant benannt.
- Labs, Relays, Signale und Freigaben aus dem Netz gehören nicht in diese Doku (erste Gateway-Version ohne Labs). Sie stehen in den Konzeptdateien unter „Lab-Server“ und „Relays“.
- Sprache und Begriffe: [brand/01-marke.md](../brand/01-marke.md), Glossar; vor dem Veröffentlichen [skills/humanizer](../../skills/humanizer/SCHILD.md) anwenden.
