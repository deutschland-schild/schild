# Humanizer for Deutschland-Schild

`SKILL.md` and `LICENSE` are vendored unchanged from [blader/humanizer](https://github.com/blader/humanizer) (MIT, Siqi Chen), commit `8c307f367c91`. This file adds the project overrides. Where they conflict with `SKILL.md`, this file wins; `AGENTS.md` wins over both.

Use it for every public German text: website copy (`site/app`), docs (`docs/concept`, `docs/brand`, `docs/stories`), UI copy.

## Overrides for German copy

- **Dashes (§8):** reduce strongly, but not to zero. Keep the en dash for ranges ("2–3", "Mo–Fr") and where German punctuation needs one. No dash as a universal connector between clauses.
- **Contrasts (§1):** keep a contrast when it corrects a belief readers actually hold. Our core contrasts stay: "Regeln statt IP-Listen", "Labs statt Zentrale", "CrowdSec teilt IP-Adressen über eine Firma. Schild teilt geprüfte Regeln über unabhängige Labs."
- **Required wording stays:** "Grundschutz aktiv", "pseudonym" (never "anonym"), no unqualified "geschützt" or "sicher", "TECH-Coach", "Traffic" for network traffic (never "Verkehr"), product names (Schild Gateway, Schild Agent, Schild Dashboard, Schild Lab, Relay). See [docs/brand/01-marke.md](../../docs/brand/01-marke.md).
- **Do not change:** headings that other documents or the specs in `tests/specs/` cite, anchors, IDs (`SEC-01`, `US-HA-01`, `T29`, `E4`, `D28` …), status markers (ENTSCHIEDEN, ENTWURF, OFFEN …), numbers, sources, links, code, field names.
- **"Kurz:" blocks** at the top of concept docs are a docs rule (docs/AGENTS.md), not a staged opener; keep them.
- German stock phrases to treat like §12/§13: "spannend", "nahtlos", "ganzheitlich", "maßgeschneidert", "Mehrwert schaffen", "auf ein neues Level", "Game Changer", "im Herzen von", "Ehrlich gesagt:", "Wichtig:" as a standalone opener, "Kurzum", "Unterm Strich".
- Bold labels (§19): fine for scannable lists and tables; not before every sentence of running text.
