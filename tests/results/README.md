# Measurement results

Reports and result records of the measurements: `REPORT.md`, `measurements.md`, `ux-review.md` and the `MVP-xx*.json` result files (format: `contracts/results.schema.json`).

The dated reports of single measurements and reviews (`MVP-19-messung-2026-10-28.md`, `messung-2026-10-29-abend.md`, `security-review-2026-10-30.md`, `storage-bounds-audit-2026-10-29.md` and the like) are working records of the prototype and not part of this repository. Decisions, specs and code comments still name them as the trigger of a change; what was decided from them stands in [contracts/DECISIONS.md](../../contracts/DECISIONS.md).

The raw material of the measurements (logs, screenshots, dumps, generated configs) is not part of this repository. Where a report names a path such as `D36-nachmessung/ui/`, `MVP-21-messung/…`, `messung-2026-10-29-abend/…`, `MVP-26-messung-2026-10-30/…`, `ui-*-2026-10-29/`, `stage3-baseline/raw/` or `runs/…`, it names where that material lay during the measurement. The findings and numbers in the reports stand as written.

Kept besides the reports:

- `MVP-19-messung/env/`: the environment (Caddyfiles, configs, scripts) of the MVP-19 measurements, sourced by the scripts in `tests/testlab/measure/ingress-load/load/`.
- `stage3-baseline/`: the report (`README.md`) and its seven result files; the artifacts they list under `raw/` are not included.
- `waiting-page-2026-10-29/variant-a.html`: the chosen waiting page draft, the source named in `contracts/waiting-page.md`.

`runs/`, `tmp/` and `ux/` are local output directories of the test lab scripts and are ignored by git.
