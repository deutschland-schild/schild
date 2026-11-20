---
short: Zugriffsregeln
group: Wie
description: "Eine Regelliste je Website: URL-Bereiche sperren, nur für eigene Adressen und DynDNS-Namen freigeben, später mit Passkey-Login. Entwurf."
---

# Zugriffsregeln pro URL-Bereich

**Status:** ENTWURF (2026-10-31), noch nicht gebaut, keine Entscheidung des Initiators.

**Kurz:** Jede Website bekommt eine geordnete Regelliste: Wenn Pfad und Absender passen, dann sperren, durchlassen oder protokollieren. Die erste passende Regel entscheidet. Eigene Adressen und DynDNS-Namen stehen in benannten Listen, die Regeln wirken vor der WAF und laufen im Dashboard, in der Datei und über die Agent-API. Der Login mit Passkey kommt als spätere Aktion in dieselbe Liste. Offen sind die vier Entscheidungen am Ende.

## Problem

`/admin` soll für die Welt zu sein und für das Büro offen, auch wenn das Büro eine wechselnde Adresse hat. Das geht heute nur mit festen IPs im Caddyfile. Dafür brauchst du ein Deployment, und der DynDNS-Name zuhause passt dort nicht hinein. Die Allowlist löst DynDNS-Namen zwar auf, sie nimmt Adressen aber von Sperren aus und kennt keine Pfade. Der Entwurf [`protect`](13-technik-kompakt.md#formulare-und-passwortschutz-entwurf) und [MVP-14](../../tests/specs/MVP-14-access-lock.yaml) kennen Pfade, nur als Passwortschutz und ohne Reihenfolge.

**Hypothese:** Eine einzige Liste deckt Sperren, Freigaben, später Login und Notfall-Sperre ab. Wer eine Regel in Cloudflare angelegt hat, findet sich sofort zurecht.

## Vorbild und Abweichungen

Cloudflare prüft eigene WAF-Regeln der Reihe nach; eine Aktion wie Block beendet die Prüfung. Jede Regel besteht aus Ausdruck und Aktion. In Cloudflare Access gilt: Include ist ODER, Exclude ist NICHT, die erste passende Allow- oder Block-Regel entscheidet. (Quellen: [WAF custom rules](https://developers.cloudflare.com/waf/custom-rules/), [Actions](https://developers.cloudflare.com/ruleset-engine/rules-language/actions/), [Access policies](https://developers.cloudflare.com/cloudflare-one/policies/access/), geprüft am 2026-10-31.)

| Punkt | Cloudflare | Schild |
| --- | --- | --- |
| Reihenfolge | von oben nach unten | gleich, die erste passende Regel entscheidet immer |
| Bedingung | eigene Ausdruckssprache | feste Felder plus `unless`, keine Sprache |
| Skip der WAF | Aktion in der Liste | gibt es hier nicht, siehe unten |
| Login | eigenes Produkt (Access) | Aktion in derselben Liste, Stufe 3 |
| Daten | laufen über Cloudflare | bleiben auf dem eigenen Server |

## Die Regel

```yaml
access_lists:                     # local only, never sent or distributed
  office:
    - { cidr: 203.0.113.0/28, label: "Office" }
    - { host: home.example-dyndns.net, label: "Home office", expires: 2026-12-31T00:00:00Z }

access_rules:
  - name: "Admin only from own networks"
    site: app.example
    when: { path: ["/admin", "/admin/*"] }
    unless: { list: [office] }
    then: block
  - name: "Staging for the agency until November"
    site: staging.example
    when: { path: ["/*"] }
    unless: { list: [office] }
    then: block
    expires: 2026-11-30T00:00:00Z
```

Im Dashboard liest sich das als Satz: **Wenn** Pfad `/admin/*` **außer** Liste Büro, **dann** sperren.

**Bedingungen in `when` und `unless`:** `path`, `method`, `list`, `cidr`; ab Stufe 2 `country` und `bot`. Mehrere Felder gelten zusammen (UND), mehrere Werte in einem Feld gelten alternativ (ODER). `unless` greift, wenn seine Felder zutreffen. Das reicht für die Fälle oben, und nur für diese Felder lässt sich die Vorschau verlässlich rechnen.

**Header sind keine Bedingung.** `User-Agent` oder `Referer` schreibt der Absender selbst. Eine Freigabe darauf wäre keine Freigabe.

**Aktionen:**

| Aktion | Wirkung | Stufe |
| --- | --- | --- |
| `block` | ruhige Sperrseite mit 403, die Anfrage erreicht die App nicht | 1 |
| `allow` | beendet die Liste; WAF, Limits und Verhalten laufen weiter | 1 |
| `log` | zählt und protokolliert, die Liste läuft weiter | 1 |
| `challenge` | Rechenaufgabe, sobald es die Browser-Prüfung gibt | 2 |
| `login` | Passkey am Gateway, siehe Stufe 3 | 3 |
| `maintenance` | Wartungsseite mit 503, ersetzt „Nur für Interne“ aus MVP-14 | 4 |

`allow` braucht die Ausnahme vor einem Bereich: `/wp-admin/admin-ajax.php` steht als `allow` über der Sperre von `/wp-admin/*`.

## Entscheidungen im Entwurf

- **Die Listen sind von der Allowlist getrennt.** Die Allowlist nimmt Adressen von Sperren aus, mit `bypass_waf` sogar von der WAF. Wer das Büro für `/admin` freigibt, soll damit nichts anderes abschalten. Eine Adresse kann in beiden stehen, die Auflösung von DynDNS-Namen ist dieselbe.
- **Kein Skip der WAF.** Regeln, die nicht passen, gehören als Ausnahme nach `rules.d`, gezielt je Regel-ID. Ein Klick „WAF aus für `/api/*`“ wäre der leichteste Weg, den Schutz zu verlieren.
- **Position in der Anfrage.** Nach Client-Adresse, vor Verhalten, Limits und WAF. Die Allowlist öffnet keine Tür: Auch `bypass_waf` läuft durch die Liste. Eine gesperrte Anfrage kostet keine WAF-Arbeit und liest keinen Body.
- **Nur die geprüfte Client-Adresse zählt** (`trusted_proxies`, [G5](18-manipulation-und-poisoning.md)), nie ein ungeprüftes `X-Forwarded-For`.
- **Treffer sind keine Bedrohung.** Regel-Treffer erzeugen keine Signale, gehen nie an Labs und zählen nicht für `path_probing`. Sonst sperrt das Verhalten jemanden aus dem Team, der mit falscher Adresse durch den Admin klickt. Wer eine Sperre gegen Crawler will, bekommt sie weiter über die Probe-Pfade.
- **Änderungen wirken sofort**, ohne Neustart. Der Regelsatz wird pro Anfrage einmal gelesen (atomarer Zeiger), wie bei der WAF. Das Regelwerk ist kein Teil von Caddy; DynDNS, Länder und Ereignisse liegen ohnehin im Gate.
- **Nur der Betreiber schreibt.** Dashboard, Datei, Agent-Token. Labs und Netz können nie eine Regel setzen oder lösen.

## Woran eine Pfadregel scheitern kann

Eine Regel gilt für den Pfad, den Schild sieht. Die App kann denselben Bereich unter anderen Schreibweisen erreichen. Das ist der gefährlichste Teil des Konzepts, und er wird vor dem ersten Einsatz gemessen.

| Weg | Antwort des Entwurfs |
| --- | --- |
| `//admin`, `/%61dmin`, `/ADMIN`, `/x/../admin`, `/admin/.`, `/admin;x`, `\admin` | Vergleich auf dem normalisierten Pfad, Groß- und Kleinschreibung egal; ein Pfad, der sich nicht eindeutig normalisieren lässt, zählt als Treffer |
| `/index.php/admin` | PHP-Apps routen auch so; die Vorlagen für PHP nehmen diese Form mit auf |
| `X-Original-URL`, `X-Rewrite-URL` | entfernt, sobald eine Website Pfadregeln hat |
| `X-HTTP-Method-Override`, `_method` | die App kann die Methode umschreiben; eine Regel mit `method` zeigt dazu einen Hinweis |
| Aufrufe außerhalb des Pfads, z. B. `/livewire/update` | deckt die Regel nicht ab; die Vorlage nennt solche Pfade, das Login der App bleibt nötig |
| direkter Zugang zum Backend, Website ohne `schild` | Schild sieht die Anfrage nicht; `schild ingress validate` lehnt eine Regel für eine Site ohne Directive ab |

## Fehlerfälle

| Fall | Verhalten |
| --- | --- |
| Regel ungültig | beim Speichern abgelehnt; in der Datei: kein Start, wie bei `schild.yaml`, damit kein Bereich still offen steht |
| DNS für einen Namen fällt aus | letzte gute Adressen gelten bis zu 24 h weiter, danach zählt der Name nicht mehr (Tür zu); das Dashboard warnt |
| Adresse wechselt | die Freigabe hinkt um das Prüfintervall nach, bei der Einrichtung zeigt das Dashboard den Abstand |
| Regel läuft ab | die ganze Regel endet, eine Sperre öffnet also den Bereich; das Dashboard erinnert vorher daran |
| Eintrag einer Liste läuft ab | nur diese Adresse verliert die Freigabe, die Tür bleibt für sie zu |
| Rollback auf normalen Caddy | alle Regeln sind weg. `schild access export --caddyfile` schreibt die Sperren mit festen Adressen in einen Block für die Rollback-Datei. DynDNS und Login lassen sich so nicht abbilden, das steht in der Ausgabe |
| Gate-Fehler bei der Prüfung | 503 auf einem Pfad, den eine Regel erfasst; nie durchlassen |

## Wirkung im Modus `observe`

Regeln wirken in jedem Gateway-Modus. Der Modus steuert, was Schild selbst erkennt; eine Regel hat der Betreiber ausdrücklich gesetzt. Eine Tür, die im Lernbetrieb still offen steht, wäre die schlechtere Überraschung. Limits verhalten sich schon so. Zum Ausprobieren steht jede einzelne Regel auf `state: on | log | off`.

## Dashboard

Unter jeder Website ein Bereich **Zugriff**, gleich aufgebaut wie die Website-Ansicht:

- Liste mit Name, Satz, Treffer in 24 h, Ablauf; Reihenfolge per Ziehen.
- **Vorschau vor dem Speichern:** Aus den letzten Anfragen zeigt das Dashboard, wie viele die Regel getroffen hätte und welche Adressen darunter sind, etwa „14 Anfragen von 3 Adressen in den letzten 24 h“.
- **Warnung bei Selbstaussperrung:** „Deine letzte Admin-Sitzung kam von einer Adresse, die diese Regel sperrt.“ Das Dashboard selbst bleibt erreichbar, es hängt nicht an der Website.
- **Vorlagen:** Admin-Bereich absichern, WordPress-Login (mit `admin-ajax.php`), Laravel/Filament, Staging, Notfall: einen Pfad sperren. Jede Vorlage bringt ihre bekannten Ausnahmen mit und nennt, was sie nicht abdeckt.
- „Meine Adresse hinzufügen“ schlägt die aktuelle Adresse vor, wie bei der Allowlist.

Kein zusätzliches Passwort beim Speichern, wie bei den übrigen Aktionen des Dashboards.

## Datei, Dashboard, Agent

**Zwei Herkünfte, keine Mischung.** Regeln aus `schild.yaml` stehen im Dashboard gesperrt ganz oben, Regeln aus Dashboard und API liegen im Speicher des Gateways und folgen darunter. So überschreibt niemand etwas still, und ein Deployment ändert keine Notfall-Regel.

**Agent-API:** `GET` und `PUT /agent/v0/access-rules`, beschrieben im OpenAPI-Dokument, das Schild selbst ausliefert, eigener Scope `access:write`. Ein Agent kann in Sekunden einen verwundbaren Pfad sperren; `expires` ist dabei Pflicht. Jede Änderung landet als Ereignis im Protokoll (wer, was, wann).

**Messbar:** `schild_access_rule_hits_total{rule,action}`, Ereignisse gesampelt und lokal.

## Stufen

**Stufe 1, sofort nutzbar:** `path`, `method`, `list`, `cidr`, `unless`; `block`, `allow`, `log`; `expires`; Listen mit DynDNS; `schild.yaml`, Dashboard mit Vorschau, API, Export für den Rollback.

**Stufe 2:** `country` und `bot` aus den lokalen Daten, Vorlagen je App, `challenge`.

**Stufe 3, Login:** Aktion `login`, in `unless` kombinierbar: „eigenes Netz oder Passkey“.

- Der Login läuft auf einer Login-Domain des Betreibers, denn ein Passkey gilt nur für seine Domain. Mit einem Einmal-Ticket kommt die Person zurück zur Website und bekommt dort ein `__Host-`-Cookie, das Schild vor dem Backend entfernt. So reicht ein Passkey für alle Websites.
- Zugänge verwaltest du im Dashboard, sie sind aber vom Dashboard-Konto getrennt: Das Dashboard bleibt nie öffentlich, und wer `/admin` öffnen darf, bekommt keine Rechte an Schild.
- Nur Passkeys, kein Passwort, damit öffentlich nichts zu erraten ist. Das ändert MVP-14, dort sind Passkeys ausgeklammert.

**Stufe 4:** `maintenance` und Sperre der ganzen Website, einschließlich Verhalten bei Ausfall aus MVP-14.

## Akzeptanz und Tests

| Prüfung | Kriterium |
| --- | --- |
| Pfad-Tricks und alle Methoden aus MVP-14, dazu die Tabelle oben | 0 Anfragen erreichen die App, Beleg im Log der App |
| Freigabe per CIDR und DynDNS | Zugang von innen, nach Adresswechsel innerhalb des Prüfintervalls |
| Abgelaufene Regel, abgelaufener Listeneintrag | wirkt ab der nächsten Anfrage nicht mehr |
| `bypass_waf` auf gesperrtem Pfad | gesperrt |
| Unabhängige Messung | wie immer nicht durch die Bauenden |
| Latenz | Zielwert im Budget von M1, ZU PRÜFEN mit 256 Regeln |

**Abbruch (Vorschlag, Entscheidung beim Initiator):** Eine nicht freigegebene Anfrage erreicht einen gesperrten Pfad, eine abgelaufene Freigabe gewährt noch Zugang, oder etwas außerhalb des Betreibers ändert eine Regel.

## Risiken und Umkehrbarkeit

- **Falsche Sicherheit:** Eine Regel ersetzt kein Login der App und deckt nur den angegebenen Pfad ab. Das Dashboard schreibt „gesperrt für alle außer Büro“, nie „geschützt“.
- **Parser-Unterschiede:** Neue App-Routen oder Frameworks können neue Schreibweisen bringen. Die Vorlagen brauchen Pflege.
- **Aussperren:** Eine falsche Regel kann eine ganze Website sperren. Vorschau, `log` und `schild access disable <rule>` per CLI fangen das auf.
- **Umkehrbar:** Regel löschen genügt, die Änderung braucht keinen Neustart. Das Caddyfile bleibt unberührt.

## Offene Entscheidungen

1. **Modus:** Regeln wirken auch in `observe`? Empfehlung: ja.
2. **Antwort auf `block`:** 403 mit ruhiger Seite oder 404, das den Bereich verbirgt? Empfehlung: 403 als Standard, 404 als Option je Regel, weil die Sperrseite Mitarbeitenden die eigene Adresse zeigen kann.
3. **Herkunft der Regeln:** Datei oben gesperrt, Dashboard darunter? Empfehlung: ja.
4. **Spec:** Stufe 1 als eigener Vertrag vor MVP-14, MVP-14 baut dann darauf auf? Empfehlung: ja.
