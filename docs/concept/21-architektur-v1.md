---
short: Architektur V1 (Föderation)
group: Wie
description: "Technische Umsetzung V1: jeder Betreiber wählt seine Labs und Peers selbst, signierte Bewertungen und Reports, lokale Entscheidung statt globaler Sperrliste, Session-Modi, ACK-Semantik, Protobuf-Skizze, Kapazitätsmodell und Bauabschnitte."
---

# Architektur V1: föderiertes Scoring-Netz

**Status:** ENTWURF · Stand 25. Oktober 2026 · Grundlage: Architekturentwurf „Föderiertes WAF-Scoring-Netzwerk V1“, eingeordnet in die bisherigen Konzepte (13, 18, 20).

**Kurz:**

- Zwei Pfade: Client (Schild Gateway) → Lab und Lab ↔ Lab; die Regelverteilung über Relays steht in [Events und Geschwindigkeit](20-events-und-geschwindigkeit.md).
- Jede Website wählt ihre Labs, jedes Lab seine Peers; keine globale Sperrliste, mindestens 2 unabhängige Betreiber (Standard 3).
- Die WAF wartet nie auf ein Lab; der Lab-Eingang quittiert in Millisekunden (Ziel `EventAck` p99 < 50 ms), Analyse läuft asynchron.
- Standard ist unverkettbar (nur Signale über OHTTP); Bewertungen pro Ereignis nur im Scoring-Abo (Opt-in), dessen Transport noch offen ist.
- Abschnitt 2.1 listet die lokalen Ereignistypen; die Protobuf-Skizze (5.1) ist nicht implementierungsfertig.

## 1. Zielbild

**Leitprinzip:** Jeder Betreiber wählt seine Vertrauensbeziehungen selbst: **Jede Website** wählt ihre Labs, **jedes Lab** seine Peers. Nachrichten sind signiert, Bewertungen lokal, Maßnahmen werden nie global erzwungen. Keine Pflicht-Registry, keine globale Sperrliste, kein globaler Konsens: „Mindestens X Labs“ ist eine **lokale** Regel (`remote_rules.min_labs`, [Technik kompakt](13-technik-kompakt.md)), Untergrenze 2 unabhängige Betreiber (Standard 3).

Zwischen **Client und Schild Lab** gehen im Standard nur Signale (pseudonym, OHTTP); Sitzungen und Bewertungen pro Ereignis nur im Scoring-Abo (Opt-in, Abschnitt 13). Zwischen **Labs** gehen signierte Beobachtungen, Reputationshinweise, Korrekturen und Widerrufe.

**Nicht in V1:** EUDI/eID, staatliche Identitätsprüfung, globale Reputation, netzwerkweite Sperren, Browser-Fingerprints.

## 2. Begriffe und Vertrauensgrenzen

| Begriff | Bei uns | Bedeutung |
| --- | --- | --- |
| Client | Schild Gateway (`schild run`) gegenüber Labs und Relays | Reverse-Proxy mit WAF und isoliertem Signal-Prozess; seine IP ist kein Identitätsbeweis. |
| Scoring-Node / Peer | Schild Lab | Bewertet Signale; ein Peer ist ein Lab, dessen Meldungen ein anderes annehmen darf. |
| Operator | Betreiber | Rechtlich eigenständig; mehrere Labs eines Betreibers zählen einmal. |
| Request / Session | Anfrage / Sitzung | Beobachtung, kein Urteil; Sitzung = lokaler, befristeter Zusammenhang, keine Nutzeridentität. |
| Environment | Umgebung | System, Laufzeit, Anwendungen, Plugins, Versionen – für den lokalen Warnungsabgleich; verlässt den Server **nie**. |
| Event / Signal | Ereignis / Signal | Ereignis: alles, was Schild lokal notiert (2.1). Signal: das Wenige, das aus auffälligen Ereignissen an Labs geht ([`contracts/signal.md`](../../contracts/signal.md)). |
| Browser check | Prüfung im Browser | Zwischenseite mit Rechenaufgabe, ab Werk aus; **kein** Menschlichkeitsbeweis. |

### 2.1 Ereignisse: was lokal bleibt, was rausgeht (ENTWURF, 25.10.2026)

Typnamen `schild.<ding>.<verb>.v1` (CloudEvents, [Events und Geschwindigkeit](20-events-und-geschwindigkeit.md)); lokale Typen werden nie veröffentlicht. In der Oberfläche: **Ereignisse**, nicht „Request-Log“.

| Typ (lokal) | Wann | Geht etwas raus? |
| --- | --- | --- |
| `schild.request.evaluated.v1` | Request bewertet (Unauffälliges gesampelt) | bei Auffälligkeit ein Signal |
| `schild.request.blocked.v1` | Request abgewehrt, mit Vorfallnummer | Signal |
| `schild.request.unblocked.v1` | Freischaltung über die Vorfallnummer | bei Fehlalarm `schild.feedback` |
| `schild.session.flagged.v1` | Sitzung überschreitet eine Schwelle (Tempo, Fehlerrate, Pfadfolge) | nein; Ausnahme: Scoring-Abo |
| `schild.environment.changed.v1` | Umgebung ändert sich | **nie** |
| `schild.environment.anomaly.v1` | Auffälligkeit am Server, z. B. hohe CPU ohne Besucher | freiwillig nur die grobe Zustandsstufe |
| `schild.advisory.assessed.v1` | Warnung lokal abgeglichen: betroffen · abgefedert · wahrscheinlich nicht betroffen · nicht übers Web erreichbar · unklar (nie „alles gut“) | nein; später optional eine aggregierte Zählung |
| `schild.rule.received.v1`, `.adopted.v1`, `.dropped.v1` | Netzregel empfangen, übernommen, zurückgezogen | nein |

**An Labs (OHTTP):** nur `schild.signal`, `schild.feedback`. **Vom Relay-Strom:** `schild.dist.checkpoint`, `schild.dist.withdrawal`, Warnungen der Labs (`schild.advisory.published.v1`, ZU PRÜFEN).

Signaturen belegen Urheberschaft, **nicht** Wahrheit: Ein kompromittierter Client kann Events erfinden ([Manipulation und Poisoning](18-manipulation-und-poisoning.md)).

## 3. Übersicht

```text
visitor / bot
      |
      v
reverse proxy (Caddy) + Coraza / OWASP CRS
      |
      +--> request analyzer --+
      |                       |
      +--> session tracker ---+--> isolated signal process (unprivileged)
      |                       |         |
      +--> optional           |         | persistent, client-initiated
           browser check -----+         | HTTP/2 streams (see 5.1)
                                        v
                              +---------+---------+
                              |         |         |
                            Lab A     Lab B     Lab C
                              |         |         |
                              +-- local scoring --+
                              |         |         |
                              <--- federation ---->
                              (chosen peers only)
```

Die WAF wartet **nie** auf ein Lab; Bewertungen wirken ab der nächsten Anfrage.

## 4. Identität und lokale Vertrauenslisten

### 4.1 Client → Lab

Ed25519-Schlüsselpaar je Client, `client_id` aus dem öffentlichen Schlüssel. Zulassung je Lab, meist über einen **Bürgen** (Hoster, Verband, [Manipulation und Poisoning](18-manipulation-und-poisoning.md)). IP und ASN dienen nur Rate-Limits, nie als Identität.

### 4.2 Lab → Lab

Jedes Lab hat eine kryptografische Identität und eine **Betreiber-ID**. Peers trägt der Betreiber ausdrücklich ein (Discovery optional), mit `accept_from`, `share_with`, `trust_weight` und `observe_only`. Empfangen heißt **nicht** übernehmen. Website und Lab entscheiden getrennt, in zwei Dateien:

```yaml
# schild.yaml (website) – which labs score my events
scoring:
  labs:
    - id: lab-a
      endpoint: https://lab-a.example:443
      public_key: ed25519:BASE64_PUBLIC_KEY_A
      operator: operator-a
    - id: lab-b
      endpoint: https://lab-b.example:443
      public_key: ed25519:BASE64_PUBLIC_KEY_B
      operator: operator-b
    - id: lab-c
      endpoint: https://lab-c.example:443
      public_key: ed25519:BASE64_PUBLIC_KEY_C
      operator: operator-c
  min_independent_operators: 3   # signals always go to at least 3 Labs of different operators (concept 13)
  aggregation: median
```

```yaml
# lab.yaml (lab) – which peers I talk to
identity:
  operator: operator-example
  lab: lab-a
federation:
  peers:
    - lab: lab-b
      endpoint: https://lab-b.example:443
      public_key: ed25519:BASE64_PUBLIC_KEY_B
      operator: operator-b
      accept_from: true
      share_with: true
      trust_weight: 0.7
    - lab: lab-c
      endpoint: https://lab-c.example:443
      public_key: ed25519:BASE64_PUBLIC_KEY_C
      operator: operator-c
      accept_from: true
      share_with: false
      trust_weight: 0.3
      observe_only: true   # reports are logged, never acted on
```

## 5. Transport und Nachrichtenfluss

**V1-Vorschlag:** persistente gRPC-Bidi-Streams über HTTP/2 und TLS 1.3, aufgebaut vom Client bzw. vom initiierenden Lab, Protobuf, zstd optional (Verhältnis zu SSE und OHTTP: **Abschnitt 13**, Nachrichten: 5.1). Kein Polling; Reconnect mit Backoff und Jitter; 16-Byte-UUID je Event, Batch-ID, Sequenznummer.

**ACK-Semantik.** `accepted` heißt dauerhaft übernommen, **nicht** fertig bewertet; ein Result-ACK heißt lokal übernommen. Dedupe über `(sender_id, message_id)` und Event-UUID; Replay-Fenster und Resume-Cursor begrenzt. **At-least-once mit idempotenter Verarbeitung**, kein „exactly once“.

### 5.0 Schneller Eingang, Analyse im Hintergrund (ENTWURF, 25.10.2026)

Erst quittieren, dann arbeiten, auch in einer Angriffswelle.

```text
Client ──► Eingang (hot path) ──► ACK in Millisekunden
             │  prüfen: Signatur, Token, Größe, Rate-Limit
             │  dedupe, in Warteschlange schreiben
             ▼
           Warteschlange (dauerhaft, begrenzt, mit Prioritäten)
             ├─► Bewertung (Regeln, Statistik)          Sekunden
             ├─► Föderation mit anderen Labs (async)     Sekunden bis Minuten
             └─► KI-Analyse, Sandbox, Nachstellen        Minuten bis Stunden
                    └─► Ergebnis als ResultBatch bzw. Regel über SSE/TUF
```

1. **Im Eingang nur Billiges:** Signatur, Token, Limits, Dedupe, einreihen, `EventAck`; keine KI, keine Föderation. **Ziel:** `EventAck` p99 < 50 ms, unabhängig von der Last dahinter (Lasttest, [Testkonzept](14-testkonzept.md)), in getrennten Prozessen.
2. **Volle Warteschlange: früh ablehnen** (`ServerControl.retry_after_ms`); der Client puffert oder nutzt seine anderen Labs (mindestens drei). Priorität: neue Muster, dann Wiederholungen, dann Stichproben.
3. **Föderation und KI asynchron** mit eigenen Quoten. Für den Client gilt: Netzanteil am p99-Aufschlag = 0 ms ([Events und Geschwindigkeit](20-events-und-geschwindigkeit.md)).

### 5.1 Protobuf-Skizze

```protobuf
syntax = "proto3";
package schild.v1;

service ScoringService {
  rpc Connect(stream ClientMessage) returns (stream ServerMessage);
}
service FederationService {
  rpc Exchange(stream FederationMessage) returns (stream FederationMessage);
}

message ClientMessage {
  oneof payload {
    EventBatch events = 1;
    SessionUpdateBatch sessions = 2;
    ResultAck result_ack = 3;
  }
}
message ServerMessage {
  oneof payload {
    EventAck event_ack = 1;
    ResultBatch results = 2;
    ServerControl control = 3;
  }
}
message SecurityEvent {
  bytes uuid = 1;               // exactly 16 bytes
  uint64 timestamp_ms = 2;
  repeated uint32 rule_ids = 3;
  uint32 anomaly_score = 4;
  bytes sanitized_features = 5;
  bytes session_id = 6;         // optional, scoped to one website
}
message EventBatch {
  bytes batch_id = 1;
  repeated SecurityEvent events = 2;
}
message EventAck {
  bytes batch_id = 1;
  repeated bytes accepted_uuids = 2;
  repeated bytes rejected_uuids = 3;
}
message SessionUpdate {
  bytes session_id = 1;
  uint64 sequence = 2;
  uint64 updated_at_ms = 3;
  uint32 request_count = 4;
  uint32 waf_anomaly_count = 5;
  uint32 http_4xx_count = 6;
  reserved 7;                   // was browser_check: nothing about the browser check leaves the server (concept 24 §10)
  bytes sanitized_features = 8;
}
message SessionUpdateBatch {
  bytes batch_id = 1;
  repeated SessionUpdate sessions = 2;
}
message Evaluation {
  bytes event_uuid = 1;
  bytes payload_hash = 2;
  uint32 risk_score = 3;        // 0..100, semantics defined per scale version
  uint32 model_version = 4;
}
message ResultBatch {
  uint64 sequence = 1;
  uint64 expires_at_ms = 2;
  repeated Evaluation evaluations = 3;
  bytes signature = 4;
}
message ResultAck { uint64 last_committed_sequence = 1; }
message ServerControl {
  uint32 retry_after_ms = 1;
  uint32 max_batch_events = 2;
}

enum ReportType {
  REPORT_UNSPECIFIED = 0;
  INVALID_MESSAGES = 1;
  RATE_LIMIT_ABUSE = 2;
  REPLAY_ATTEMPTS = 3;
  SUSPECTED_COMPROMISE = 4;
  KEY_REVOKED = 5;
  FALSE_POSITIVE_CORRECTION = 6;
}
message ReputationReport {
  bytes report_id = 1;
  bytes issuer_lab_id = 2;
  bytes issuer_operator_id = 3;
  bytes subject_client_id = 4;
  uint64 observed_from_ms = 5;
  uint64 observed_until_ms = 6;
  ReportType type = 7;
  uint32 severity = 8;
  uint32 confidence = 9;
  bytes evidence_hash = 10;
  uint64 expires_at_ms = 11;
  bytes supersedes_report_id = 12;
  bytes signature = 13;
}
message FederationReportBatch {
  bytes batch_id = 1;
  repeated ReputationReport reports = 2;
}
message FederationAck {
  bytes batch_id = 1;
  repeated bytes accepted_report_ids = 2;
}
message CorrectionBatch {
  bytes batch_id = 1;
  repeated ReputationReport corrections = 2;
}
message PeerControl { uint32 retry_after_ms = 1; }
message FederationMessage {
  oneof payload {
    FederationReportBatch reports = 1;
    FederationAck ack = 2;
    CorrectionBatch corrections = 3;
    PeerControl control = 4;
  }
}
```

**Nicht implementierungsfertig:** Es fehlen Authentifizierung, Schlüsselrotation, Versionen, Feldvalidierung, Session-ACKs, Report-Typen und Wiederaufnahme. Signiert wird im DSSE-Umschlag mit Domain Separation, Absender, Version, Zeitfenster und Empfängerbindung, weil rohes Protobuf nicht kanonisch ist.

## 6. Request- und Session-Bewertung

- **Request Analyzer:** WAF-Regeln, Pfad- und Methodenklassen, Status, grobe TLS-/HTTP-Merkmale. **Session Tracker:** Rate, Pfadfolgen, Fehlerraten, WAF-Treffer, Verfall.
- **human_score (Stufe 0, immer):** aus Headern und Anfragerhythmus, nur im Arbeitsspeicher, nie gesendet ([Datenschutzkonzept, Abschnitt 10](24-datenschutz.md)). **Prüfung im Browser (Stufe 1, ab Werk aus):** sichtbare Zwischenseite, Freigabe-Cookie ohne Kennung ([`tests/specs/MVP-12`](../../tests/specs/MVP-12-human-score.yaml)).

### 6.1 Modi je Website

Seit 27.10.2026 gilt: Cookies ohne Kennung, nur sichtbare Prüfung, nichts aus dem Browser verlässt den Server.

| Modus | Verhalten | Standard |
| --- | --- | --- |
| `passive` | nur passive Merkmale (Stufe 0), Sitzungen nur im Arbeitsspeicher über IP-Präfix und User-Agent-Klasse, Minuten | ja, immer |
| Prüfung im Browser | `human.challenge.mode`: aus · bei Verdacht · immer | aus |

Gleiche IP heißt nicht gleiche Session. Ein fehlender Browsernachweis ist kein Sperrgrund, eine bestandene Prüfung keine WAF-Ausnahme. **Nichts über die Prüfung geht an Labs**, auch nicht im Scoring-Abo (Feld 7 in 5.1 reserviert); aggregierte Bestehensquoten sind ZU PRÜFEN (Frage 5 im Datenschutzkonzept). Keine Browser-IDs, Gerätemerkmale (Canvas, WebGL, Audio, Fonts) oder Biometrie.

## 7. Föderierter Austausch zwischen Labs

Ein Lab meldet **Beobachtungen** und kennzeichnet Deutungen als Verdacht. Reports (`ReputationReport` in 5.1) tragen Evidenz-Hash, Konfidenz und Ablauf, nie Rohlogs; Korrekturen verweisen per `supersedes_report_id` auf den alten Report.

### 7.1 Lokale Vertrauensentscheidung je Lab

Signatur, Ablauf, Schema, Zulassung, Replay prüfen → Ursprung einem **Betreiber** zuordnen (Weiterleitungen sind keine Stimmen) → nach Peer-Policy gewichten oder verwerfen, eigene Beobachtungen bevorzugen → Maßnahmen nur nach eigener Policy (Prüfung, Quoten, befristete Sperre). Ein fremder Report allein erzwingt nie eine Sperre.

### 7.2 Schutz vor Reputationsmanipulation

Kopien deduplizieren, Labs eines Betreibers zählen einmal, selbst gemeldeter „guter Traffic“ wertet nichts auf, Bewertungen verfallen. **Die Zuverlässigkeit eines Melders und das Risiko eines Clients sind getrennte Größen.** Verdacht ist kein Nachweis.

## 8. Ergebnisse robust zusammenführen (Client)

Bewertungen desselben Events von Labs verschiedener Betreiber führt der Client z. B. über den **Median** zusammen; ohne Ergebnisse gilt die lokale Policy. Gegen abgesprochene Betreiber hilft der Median **nicht**. Deshalb blocken Netzpunkte nie allein, und IPs werden nie verteilt ([Manipulation und Poisoning](18-manipulation-und-poisoning.md)).

## 9. Sicherheit und Betrieb

| Ebene | Maßnahmen |
| --- | --- |
| **Client** | isolierter, unprivilegierter Signal-Prozess; begrenzte Queues und Nutzlasten; Quoten, Timeouts, Backpressure, Circuit Breaker – ein bösartiges Lab darf den Proxy nicht destabilisieren. |
| **Lab** | Zulassung je Client-Schlüssel; Limits für Verbindungen, CPU, Speicher, Parsing; Prioritätswarteschlangen; getrennte Ressourcen für Scoring und Föderation. |
| **Föderation** | Quoten je Peer, Report-TTL, Weiterleitungslimit, Replay-Schutz, Betreiber-Dedupe, Audit-Log. |
| **Datenschutz** | Merkmale minimieren, kurz aufbewahren, Session-IDs nur je Website. Hashes stabiler Kennungen sind **nicht** automatisch anonym. |

## 10. Kapazitätsmodell

1 Mio. Clients mit je 5 Lab-Verbindungen ergeben **5 Mio. parallele Streams**, bei 1 Event pro Sekunde **5 Mio. Bewertungen pro Sekunde** plus Föderation. Batching senkt nur Overhead; Kosten werden getrennt gemessen ([Testkonzept](14-testkonzept.md)).

**Deshalb geht nicht jeder Request ins Netz**, sondern nur lokal Auffälliges (Score ≥ 40, neue Muster, Session-Ausreißer) und eine kleine Stichprobe als Vergleich. Unverbindliche Startwerte für Lasttests: Event-Batches bis 64 Events / 32 KiB / 200 ms; Result-Batches bis 128 Ergebnisse / 64 KiB / 100 ms.

## 11. Umsetzung in Bauabschnitten

| Bauabschnitt | Inhalt |
| --- | --- |
| **1 – Client/Lab-Prototyp** | Signal-Prozess, Stream, Authentifizierung, Batching, signierte Ergebnisse, ACK, Dedupe, Reconnect, lokale Fallback-Policy |
| **2 – Sessions** | passiver Session-Tracker, Sequenznummern; optional Prüfung im Browser (lokal) |
| **3 – Föderations-Prototyp** | Lab-Identitäten, Peers und Quoten, signierte Reports, Korrekturen, TTL, Trust-Policies |
| **4 – Härtung und Skalierung** | mehrere Betreiber, Angriffs-, Replay- und Lasttests, Threat-Model-Review, Schlüsselrotation, Interoperabilität |

Bauabschnitte sind keine Phasen der Einführung ([Produkt, UX und Onboarding](03-produkt-und-ux.md)). Zuordnung (ZU PRÜFEN): Bauabschnitte 1–2 in der Alpha (eigene Projekte und Partner, nur unsere Labs, die Partner betreiben keine); Bauabschnitte 3–4 in der Phase „Externe Labs“ (v1).

## 12. Offene Entscheidungen vor dem Coding

1. Semantik und Versionierung der Score-Skala.
2. Kanonisch signiertes Nachrichtenformat, Schlüsselrotation.
3. Zulassung und Registrierung je Lab.
4. ACK- und Resume-Garantien, Speicherlimits.
5. Trennung von Event-ID, Session-ID und Client-Identität.
6. Teilbare Session-Merkmale.
7. Betreiber-Unabhängigkeit und Peer-Vertrauen.
8. Ab wann Reports lokale Einschränkungen erlauben.
9. Fälschlich verdächtigte Clients, Widerrufe.
10. Benchmarks für Batching, Streams, Scoring-Last.

## 13. Abgleich mit den bisherigen Festlegungen

| Thema | Bisher | Architektur V1 | Einordnung |
| --- | --- | --- | --- |
| Konsens | `min_labs` | kein globaler Konsens | **passt:** `min_labs` war schon lokal. Labs stimmen über **Muster und Regeln** ab, nie über Besucher. |
| Sperren | Empfehlungen, Modus entscheidet | keine netzwerkweite Sperre | **passt**, auch Reports über Clients wirken nur lokal. |
| Regelverteilung | SSE über Relays, TUF, ein Log je Lab | nicht behandelt | **bleibt** ([Events und Geschwindigkeit](20-events-und-geschwindigkeit.md)). |
| Signale Client → Lab | OHTTP, unverkettbar, Bürgen-Tokens (ARC) | gRPC-Stream mit Client-Schlüssel, Ergebnis zurück | **Zielkonflikt**, siehe unten. |
| Lab ↔ Lab | ein signierter Feed je Lab (SSE + mTLS) | gRPC-Bidi, explizite Peers, `trust_weight` | **passt inhaltlich**; Transport offen, Feed-Modell bleibt für Regeln. |
| Bewertung pro Event | nur Muster | Remote-Score pro Event, Median | **neu**, sinnvoll für Session-Kontext und Hoster-Labs. |
| Signaturformat | DSSE + CloudEvents | eigener Envelope | **passt:** DSSE ist so ein Envelope. |

**Der Zielkonflikt.** Ein Stream mit Client-Schlüssel und Rückkanal braucht eine wiedererkennbare Identität, und genau die verhindert OHTTP. Beides geht nicht auf einem Kanal.

**Vorschlag (ENTWURF, zu entscheiden):** zwei Betriebsarten nach Wahl des Betreibers.

- **Unverkettbar (Standard):** Signale über OHTTP mit Bürgen-Token, kein Rückkanal pro Event; Schutz über Regeln aus dem Relay-Strom.
- **Scoring-Abo (Opt-in):** Anmeldung mit Schlüssel bei Labs der Wahl, Bewertungen pro Event und Session zurück – vor allem beim eigenen Hoster-Lab ([Technik kompakt](13-technik-kompakt.md)). Besucher-IPs gehen auch hier nie raus (E4).

Transport für das Scoring-Abo: gRPC-Bidi oder HTTP/2-Streaming mit DSSE-JSON ohne Protobuf-Codegen, Entscheidung nach Messung ([Testkonzept](14-testkonzept.md), B03/B05). OFFEN.
