package gate

import (
	"net/http"
	"strings"
)

// dropTunnelUpgrades removes every protocol upgrade but WebSocket from a
// request on its way to the backend (D43). A backend that answers 101 opens a
// tunnel, and schild sees none of the bytes in it: `Upgrade: h2c` would carry
// whole requests past the rules (MVP-26 measurement, finding 4). The request
// itself goes on: an upgrade is an offer, and the backend answers without it.
// WebSocket stays, because Livewire and Reverb need it; its handshake went
// through the rules like any request, its frames are not inspected.
func dropTunnelUpgrades(h http.Header) {
	upgrades, settings := h["Upgrade"], h["Http2-Settings"]
	if len(upgrades) == 0 && len(settings) == 0 {
		return
	}
	kept := ""
	for _, v := range upgrades {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); kept == "" && strings.EqualFold(tok, "websocket") {
				kept = tok
			}
		}
	}
	h.Del("Http2-Settings")
	if kept != "" {
		h.Set("Upgrade", kept)
	} else {
		h.Del("Upgrade")
	}
	var conn []string
	for _, v := range h["Connection"] {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" || strings.EqualFold(tok, "http2-settings") || (kept == "" && strings.EqualFold(tok, "upgrade")) {
				continue
			}
			conn = append(conn, tok)
		}
	}
	if len(conn) > 0 {
		h.Set("Connection", strings.Join(conn, ", "))
	} else {
		h.Del("Connection")
	}
}
