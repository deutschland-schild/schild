package preflight

import (
	"fmt"

	"github.com/deutschland-schild/schild/contract/config"
)

// Site checks schild.yaml: every agent key that is not revoked (host_check,
// v0.3) and the trusted CAs of the process. The gateway holds no signing key
// (D72).
func Site(cfg *config.Site) *Report {
	r := New("schild")
	r.Site(cfg)
	return r
}

// Site adds the checks of schild.yaml to r.
func (r *Report) Site(cfg *config.Site) {
	if hc := cfg.HostCheck; hc != nil {
		for _, k := range hc.Agents.Keys {
			if k.Revoked {
				continue
			}
			r.PublicKey("host_check.agents.keys", k.KeyID, k.PublicKey)
		}
	}
	r.TrustAnchors()
}

// Lab checks lab.yaml: the lab's signing keys, the admitted site keys,
// the peer labs' keys, its serving certificate and the trusted CAs.
func Lab(cfg *config.LabConfig) *Report {
	r := New("schild-lab")
	r.Lab(cfg)
	return r
}

// Lab adds the checks of lab.yaml to r.
func (r *Report) Lab(cfg *config.LabConfig) {
	for _, k := range cfg.Keys {
		r.PrivateKeyFile("keys", k.KeyID, k.PrivateKeyFile)
	}
	for _, c := range cfg.Clients {
		if c.Revoked {
			continue
		}
		r.PublicKey("clients", c.KeyID, c.PublicKey)
	}
	for _, p := range cfg.Peers {
		for _, k := range p.Keys {
			r.PublicKey(fmt.Sprintf("peers[%s].keys", p.Lab), k.KeyID, k.PublicKey)
		}
	}
	if cfg.TLS != nil {
		r.ServingCert("tls.cert_file", cfg.TLS.CertFile)
	}
	r.TrustAnchors()
}

// Relay checks a relay: its serving certificate (SCHILD_RELAY_TLS_CERT)
// and the CAs it trusts for upstream TLS. Relays hold no signing keys.
func Relay() *Report {
	r := New("schild-relay")
	r.Relay()
	return r
}

// Relay adds the relay checks to r.
func (r *Report) Relay() {
	r.ServingCert("SCHILD_RELAY_TLS_CERT", r.Env("SCHILD_RELAY_TLS_CERT"))
	r.TrustAnchors()
}
