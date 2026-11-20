package hostagent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/keygen"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
)

// InitOptions of `schild-agent init`: an agent enrolled by explicit public
// key in the gateway's schild.yaml (host_check.agents.keys, contracts/
// host-check.md section 5, way 2) instead of a one-time code.
type InitOptions struct {
	Dir         string
	GatewayURL  string
	GatewayName string
	Pin         string
	// KeyFile is an existing key file (seed format) to use; empty creates a
	// new key <dir>/agent.key (mode 0600, never overwritten).
	KeyFile  string
	KeyID    string // default <hostname>/agent/<yyyy-mm>
	Hostname string
	Now      func() time.Time
	Out      io.Writer
}

// Init writes agent.json without contacting the gateway and prints what the
// gateway's schild.yaml needs (keyid, public_key, hostname). The agent's
// reports are accepted once that entry is in schild.yaml and schild was
// restarted; until then the gateway answers `signature`.
func Init(o InitOptions) (*State, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if !idRe.MatchString(o.GatewayName) {
		return nil, fmt.Errorf("gateway name %q must be the gateway's node_name", o.GatewayName)
	}
	host := strings.ToLower(o.Hostname)
	if host == "" {
		h, _ := os.Hostname()
		host = strings.ToLower(h)
	}
	if !hostRe.MatchString(host) {
		return nil, fmt.Errorf("hostname %q does not fit the contract; pass --hostname", host)
	}
	// Validates URL and pin; no connection is made.
	cl, err := NewClient(o.GatewayURL, o.Pin)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(StateFile(o.Dir)); err == nil {
		return nil, fmt.Errorf("%s exists: this host is already set up; remove the directory to start again with a new key", StateFile(o.Dir))
	}
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, err
	}
	keyid := o.KeyID
	if keyid == "" {
		if o.KeyFile != "" {
			return nil, errors.New("--keyid is required with --key")
		}
		short := strings.SplitN(host, ".", 2)[0]
		keyid = short + "/agent/" + now().UTC().Format("2006-01")
	}
	keyFile := o.KeyFile
	var pub ed25519.PublicKey
	if keyFile == "" {
		keyFile = filepath.Join(o.Dir, "agent.key")
		k, err := keygen.NewSigningKey(keyFile, keyid, "")
		if err != nil {
			return nil, err
		}
		pub = k.Public
		fmt.Fprintf(o.Out, "agent key %s created in %s (mode 0600, stays on this host)\n", keyid, keyFile)
	} else {
		abs, err := filepath.Abs(keyFile)
		if err != nil {
			return nil, err
		}
		keyFile = abs
		s, err := keys.LoadSigner(keyid, keyFile)
		if err != nil {
			return nil, err
		}
		pub = s.Public()
		if keys.Release && keys.IsTestKey(keyid, pub) {
			return nil, errors.New("release builds refuse test keys")
		}
	}
	fp := Fingerprint(pub)
	st := &State{GatewayURL: cl.URL, GatewayName: o.GatewayName, Pin: strings.ToLower(o.Pin), KeyID: keyid, KeyFile: keyFile, Fingerprint: fp,
		Hostname: host, EnrolledAt: msg.FormatTime(now())}
	if err := saveState(o.Dir, st); err != nil {
		return nil, err
	}
	fmt.Fprintf(o.Out, "fingerprint: %s\nadd this agent to host_check.agents.keys in the gateway's schild.yaml and restart schild there:\n"+
		"  - keyid: %s\n    public_key: %s\n    hostname: %s\nthen start `schild-agent run` here.\n", fp, keyid, keys.FormatPublicKey(pub), host)
	return st, nil
}
