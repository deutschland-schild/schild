// Package peers connects a lab with the labs in lab.yaml peers[]:
//
//   - it follows each peer's feed (GET /v0/stream) like a relay does and
//     imports bundles and withdrawals that carry k distinct operators, so
//     every lab serves the newest state of the channel (labs are relays too);
//   - it polls each peer's GET /v0/collecting and offers what the peer signed
//     to this lab's operators for co-signing (dashboard);
//   - it delivers this lab's co-signatures to the proposing lab
//     (POST /v0/signatures).
//
// A slow or absent peer never touches ingest or scoring (concept 21 §5.0).
package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/lab/internal/feed"
	"github.com/deutschland-schild/schild/lab/internal/rules"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// Peer is the dashboard view of one peer (API Peer).
type Peer struct {
	Lab         string     `json:"lab"`
	Operator    string     `json:"operator"`
	Endpoint    string     `json:"endpoint"`
	AcceptFrom  bool       `json:"accept_from"`
	ShareWith   bool       `json:"share_with"`
	TrustWeight float64    `json:"trust_weight"`
	ObserveOnly bool       `json:"observe_only"`
	Status      string     `json:"status"`
	LastSeen    *time.Time `json:"last_seen"`
	Independent bool       `json:"independent"`
}

type peerState struct {
	cfg      config.Peer
	sub      *upstream.Subscriber
	lastSeen time.Time
}

// Manager runs the peer connections.
type Manager struct {
	Lab, Operator string
	Engine        *rules.Engine
	Trust         *keys.TrustStore
	Client        *http.Client
	Log           *slog.Logger
	Now           func() time.Time
	PollEvery     time.Duration
	// Signer is this lab's rules key: it signs GET /v0/collecting so the
	// peer answers (contracts v0.1, cosign.md).
	Signer *keys.Signer

	mu    sync.Mutex
	peers map[string]*peerState
}

// New returns a manager for the configured peers.
func New(lab, operator string, ps []config.Peer, eng *rules.Engine, trust *keys.TrustStore, client *http.Client, log *slog.Logger) *Manager {
	m := &Manager{Lab: lab, Operator: operator, Engine: eng, Trust: trust, Client: client, Log: log, Now: time.Now, PollEvery: 10 * time.Second, peers: map[string]*peerState{}}
	for _, p := range ps {
		st := &peerState{cfg: p}
		if p.AcceptFrom == nil || *p.AcceptFrom {
			lab := p.Lab
			st.sub = &upstream.Subscriber{Base: strings.TrimRight(p.Endpoint, "/"), Client: client, Name: m.Lab, Log: log,
				OnEvent: func(ev upstream.Event) { m.onEvent(lab, ev) },
				// Contracts v0.2: the stream subscription is signed like
				// /v0/collecting, so the peer lists this lab as kind
				// peer_lab instead of trusting the X-Schild-Relay name.
				Authorize: func(req *http.Request) error {
					if m.Signer == nil {
						return nil // unsigned: the peer lists this lab as a relay
					}
					return peerauth.SetHeader(req, m.Signer, m.Lab, lab, nil, m.Now())
				}}
		}
		m.peers[p.Lab] = st
	}
	return m
}

// Run follows peers until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, st := range m.peers {
		if st.sub == nil {
			continue
		}
		wg.Add(2)
		go func(st *peerState) { defer wg.Done(); st.sub.Run(ctx) }(st)
		go func(st *peerState) { defer wg.Done(); m.pollLoop(ctx, st) }(st)
	}
	wg.Wait()
}

func (m *Manager) seen(lab string) {
	m.mu.Lock()
	if st := m.peers[lab]; st != nil {
		st.lastSeen = m.Now()
	}
	m.mu.Unlock()
}

func (m *Manager) onEvent(lab string, ev upstream.Event) {
	m.seen(lab)
	e := ev.Event
	switch e.Type {
	case stream.TypeCheckpoint, stream.TypeHeartbeat:
		env := e.Envelope
		if e.Type == stream.TypeHeartbeat {
			env = e.Checkpoint
		}
		res, err := verify.Signed(contract.KindCheckpoint, env, &verify.Context{Now: m.Now(), Trust: m.Trust, SkipState: true})
		if err != nil {
			m.Log.Warn("peer checkpoint rejected", "peer", lab, "err", err)
			return
		}
		if cp := res.Value.(*msg.Checkpoint); cp.Bundle.Version > 0 {
			m.Engine.NotePeerVersion(cp.Bundle.Version)
		}
	case stream.TypeBundle:
		env := []byte(e.Envelope)
		if e.Ref != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			b, err := upstream.Fetch(ctx, m.Client, ev.Upstream, e.Ref)
			cancel()
			if err != nil {
				m.Log.Warn("peer bundle fetch failed", "peer", lab, "err", err)
				return
			}
			env = b
		}
		if _, err := m.Engine.ImportPublished(contract.KindBundle, env, lab); err != nil {
			m.Log.Info("peer bundle not imported", "peer", lab, "err", err)
		}
	case stream.TypeWithdrawal:
		if _, err := m.Engine.ImportPublished(contract.KindWithdrawal, e.Envelope, lab); err != nil {
			m.Log.Info("peer withdrawal not imported", "peer", lab, "err", err)
		}
	}
}

func (m *Manager) pollLoop(ctx context.Context, st *peerState) {
	t := time.NewTicker(m.PollEvery)
	defer t.Stop()
	for {
		if err := m.Poll(ctx, st.cfg.Lab); err != nil {
			m.Log.Debug("peer collecting poll failed", "peer", st.cfg.Lab, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll fetches a peer's collecting items once and offers them to this lab.
func (m *Manager) Poll(ctx context.Context, lab string) error {
	m.mu.Lock()
	st := m.peers[lab]
	m.mu.Unlock()
	if st == nil {
		return fmt.Errorf("unknown peer %s", lab)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, strings.TrimRight(st.cfg.Endpoint, "/")+"/v0/collecting", nil)
	if err != nil {
		return err
	}
	if m.Signer == nil {
		return fmt.Errorf("no rules key to sign the request to %s", lab)
	}
	if err := peerauth.SetHeader(req, m.Signer, m.Lab, lab, nil, m.Now()); err != nil {
		return err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var page struct {
		Lab   string                 `json:"lab"`
		Items []rules.CollectingItem `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&page); err != nil {
		return err
	}
	m.seen(lab)
	for _, it := range page.Items {
		if it.Lab != lab || (it.Kind != string(contract.KindBundle) && it.Kind != string(contract.KindWithdrawal)) {
			continue
		}
		if err := m.Engine.OfferFromPeer(lab, contract.Kind(it.Kind), it.Envelope); err != nil {
			m.Log.Info("peer offer refused", "peer", lab, "kind", it.Kind, "err", err)
		}
	}
	return nil
}

// SendSignature implements rules.Courier.
func (m *Manager) SendSignature(peerLab string, kind contract.Kind, digest string, sig dsse.Signature) error {
	m.mu.Lock()
	st := m.peers[peerLab]
	m.mu.Unlock()
	if st == nil {
		return fmt.Errorf("unknown peer %s", peerLab)
	}
	return PostSignature(context.Background(), m.Client, st.cfg.Endpoint, kind, digest, sig)
}

// PostSignature delivers one co-signature to a lab feed.
func PostSignature(ctx context.Context, c *http.Client, endpoint string, kind contract.Kind, digest string, sig dsse.Signature) error {
	body, _ := json.Marshal(feed.SignatureRequest{Kind: string(kind), Digest: digest, Signature: sig})
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/v0/signatures", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// List returns the peers for the dashboard.
func (m *Manager) List() []Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	out := make([]Peer, 0, len(m.peers))
	for _, st := range m.peers {
		c := st.cfg
		p := Peer{Lab: c.Lab, Operator: c.Operator, Endpoint: c.Endpoint, AcceptFrom: c.AcceptFrom == nil || *c.AcceptFrom, ShareWith: c.ShareWith,
			TrustWeight: 0.5, ObserveOnly: c.ObserveOnly, Status: "unknown", Independent: c.Operator != m.Operator}
		if c.TrustWeight != nil {
			p.TrustWeight = *c.TrustWeight
		}
		if !st.lastSeen.IsZero() {
			t := st.lastSeen.UTC()
			p.LastSeen = &t
			switch age := now.Sub(st.lastSeen); {
			case age <= 45*time.Second:
				p.Status = "ok"
			case age <= stream.FreezeAfter:
				p.Status = "slow"
			default:
				p.Status = "down"
			}
		}
		out = append(out, p)
	}
	return out
}
