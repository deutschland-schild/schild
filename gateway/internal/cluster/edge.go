package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	contract "github.com/deutschland-schild/schild/contract/cluster"
)

// Edge is a member that only enforces: a balancer VM in front of the
// gateways that drops blocked addresses before they cost a gateway a
// handshake (`schild firewall run -group`, MVP-27). It has a key and a place
// in the member list like a gateway, and that is where the likeness ends:
// it listens on nothing, it writes no record, and a gateway answers it two
// things only: the member list, so it knows whom to ask, and what was
// registered for edges (OnEdgeAsk), the block list. No event, request,
// setting, login, certificate or key reaches it.
type Edge struct {
	n    *Node
	log  *slog.Logger
	last string // the gateway that answered last
	seen time.Time
}

// ErrNoEdge: the data directory is not the one of an edge.
var ErrNoEdge = errors.New("cluster: this node did not join as an edge (schild cluster invite -role edge, then schild cluster join ADDRESS CODE -edge)")

// OpenEdge loads the edge of a data directory.
func OpenEdge(dir string, log *slog.Logger) (*Edge, error) {
	if log == nil {
		log = slog.Default()
	}
	n, err := Open(Options{Dir: dir, Log: log})
	if err != nil {
		return nil, err
	}
	if role, _ := n.meta("role"); string(role) != contract.RoleEdge {
		n.Close()
		return nil, ErrNoEdge
	}
	return &Edge{n: n, log: log}, nil
}

// Close ends the edge's database.
func (e *Edge) Close() { e.n.Close() }

// ID and Name of the edge.
func (e *Edge) ID() string   { return e.n.ID() }
func (e *Edge) Name() string { return e.n.Name() }

type gateway struct {
	id, address string
	key         ed25519.PublicKey
}

func (e *Edge) gateways() []gateway {
	e.n.rmu.RLock()
	defer e.n.rmu.RUnlock()
	var out []gateway
	for _, m := range e.n.roster.Members() {
		if m.Removed || m.Member.Role != contract.RoleGateway {
			continue
		}
		key, _ := m.Member.Key()
		out = append(out, gateway{id: m.ID, address: m.Member.Address, key: key})
	}
	// The one that answered last first, the others in a fixed order.
	sort.Slice(out, func(i, j int) bool {
		if (out[i].id == e.last) != (out[j].id == e.last) {
			return out[i].id == e.last
		}
		return out[i].id < out[j].id
	})
	return out
}

// refresh takes the member list from a gateway, at most every 30 s.
func (e *Edge) refresh(ctx context.Context, g gateway, c *http.Client) {
	if time.Since(e.seen) < 30*time.Second {
		return
	}
	vec, err := e.n.vector()
	if err != nil {
		return
	}
	var resp syncResponse
	if err := postJSON(ctx, c, "https://"+g.address+pathSync, syncRequest{Group: e.n.group, Vector: vec}, &resp); err != nil {
		return
	}
	if _, err := e.n.take(resp.Records, resp.Covered); err == nil {
		e.seen = time.Now()
	}
}

// Ask asks the gateways of the group, one after the other, until one
// answers. A gateway that holds the edge for removed ends the search:
// ErrRemovedSelf.
func (e *Edge) Ask(ctx context.Context, kind string, body []byte, timeout time.Duration) ([]byte, error) {
	raw, err := json.Marshal(tellRequest{Kind: kind, Body: body})
	if err != nil {
		return nil, err
	}
	gws := e.gateways()
	if len(gws) == 0 {
		return nil, errors.New("cluster: the member list of this edge names no gateway")
	}
	var last error
	for _, g := range gws {
		key := g.key
		c := meshClient(e.n.cert, func(k ed25519.PublicKey) bool { return k.Equal(key) }, timeout)
		e.refresh(ctx, g, c)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+g.address+pathAsk, bytes.NewReader(raw))
		if err != nil {
			c.CloseIdleConnections()
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			c.CloseIdleConnections()
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		out, rerr := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBody+1))
		resp.Body.Close()
		c.CloseIdleConnections()
		switch {
		case resp.StatusCode == http.StatusGone:
			return nil, ErrRemovedSelf
		case resp.StatusCode != http.StatusOK:
			last = fmt.Errorf("gateway %s answered %s", g.address, resp.Status)
			continue
		case rerr != nil || len(out) > maxAnswerBody:
			last = fmt.Errorf("gateway %s: answer not read", g.address)
			continue
		}
		e.last = g.id
		return out, nil
	}
	return nil, last
}
