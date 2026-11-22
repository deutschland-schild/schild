package config

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
)

// Cluster makes this gateway one node of a group that shares its state from
// node to node (MVP-27, D103, contracts/cluster.md). Off by default.
type Cluster struct {
	Enabled bool `json:"enabled"`
	// Name is the name of this node in its group (see MemberName).
	Name string `json:"name"`
	// NameFromHost: the node is named after its host (see MemberName), for
	// a deployment that writes the same schild.yaml to every node.
	NameFromHost bool `json:"name_from_host"`
	// Listen is host:port of the mesh listener.
	Listen string `json:"listen"`
	// Advertise is host:port under which the other nodes reach it; empty:
	// Listen.
	Advertise         string `json:"advertise"`
	AllowPublicListen bool   `json:"allow_public_listen"`
	// SecretFile sets the group up by configuration: the same secret on
	// every node admits it at its start (contract/cluster admit.go).
	SecretFile string `json:"secret_file"`
	// Peers are the mesh addresses of the other nodes, where a node that
	// knows no member yet finds the group.
	Peers []string `json:"peers"`
	// Drain is how a node leaves traffic when it stops.
	Drain ClusterDrain `json:"drain"`
}

// ClusterDrain: the readiness answer turns to 503, the node serves on for
// DelayS, then lets running requests finish within GraceS.
type ClusterDrain struct {
	DelayS *int `json:"delay_s"`
	GraceS *int `json:"grace_s"`
}

// Delay and Grace with their defaults (15 s, 30 s).
func (d ClusterDrain) Delay() time.Duration {
	if d.DelayS == nil {
		return 15 * time.Second
	}
	return time.Duration(*d.DelayS) * time.Second
}

func (d ClusterDrain) Grace() time.Duration {
	if d.GraceS == nil {
		return 30 * time.Second
	}
	return time.Duration(*d.GraceS) * time.Second
}

// Address is what the other nodes dial: Advertise, else Listen.
func (c *Cluster) Address() string {
	if c.Advertise != "" {
		return c.Advertise
	}
	return c.Listen
}

func (c *Cluster) check() error {
	if !c.Enabled {
		return nil
	}
	ap, err := netip.ParseAddrPort(c.Listen)
	if err != nil || ap.Port() == 0 {
		return contract.Errf(contract.CodeConfig, "cluster.listen: an IP address and a port are required with cluster.enabled")
	}
	a := ap.Addr().Unmap()
	if !c.AllowPublicListen && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
		return contract.Errf(contract.CodeConfig, "cluster.listen %s is no private or loopback address: put the mesh on a private network, or set cluster.allow_public_listen", c.Listen)
	}
	if c.Name != "" && c.NameFromHost {
		return contract.Errf(contract.CodeConfig, "cluster.name and cluster.name_from_host: set one of them")
	}
	for _, p := range c.Peers {
		if ap, err := netip.ParseAddrPort(p); err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() {
			return contract.Errf(contract.CodeConfig, "cluster.peers: %q is no address and port of another node", p)
		}
	}
	if len(c.Peers) > 0 && c.SecretFile == "" {
		return contract.Errf(contract.CodeConfig, "cluster.peers needs cluster.secret_file: without the group secret a node joins with schild cluster join")
	}
	adv, err := netip.ParseAddrPort(c.Address())
	if err != nil || adv.Port() == 0 || adv.Addr().IsUnspecified() {
		return contract.Errf(contract.CodeConfig, "cluster.advertise: host:port under which the other nodes reach this node is required when cluster.listen binds every address")
	}
	return nil
}

var memberNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// MemberName is the name a node takes in its group: cluster.name when set;
// with cluster.name_from_host the first label of the host name in lower
// case when that is a valid name; in every other case node_name.
func (s *Site) MemberName(hostname string) string {
	if s.Cluster.Name != "" {
		return s.Cluster.Name
	}
	if s.Cluster.NameFromHost {
		h, _, _ := strings.Cut(strings.ToLower(hostname), ".")
		if memberNameRe.MatchString(h) {
			return h
		}
	}
	return s.NodeName
}
