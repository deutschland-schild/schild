package config

import (
	"net/netip"

	"github.com/deutschland-schild/schild/contract"
)

// Cluster makes this gateway one node of a group that shares its state from
// node to node (MVP-27, D103, contracts/cluster.md). Off by default.
type Cluster struct {
	Enabled bool `json:"enabled"`
	// Listen is host:port of the mesh listener.
	Listen string `json:"listen"`
	// Advertise is host:port under which the other nodes reach it; empty:
	// Listen.
	Advertise         string `json:"advertise"`
	AllowPublicListen bool   `json:"allow_public_listen"`
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
	adv, err := netip.ParseAddrPort(c.Address())
	if err != nil || adv.Port() == 0 || adv.Addr().IsUnspecified() {
		return contract.Errf(contract.CodeConfig, "cluster.advertise: host:port under which the other nodes reach this node is required when cluster.listen binds every address")
	}
	return nil
}
