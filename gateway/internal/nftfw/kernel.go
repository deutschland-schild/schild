//go:build linux

package nftfw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Kernel is the table in the kernel, over netlink (no nft binary needed).
type Kernel struct{}

const (
	tableName = "schild"
	set4Name  = "blocked4"
	set6Name  = "blocked6"
	portsName = "web_ports"
	chainName = "prerouting"
)

func table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
}

func (Kernel) conn() (*nftables.Conn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("netlink: %w", err)
	}
	return c, nil
}

func exists(c *nftables.Conn) (bool, error) {
	ts, err := c.ListTables()
	if err != nil {
		return false, permission(err)
	}
	for _, t := range ts {
		if t.Family == nftables.TableFamilyINet && t.Name == tableName {
			return true, nil
		}
	}
	return false, nil
}

func permission(err error) error {
	if errors.Is(err, unix.EPERM) {
		return fmt.Errorf("%w: the firewall needs CAP_NET_ADMIN (docker: --cap-add NET_ADMIN)", err)
	}
	return err
}

// Ensure builds the table afresh in one transaction: the sets, the ports and
// one chain on prerouting (priority -150, before Docker's DNAT) that drops
// TCP and UDP to the web ports from the blocked clients. No policy drop.
func (k Kernel) Ensure() error {
	c, err := k.conn()
	if err != nil {
		return err
	}
	had, err := exists(c)
	if err != nil {
		return err
	}
	t := table()
	if had {
		c.DelTable(t)
	}
	c.AddTable(t)
	set4 := &nftables.Set{Table: t, Name: set4Name, KeyType: nftables.TypeIPAddr, HasTimeout: true}
	set6 := &nftables.Set{Table: t, Name: set6Name, KeyType: nftables.TypeIP6Addr, Interval: true, HasTimeout: true}
	ports := &nftables.Set{Table: t, Name: portsName, KeyType: nftables.TypeInetService, Constant: true}
	for _, s := range []*nftables.Set{set4, set6} {
		if err := c.AddSet(s, nil); err != nil {
			return err
		}
	}
	if err := c.AddSet(ports, []nftables.SetElement{{Key: binary.BigEndian.AppendUint16(nil, 80)}, {Key: binary.BigEndian.AppendUint16(nil, 443)}}); err != nil {
		return err
	}
	accept := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{Name: chainName, Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle, Policy: &accept})
	for _, fam := range []struct {
		proto  byte
		offset uint32
		len    uint32
		set    *nftables.Set
	}{{unix.NFPROTO_IPV4, 12, 4, set4}, {unix.NFPROTO_IPV6, 8, 16, set6}} {
		for _, l4 := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam.proto}},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Lookup{SourceRegister: 1, SetName: ports.Name, SetID: ports.ID},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: fam.offset, Len: fam.len},
				&expr.Lookup{SourceRegister: 1, SetName: fam.set.Name, SetID: fam.set.ID},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}})
		}
	}
	return permission(c.Flush())
}

// Replace makes the sets hold exactly els, each with its timeout, in one
// transaction.
func (k Kernel) Replace(els []Element) error {
	c, err := k.conn()
	if err != nil {
		return err
	}
	t := table()
	set4, err := c.GetSetByName(t, set4Name)
	if err != nil {
		return fmt.Errorf("set %s: %w", set4Name, permission(err))
	}
	set6, err := c.GetSetByName(t, set6Name)
	if err != nil {
		return fmt.Errorf("set %s: %w", set6Name, permission(err))
	}
	c.FlushSet(set4)
	c.FlushSet(set6)
	var v4, v6 []nftables.SetElement
	for _, e := range els {
		p, err := netip.ParsePrefix(e.Client)
		if err != nil {
			a, aerr := netip.ParseAddr(e.Client)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		timeout := e.Timeout.Truncate(time.Second)
		if timeout < time.Second {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, nftables.SetElement{Key: p.Addr().AsSlice(), Timeout: timeout})
			continue
		}
		end, ok := after(p)
		v6 = append(v6, nftables.SetElement{Key: p.Masked().Addr().AsSlice(), Timeout: timeout})
		if ok {
			v6 = append(v6, nftables.SetElement{Key: end.AsSlice(), IntervalEnd: true})
		}
	}
	for i := 0; i < len(v4); i += 1000 {
		if err := c.SetAddElements(set4, v4[i:min(i+1000, len(v4))]); err != nil {
			return err
		}
	}
	for i := 0; i < len(v6); i += 1000 {
		if err := c.SetAddElements(set6, v6[i:min(i+1000, len(v6))]); err != nil {
			return err
		}
	}
	return permission(c.Flush())
}

// after is the first address after prefix p; ok false at the end of the
// address space.
func after(p netip.Prefix) (netip.Addr, bool) {
	b := p.Masked().Addr().As16()
	bits := p.Bits()
	// Add 1 at the last bit of the prefix.
	for i := bits - 1; i >= 0; i-- {
		byteI, bit := i/8, byte(1)<<(7-i%8)
		if b[byteI]&bit == 0 {
			b[byteI] |= bit
			for j := i + 1; j < bits; j++ {
				b[j/8] &^= byte(1) << (7 - j%8)
			}
			return netip.AddrFrom16(b), true
		}
	}
	return netip.Addr{}, false
}

// Held counts the clients the sets hold now (expired ones are gone).
func (k Kernel) Held() ([]Held, error) {
	c, err := k.conn()
	if err != nil {
		return nil, err
	}
	t := table()
	var out []Held
	for _, name := range []string{set4Name, set6Name} {
		s, err := c.GetSetByName(t, name)
		if err != nil {
			return nil, fmt.Errorf("set %s: %w", name, permission(err))
		}
		els, err := c.GetSetElements(s)
		if err != nil {
			return nil, permission(err)
		}
		for _, e := range els {
			if e.IntervalEnd {
				continue
			}
			a, ok := netip.AddrFromSlice(e.Key)
			if !ok {
				continue
			}
			client := a.Unmap().String()
			if a.Is6() && !a.Is4In6() {
				client = netip.PrefixFrom(a, 64).String()
			}
			out = append(out, Held{Client: client, Expires: e.Expires})
		}
	}
	return out, nil
}

// Remove deletes the table; without one it does nothing.
func (k Kernel) Remove() error {
	c, err := k.conn()
	if err != nil {
		return err
	}
	had, err := exists(c)
	if err != nil || !had {
		return err
	}
	c.DelTable(table())
	return permission(c.Flush())
}
