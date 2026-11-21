package hostcheck

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// Ruleset is what the firewall check needs from nft or iptables-save.
type Ruleset struct {
	InputPolicy string // accept, drop, reject, unknown ("" when no input chain)
	InputRules  int    // rules in input chains
	// InputFilters: an input chain drops or rejects by service (port,
	// interface, anything but a plain list of source addresses) or hands
	// over to ufw or firewalld. Blocklists of source addresses (fail2ban,
	// CrowdSec bouncers, manual bans) do not count: every service stays
	// reachable for everybody else.
	InputFilters bool
	// InputCatchAll: an input chain drops or rejects whatever reaches it
	// without any match (firewalld's final reject, a last "drop"), the
	// default deny of a ruleset whose policy is accept.
	InputCatchAll   bool
	Docker          bool // DOCKER chains exist
	DockerUserRules int  // rules in DOCKER-USER besides a plain return
	UFW             bool // ufw chains exist
	Firewalld       bool // firewalld tables exist
}

var (
	nftPolicyRe = regexp.MustCompile(`policy\s+(accept|drop|reject)`)
	// quotedRe blanks quoted strings (comments, log prefixes) before rules
	// are split into words.
	quotedRe = regexp.MustCompile(`"[^"]*"`)
)

// nftDropRule reports whether an nft rule ends in drop or reject.
func nftDropRule(words []string) bool {
	for i, w := range words {
		if w == "drop" || w == "reject" {
			// "reject with icmpx admin-prohibited", "drop comment ..."
			return i == len(words)-1 || words[i+1] == "with" || words[i+1] == "comment"
		}
	}
	return false
}

// nftCatchAll: drop or reject with nothing but counters, logging and a
// comment before it.
func nftCatchAll(words []string) bool {
	i := 0
	for i < len(words) {
		switch words[i] {
		case "counter":
			i++
			if i+3 < len(words) && words[i] == "packets" && words[i+2] == "bytes" {
				i += 4
			}
			continue
		case "log":
			i++
			for i+1 < len(words) && (words[i] == "prefix" || words[i] == "level" || words[i] == "flags" || words[i] == "group") {
				i += 2
			}
			continue
		}
		break
	}
	return i < len(words) && (words[i] == "drop" || words[i] == "reject")
}

// sourceBlocklist: the rule matches listed source addresses (ip saddr
// @set, -s ADDR, --match-set SET src) and nothing negated.
func sourceBlocklist(line string) bool {
	if strings.Contains(line, "!=") || strings.Contains(line, "! -s ") || strings.Contains(line, "! --match-set") {
		return false
	}
	return strings.Contains(line, "saddr ") || strings.Contains(line, " -s ") || strings.Contains(line, "--match-set ") && strings.Contains(line, " src")
}

// ParseNft parses `nft list ruleset` (text), all address families together.
func ParseNft(b []byte) Ruleset { return parseNft(b, "") }

// ParseNftFamily parses `nft list ruleset` for one address family ("ip" or
// "ip6"): its own tables and the inet tables, which filter both. A packet
// over IPv6 never passes a table of the family ip, so a default deny there
// says nothing about IPv6.
func ParseNftFamily(b []byte, family string) Ruleset { return parseNft(b, family) }

func parseNft(b []byte, family string) Ruleset {
	var r Ruleset
	skip := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	chain, table := "", ""
	inInput := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "table "):
			f := strings.Fields(line)
			if len(f) >= 3 {
				table = f[2]
				skip = family != "" && f[1] != family && f[1] != "inet"
			}
			if table == "firewalld" && !skip {
				r.Firewalld = true
			}
			chain, inInput = "", false
		case skip:
		case strings.HasPrefix(line, "chain "):
			f := strings.Fields(line)
			if len(f) >= 2 {
				chain = f[1]
			}
			inInput = false
			switch {
			case chain == "DOCKER" || chain == "DOCKER-USER" || strings.HasPrefix(chain, "DOCKER-"):
				r.Docker = true
			case strings.HasPrefix(chain, "ufw-"):
				r.UFW = true
			}
		case strings.HasPrefix(line, "type filter hook input"):
			inInput = true
			if m := nftPolicyRe.FindStringSubmatch(line); m != nil {
				r.InputPolicy = strictest(r.InputPolicy, m[1])
			} else {
				r.InputPolicy = strictest(r.InputPolicy, "accept")
			}
		case line == "}" || line == "":
		default:
			if inInput && !strings.HasPrefix(line, "type ") {
				r.InputRules++
				words := strings.Fields(quotedRe.ReplaceAllString(line, `""`))
				switch {
				case nftCatchAll(words):
					r.InputCatchAll, r.InputFilters = true, true
				case nftDropRule(words) && !sourceBlocklist(line) && !strings.Contains(line, "ct state invalid"):
					r.InputFilters = true
				case strings.Contains(line, "jump ufw-"):
					r.InputFilters = true
				}
			}
			if chain == "DOCKER-USER" && !strings.HasPrefix(line, "type ") && line != "return" && !strings.HasSuffix(line, " return") && !strings.HasPrefix(line, "counter packets") {
				r.DockerUserRules++
			}
		}
	}
	return r
}

// strictest keeps the stricter of two input policies (several input hooks
// all have to pass a packet).
func strictest(a, b string) string {
	rank := map[string]int{"": 0, "unknown": 0, "accept": 1, "reject": 2, "drop": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

var iptPolicyRe = regexp.MustCompile(`^:INPUT\s+(ACCEPT|DROP|REJECT)`)

// ParseIptablesSave parses `iptables-save` output.
func ParseIptablesSave(b []byte) Ruleset {
	var r Ruleset
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	table := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "*"):
			table = line[1:]
		case strings.HasPrefix(line, ":"):
			if m := iptPolicyRe.FindStringSubmatch(line); m != nil && table == "filter" {
				r.InputPolicy = strictest(r.InputPolicy, strings.ToLower(m[1]))
			}
			name := strings.Fields(line[1:])
			if len(name) > 0 {
				switch {
				case strings.HasPrefix(name[0], "DOCKER"):
					r.Docker = true
				case strings.HasPrefix(name[0], "ufw-"):
					r.UFW = true
				case strings.HasPrefix(name[0], "IN_public") || strings.HasPrefix(name[0], "INPUT_ZONES"):
					r.Firewalld = true
				}
			}
		case strings.HasPrefix(line, "-A INPUT ") && table == "filter":
			r.InputRules++
			drop := strings.Contains(line, "-j DROP") || strings.Contains(line, "-j REJECT")
			switch {
			case drop && iptCatchAll(line):
				r.InputCatchAll, r.InputFilters = true, true
			case drop && !sourceBlocklist(line) && !strings.Contains(line, "--ctstate INVALID") && !strings.Contains(line, "--state INVALID"):
				r.InputFilters = true
			case strings.Contains(line, "-j ufw-") || strings.Contains(line, "-j INPUT_"):
				r.InputFilters = true
			}
		case strings.HasPrefix(line, "-A DOCKER-USER ") && table == "filter":
			if !strings.HasSuffix(line, "-j RETURN") {
				r.DockerUserRules++
			}
		}
	}
	return r
}

// iptCatchAll: "-A INPUT -j DROP" or "-j REJECT [--reject-with X]" with at
// most a comment, no match.
func iptCatchAll(line string) bool {
	w := strings.Fields(quotedRe.ReplaceAllString(line, `""`))[2:] // after "-A INPUT"
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case "-j":
			i++ // DROP or REJECT
		case "--reject-with", "--comment":
			i++
		case "-m":
			if i+1 < len(w) && w[i+1] == "comment" {
				i++
				continue
			}
			return false
		default:
			return false
		}
	}
	return true
}

var (
	ufwEnabledRe = regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*"?(yes|no)"?`)
	ufwPolicyRe  = regexp.MustCompile(`(?m)^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(ACCEPT|DROP|REJECT)"?`)
)

func (c *checker) checkFirewall() {
	const area = "firewall"
	// What the unprivileged user can read: ufw and firewalld configuration.
	ufwOn, ufwPolicy := false, ""
	if b, err := c.env.ReadFile("/etc/ufw/ufw.conf", 64<<10); err == nil {
		if m := ufwEnabledRe.FindSubmatch(b); m != nil {
			ufwOn = string(m[1]) == "yes"
		}
	}
	if b, err := c.env.ReadFile("/etc/default/ufw", 64<<10); err == nil {
		if m := ufwPolicyRe.FindSubmatch(b); m != nil {
			ufwPolicy = strings.ToLower(string(m[1]))
		}
	}
	fwdOn := exists(c.env, "/etc/systemd/system/multi-user.target.wants/firewalld.service")
	c.facts.dockerPresent = exists(c.env, "/var/run/docker.sock") || exists(c.env, "/run/docker.sock") || exists(c.env, "/usr/bin/dockerd")
	// The ruleset itself needs CAP_NET_ADMIN.
	var rs, rs6 *Ruleset // IPv4 and IPv6
	src := ""
	var rerr error
	nftEmpty, noIptables := false, false
	if res, err := c.env.Run(c.ctx, CmdNft); err == nil && res.Exit == 0 && len(bytes.TrimSpace(res.Stdout)) > 0 {
		r, r6 := ParseNftFamily(res.Stdout, "ip"), ParseNftFamily(res.Stdout, "ip6")
		rs, rs6, src = &r, &r6, "nft"
	} else {
		rerr = err
		nftEmpty = err == nil && res.Exit == 0
		if res2, err2 := c.env.Run(c.ctx, CmdIptablesSave); err2 == nil && res2.Exit == 0 && len(bytes.TrimSpace(res2.Stdout)) > 0 {
			r := ParseIptablesSave(res2.Stdout)
			rs, src, rerr = &r, "iptables", nil
			// iptables-save lists the IPv4 rules only.
			if res6, err6 := c.env.Run(c.ctx, CmdIp6tablesSave); err6 == nil && res6.Exit == 0 && len(bytes.TrimSpace(res6.Stdout)) > 0 {
				r6 := ParseIptablesSave(res6.Stdout)
				rs6 = &r6
			}
		} else if noIptables = err2 == ErrNotInstalled; rerr == nil || readErr(rerr) == ReasonNotInstalled {
			rerr = err2
			if err2 == nil {
				rerr = errPermissionLike
			}
		}
	}
	// nft answered as root with no table at all and there is no iptables
	// that could hold rules nft does not show: the host has no rules. That
	// is a result ("Keine Firewall aktiv"), not an unreadable ruleset.
	if rs == nil && nftEmpty && noIptables && c.env.IsRoot() {
		rs, rs6, src, rerr = &Ruleset{}, &Ruleset{}, "nft", nil
	}
	if rs != nil && rs.Docker {
		c.facts.dockerPresent = true
	}
	// IPv6 has its own rules. They count when the host has an address
	// that is reachable over IPv6; without one nothing arrives that way.
	v6 := rs != nil && c.publicIPv6()
	active6 := rs6 != nil && (rs6.InputPolicy == "drop" || rs6.InputPolicy == "reject" || rs6.InputFilters)
	deny6 := rs6 != nil && (rs6.InputPolicy == "drop" || rs6.InputPolicy == "reject" || rs6.InputCatchAll)
	// firewall.active
	ev := hc.Evidence{Source: src}
	active, how := false, ""
	switch {
	case rs != nil && (rs.InputPolicy == "drop" || rs.InputPolicy == "reject" || rs.InputFilters):
		active, how = true, src
	case ufwOn:
		active, how = true, "ufw"
	case fwdOn:
		active, how = true, "firewalld"
	}
	if how != "" {
		ev.Source = how
	}
	ev.Enabled = bp(active)
	fixOn := fixFirewallOn(c.facts.family, c.facts.sshPort)
	needs := NeedsNetAdmin
	switch {
	case active && how == src && v6 && rs6 == nil:
		c.add(unreadable("firewall.active", area, "Ob die Firewall auch IPv6 filtert, ließ sich nicht lesen.", ReasonPermission, needs, hc.Evidence{Source: src}))
	case active && how == src && v6 && !active6:
		c.add(finding("firewall.active", area, "high", "Firewall filtert IPv6 nicht",
			"Für IPv4 werden eingehende Verbindungen gefiltert, für IPv6 nicht. Der Server hat eine öffentliche IPv6-Adresse: jeder Dienst, der auf ihr lauscht, ist darüber von außen erreichbar, auch wenn die Firewall ihn für IPv4 sperrt. IPv6 braucht eigene Regeln (ip6tables, nft-Tabellen der Familie ip6 oder inet; bei ufw IPV6=yes in /etc/default/ufw).",
			"", hc.Evidence{Source: src, Enabled: bp(false)}))
	case active:
		c.add(ok("firewall.active", area, "Firewall ist aktiv", "Eingehende Verbindungen werden gefiltert ("+how+").", ev))
	case rs != nil:
		c.add(finding("firewall.active", area, "high", "Keine Firewall aktiv",
			"Eingehende Verbindungen werden nicht gefiltert: jeder Dienst, der auf einer Netzwerkadresse lauscht, ist von außen erreichbar. Eine Firewall lässt nur durch, was du freigibst. Gib vor dem Einschalten den SSH-Port frei, sonst sperrst du dich aus.",
			fixOn, ev))
	default:
		c.add(unreadable("firewall.active", area, "Ob eine Firewall filtert, ließ sich nicht lesen (weder ufw noch firewalld eingerichtet, Regeln nicht lesbar).", reasonOr(rerr, ReasonPermission), needs, hc.Evidence{Source: "nft"}))
	}
	// firewall.default_incoming
	policy, psrc := "", src
	switch {
	case rs != nil && rs.InputPolicy != "":
		policy = rs.InputPolicy
		if policy == "accept" && rs.InputCatchAll {
			// Accept policy with a final drop/reject rule (firewalld). Rules
			// that drop only some ports or addresses leave the rest open.
			policy = "reject"
		}
	case ufwOn && ufwPolicy != "":
		policy, psrc = ufwPolicy, "ufw"
	case fwdOn:
		policy, psrc = "reject", "firewalld"
	case rs != nil:
		policy = "accept"
	}
	pev := hc.Evidence{Source: psrc, Policy: policy, Expected: sp("drop")}
	switch policy {
	case "drop", "reject":
		if psrc == src && v6 && rs6 == nil {
			c.add(unreadable("firewall.default_incoming", area, "Die Grundregel für eingehende Verbindungen über IPv6 ließ sich nicht lesen.", ReasonPermission, needs, hc.Evidence{Source: src}))
			break
		}
		if psrc == src && v6 && !deny6 {
			c.add(finding("firewall.default_incoming", area, "medium", "Über IPv6 ist eingehend alles erlaubt",
				"Für IPv4 wird abgewiesen, was keine Regel erlaubt. Für IPv6 lässt die Grundregel alles durch, was keine Regel ausdrücklich sperrt, und der Server hat eine öffentliche IPv6-Adresse. Setze für IPv6 dieselbe Grundregel wie für IPv4.",
				"", hc.Evidence{Source: src, Policy: "accept", Expected: sp("drop")}))
			break
		}
		c.add(ok("firewall.default_incoming", area, "Eingehend gilt: abweisen, was nicht erlaubt ist", "Verbindungen, die keine Regel erlaubt, werden abgewiesen.", pev))
	case "accept":
		c.add(finding("firewall.default_incoming", area, "medium", "Eingehend ist alles erlaubt",
			"Die Grundregel für eingehende Verbindungen lässt alles durch, was keine Regel ausdrücklich sperrt. Üblich ist es umgekehrt: alles abweisen und nur nötige Ports freigeben.",
			fixOn, pev))
	default:
		c.add(unreadable("firewall.default_incoming", area, "Die Grundregel für eingehende Verbindungen ließ sich nicht lesen.", reasonOr(rerr, ReasonPermission), needs, hc.Evidence{Source: "nft"}))
	}
	// firewall.docker_bypass
	const bid = "firewall.docker_bypass"
	dev := hc.Evidence{Source: src, Enabled: bp(c.facts.dockerPresent)}
	if dev.Source == "" {
		dev.Source = "nft"
	}
	switch {
	case !c.facts.dockerPresent:
		c.add(ok(bid, area, "Kein Docker gefunden", "Docker ist nicht installiert, es kann also keine Regeln an der Firewall vorbei setzen.", dev))
	case !ufwOn && !fwdOn:
		c.add(ok(bid, area, "Docker ohne ufw oder firewalld", "Docker setzt seine Regeln direkt; ufw oder firewalld, die umgangen werden könnten, sind nicht aktiv. Welche Ports Docker veröffentlicht, steht im Bereich Ports.", dev))
	case rs == nil:
		c.add(unreadable(bid, area, "Ob Docker-Ports an ufw oder firewalld vorbei offen sind, ließ sich nicht lesen.", reasonOr(rerr, ReasonPermission), needs, dev))
	case rs.DockerUserRules > 0:
		c.add(ok(bid, area, "Docker-Ports werden zusätzlich gefiltert", "In der Kette DOCKER-USER stehen eigene Regeln, die vor Docker greifen.", dev))
	default:
		fw := "ufw"
		if !ufwOn {
			fw = "firewalld"
		}
		c.add(finding(bid, area, "medium", "Docker-Ports umgehen "+fw,
			"Ports, die ein Container veröffentlicht (ports: in docker compose), sind von außen erreichbar, auch wenn "+fw+" sie sperrt: Docker trägt seine Regeln vor "+fw+" ein. Binde solche Ports an 127.0.0.1 oder filtere sie in der Kette DOCKER-USER.",
			"", dev))
	}
}

// publicIPv6 reports whether an interface has a global unicast IPv6
// address (2000::/3). Loopback, link-local and unique local addresses
// (fc00::/7) are not reachable from the internet.
func (c *checker) publicIPv6() bool {
	b, err := c.env.ReadFile("/proc/net/if_inet6", 1<<20)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		// address, interface index, prefix length, scope, flags, name
		f := strings.Fields(line)
		if len(f) >= 6 && len(f[0]) == 32 && (f[0][0] == '2' || f[0][0] == '3') && f[3] == "00" {
			return true
		}
	}
	return false
}

// errPermissionLike marks a ruleset read that returned no usable output.
var errPermissionLike = &permErr{}

type permErr struct{}

func (*permErr) Error() string { return "permission denied" }

func reasonOr(err error, def string) string {
	if err == nil || err == errPermissionLike {
		return def
	}
	if r := readErr(err); r != ReasonNotSupported {
		return r
	}
	return def
}
