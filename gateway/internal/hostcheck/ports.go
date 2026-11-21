package hostcheck

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
)

// Listener is one listening TCP socket.
type Listener struct {
	Addr    string // "0.0.0.0", "::", "*", "203.0.113.5"
	Port    int
	Process string
}

var ssProcRe = regexp.MustCompile(`users:\(\("([^"]+)"`)

// ParseSS parses `ss -tlnp` (with or without header).
func ParseSS(b []byte) []Listener {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[0] != "LISTEN" {
			continue
		}
		local := f[3]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		addr := strings.Trim(local[:i], "[]")
		if j := strings.IndexByte(addr, '%'); j >= 0 {
			addr = addr[:j]
		}
		l := Listener{Addr: addr, Port: port}
		if m := ssProcRe.FindStringSubmatch(strings.Join(f[5:], " ")); m != nil {
			l.Process = m[1]
		}
		out = append(out, l)
	}
	return out
}

// ParseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6 (state 0A = LISTEN).
func ParseProcNetTCP(b []byte, v6 bool) []Listener {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		raw, err := hex.DecodeString(hexAddr)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		// The kernel prints each 32-bit word in host (little endian) order.
		for w := 0; w+4 <= len(raw); w += 4 {
			raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
		}
		a, _ := netip.AddrFromSlice(raw)
		out = append(out, Listener{Addr: a.Unmap().String(), Port: int(port)})
	}
	return out
}

// exposure classes, most exposed first.
const (
	exposeAll      = 3 // wildcard: every interface, also the public one
	exposePublic   = 2 // a public address
	exposeInternal = 1 // a private or link-local address
	exposeLoopback = 0
)

func exposure(addr string) int {
	switch addr {
	case "0.0.0.0", "::", "*", "":
		return exposeAll
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return exposeAll
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return exposeLoopback
	case a.IsPrivate() || a.IsLinkLocalUnicast():
		return exposeInternal
	}
	return exposePublic
}

type portClass struct {
	kind string // db, docker, docker_tls, admin, expected, other
	name string
}

var knownPorts = map[int]portClass{
	3306: {"db", "MySQL/MariaDB"}, 5432: {"db", "PostgreSQL"}, 1433: {"db", "SQL Server"}, 27017: {"db", "MongoDB"},
	6379: {"db", "Redis"}, 11211: {"db", "Memcached"}, 9200: {"db", "Elasticsearch"}, 9300: {"db", "Elasticsearch"},
	5984: {"db", "CouchDB"}, 8086: {"db", "InfluxDB"}, 9042: {"db", "Cassandra"}, 5672: {"db", "RabbitMQ"}, 2379: {"db", "etcd"},
	2375: {"docker", "Docker API"}, 2376: {"docker_tls", "Docker API (TLS)"},
	10000: {"admin", "Webmin"}, 8880: {"admin", "Plesk"}, 8443: {"admin", "Plesk oder Admin-Oberfläche"}, 2083: {"admin", "cPanel"},
	2087: {"admin", "WHM"}, 9000: {"admin", "Portainer oder PHP-FPM"}, 9443: {"admin", "Portainer"}, 8006: {"admin", "Proxmox"},
	9090: {"admin", "Cockpit"}, 5601: {"admin", "Kibana"}, 3000: {"admin", "Grafana oder Entwicklungsserver"}, 15672: {"admin", "RabbitMQ-Verwaltung"},
	8081: {"admin", "Admin-Oberfläche"}, 4848: {"admin", "GlassFish-Verwaltung"}, 8161: {"admin", "ActiveMQ-Verwaltung"},
	22: {"expected", "SSH"}, 80: {"expected", "HTTP"}, 443: {"expected", "HTTPS"}, 25: {"expected", "SMTP"}, 465: {"expected", "SMTPS"},
	587: {"expected", "Mail-Einlieferung"}, 993: {"expected", "IMAPS"}, 995: {"expected", "POP3S"}, 143: {"expected", "IMAP"}, 110: {"expected", "POP3"},
}

var processRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

func (c *checker) listeners() ([]Listener, string, error) {
	res, err := c.env.Run(c.ctx, CmdSS)
	if err == nil && res.Exit == 0 {
		return ParseSS(res.Stdout), "ss", nil
	}
	var out []Listener
	var firstErr error
	for _, p := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		b, err := c.env.ReadFile(p.path, 32<<20)
		if err != nil {
			if firstErr == nil && !p.v6 {
				firstErr = err
			}
			continue
		}
		out = append(out, ParseProcNetTCP(b, p.v6)...)
	}
	if out == nil && firstErr != nil {
		return nil, "proc_net", firstErr
	}
	return out, "proc_net", nil
}

func (c *checker) checkPorts() {
	const area = "ports"
	ls, src, err := c.listeners()
	if err != nil {
		for _, id := range []string{"ports.public_service", "ports.docker_api", "ports.admin_panel"} {
			c.add(unreadable(id, area, "Die offenen Ports ließen sich nicht lesen.", readErr(err), "", hc.Evidence{Source: src}))
		}
		return
	}
	// One entry per port: the most exposed address wins.
	best := map[int]Listener{}
	for _, l := range ls {
		if exposure(l.Addr) == exposeLoopback {
			continue
		}
		b, seen := best[l.Port]
		switch {
		case !seen:
			best[l.Port] = l
		case exposure(l.Addr) > exposure(b.Addr):
			if l.Process == "" {
				l.Process = b.Process
			}
			best[l.Port] = l
		case b.Process == "":
			b.Process = l.Process
			best[l.Port] = b
		}
	}
	ports := make([]int, 0, len(best))
	for p := range best {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var docker, admin, public int
	for _, p := range ports {
		l := best[p]
		cl, known := knownPorts[p]
		switch {
		case l.Process == "dockerd" && p != 2376:
			cl, known = portClass{"docker", "Docker API"}, true
		case l.Process == "sshd" || p == c.facts.sshPort:
			// SSH on its own port: never suggest closing it (lockout).
			cl, known = portClass{"expected", "SSH"}, true
		}
		if !known {
			cl = portClass{"other", "Dienst"}
		}
		ex := exposure(l.Addr)
		subject := "tcp/" + strconv.Itoa(p)
		ev := hc.Evidence{Source: src, Port: p, Protocol: "tcp", Address: evAddr(l.Addr)}
		if processRe.MatchString(l.Process) {
			ev.Process = l.Process
		}
		where := "auf allen Netzwerkschnittstellen, also auch auf der öffentlichen"
		if ex == exposePublic {
			where = "auf einer öffentlichen Adresse"
		} else if ex == exposeInternal {
			where = "nur im internen Netz"
		}
		// The check sees the listening socket, not what reaches it: a firewall on
		// the host or at the provider may close the port.
		fwNote := " Ob der Port von außen wirklich offen ist, sieht der Check vom Server aus nicht: Eine Firewall auf dem Server oder bei deinem Hoster kann ihn sperren. Prüf das. Ist der Port von außen zu, kannst du den Befund im Dashboard als akzeptiert markieren."
		fix := c.portFix(p, l.Process)
		switch cl.kind {
		case "docker", "docker_tls":
			docker++
			sev := "critical"
			expl := "Die Docker-Schnittstelle (" + cl.name + ") lauscht " + where + ". Wer sie erreicht, kann Container starten und damit den ganzen Server übernehmen."
			switch {
			case cl.kind == "docker_tls" && ex == exposeInternal:
				sev = "low"
			case cl.kind == "docker_tls":
				sev = "medium"
				expl += " Mit TLS und Client-Zertifikaten ist das nur so stark wie die Zertifikatsverwaltung."
			case ex == exposeInternal:
				sev = "high"
			}
			c.add(sub(finding("ports.docker_api", area, sev, "Docker-Schnittstelle lauscht im Netz", expl+
				" Docker braucht dafür keinen TCP-Port; der lokale Socket reicht. Entferne den tcp-Eintrag unter hosts in /etc/docker/daemon.json oder die Option -H tcp://... im systemd-Override von docker und starte Docker neu."+fwNote,
				"", ev), subject))
		case "admin":
			admin++
			if ex == exposeInternal {
				c.add(sub(ok("ports.admin_panel", area, cl.name+" nur im internen Netz", "Auf Port "+strconv.Itoa(p)+" lauscht vermutlich "+cl.name+", aber nur im internen Netz.", ev), subject))
				continue
			}
			c.add(sub(finding("ports.admin_panel", area, "medium", cl.name+" könnte von außen erreichbar sein",
				"Auf Port "+strconv.Itoa(p)+" lauscht vermutlich "+cl.name+" "+where+". Verwaltungsoberflächen sind ein beliebtes Ziel für Passwort-Raten und bekannte Lücken. Besser nur über SSH-Tunnel oder VPN erreichbar machen."+fwNote, fix, ev), subject))
		case "db":
			public++
			if ex == exposeInternal {
				c.add(sub(finding("ports.public_service", area, "low", cl.name+" im internen Netz erreichbar",
					cl.name+" lauscht auf Port "+strconv.Itoa(p)+" "+where+". Das ist oft gewollt (App-Server und Datenbank getrennt). Prüf, ob nur die Server, die es brauchen, dorthin dürfen.", "", ev), subject))
				continue
			}
			expl := cl.name + " lauscht auf Port " + strconv.Itoa(p) + " " + where + ". Datenbanken und Caches gehören nicht ins Internet: Sie werden ständig nach schwachen Passwörtern und offenen Zugängen abgesucht."
			if l.Process == "docker-proxy" {
				expl += " Der Port wird von Docker veröffentlicht; trag in der Port-Zuordnung 127.0.0.1 davor ein (zum Beispiel 127.0.0.1:" + strconv.Itoa(p) + ":" + strconv.Itoa(p) + ")."
			}
			c.add(sub(finding("ports.public_service", area, "high", cl.name+" könnte von außen erreichbar sein", expl+fwNote, fix, ev), subject))
		case "expected":
			public++
			c.add(sub(ok("ports.public_service", area, cl.name+" ist erreichbar", cl.name+" auf Port "+strconv.Itoa(p)+" ist "+where+" erreichbar. Das ist für diesen Dienst üblich.", ev), subject))
		default:
			public++
			if ex == exposeInternal {
				c.add(sub(ok("ports.public_service", area, "Port "+strconv.Itoa(p)+" nur im internen Netz", "Auf Port "+strconv.Itoa(p)+" lauscht ein Dienst nur im internen Netz.", ev), subject))
				continue
			}
			c.add(sub(finding("ports.public_service", area, "low", "Port "+strconv.Itoa(p)+" könnte von außen erreichbar sein",
				"Auf Port "+strconv.Itoa(p)+" lauscht ein Dienst "+where+". Wenn ihn niemand von außen braucht, binde ihn an 127.0.0.1 oder sperr den Port in der Firewall."+fwNote, fix, ev), subject))
		}
	}
	if public == 0 {
		c.add(ok("ports.public_service", area, "Kein Dienst lauscht im Netz", "Alle lauschenden Dienste sind nur lokal (127.0.0.1) erreichbar.", hc.Evidence{Source: src}))
	}
	if docker == 0 {
		c.add(ok("ports.docker_api", area, "Docker-Schnittstelle nicht im Netz", "Keine Docker-Schnittstelle lauscht auf einem Netzwerk-Port.", hc.Evidence{Source: src}))
	}
	if admin == 0 {
		c.add(ok("ports.admin_panel", area, "Keine bekannte Verwaltungsoberfläche im Netz", "Auf den üblichen Ports von Verwaltungsoberflächen lauscht nichts von außen Erreichbares.", hc.Evidence{Source: src}))
	}
}

func sub(f hc.Finding, subject string) hc.Finding {
	f.Subject = subject
	return f
}

func evAddr(a string) string {
	if a == "" {
		return "*"
	}
	if regexp.MustCompile(`^([0-9a-f:.]{2,45}|\*)$`).MatchString(a) {
		return a
	}
	return ""
}

func (c *checker) portFix(port int, process string) string {
	if process == "docker-proxy" {
		return ""
	}
	p := strconv.Itoa(port)
	switch c.facts.family {
	case "debian":
		return "sudo ufw deny " + p + "/tcp"
	case "rhel":
		return "sudo firewall-cmd --permanent --remove-port=" + p + "/tcp && sudo firewall-cmd --reload"
	}
	return ""
}
