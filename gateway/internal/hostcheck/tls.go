package hostcheck

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	hc "github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/msg"
)

// CertInfo is what the TLS check keeps of a certificate: the site name and
// the expiry. The file content itself is never kept.
type CertInfo struct {
	Site     string
	NotAfter time.Time
	Path     string
}

var subjectRe = regexp.MustCompile(`^[A-Za-z0-9._:/@+-]{1,128}$`)

// ParseCert reads the first certificate of a PEM file. Blocks other than
// CERTIFICATE (a private key in a combined file) are skipped unread.
func ParseCert(b []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("no certificate")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

func siteOf(c *x509.Certificate) string {
	name := c.Subject.CommonName
	if len(c.DNSNames) > 0 {
		name = c.DNSNames[0]
	}
	name = strings.ToLower(strings.Replace(name, "*.", "wildcard.", 1))
	if !subjectRe.MatchString(name) {
		return ""
	}
	return name
}

// certCandidates lists the certificate files of the configured globs.
func (c *checker) certCandidates() ([]string, error) {
	globs := c.opts.CertGlobs
	if len(globs) == 0 {
		globs = DefaultCertGlobs
	}
	var out []string
	var denied error
	for _, g := range globs {
		ms, _ := c.env.Glob(g)
		if len(ms) == 0 {
			// A store that exists but cannot be listed (letsencrypt/live is
			// root only).
			root := g
			if i := strings.IndexAny(g, "*?["); i >= 0 {
				root = path.Dir(g[:i] + "x")
			}
			if _, err := c.env.ReadDir(root); errors.Is(err, fs.ErrPermission) {
				denied = err
			}
		}
		for _, m := range ms {
			if strings.Contains(path.Base(m), "key") {
				continue // never open key files
			}
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, denied
}

func (c *checker) checkTLS() {
	const id, area = "tls.certificate_expiry", "tls"
	files, denied := c.certCandidates()
	now := c.env.Now()
	best := map[string]CertInfo{}
	for _, f := range files {
		b, err := c.env.ReadFile(f, 256<<10)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				denied = err
			}
			continue
		}
		cert, err := ParseCert(b)
		if err != nil {
			continue
		}
		site := siteOf(cert)
		if site == "" {
			continue
		}
		// Several files per site (renewals): the newest one counts.
		if old, ok := best[site]; !ok || cert.NotAfter.After(old.NotAfter) {
			best[site] = CertInfo{Site: site, NotAfter: cert.NotAfter.UTC(), Path: f}
		}
	}
	if len(best) == 0 {
		if denied != nil {
			c.add(unreadable(id, area, "Die Zertifikate der Websites ließen sich nicht lesen.", ReasonPermission, NeedsRoot, hc.Evidence{Source: "cert_store"}))
			return
		}
		c.add(unreadable(id, area, "Es wurden keine Zertifikatsdateien gefunden. Gib die Pfade mit --cert an.", ReasonNotConfigured, "", hc.Evidence{Source: "cert_store"}))
		return
	}
	sites := make([]string, 0, len(best))
	for s := range best {
		sites = append(sites, s)
	}
	sort.Strings(sites)
	for _, s := range sites {
		ci := best[s]
		days := int(ci.NotAfter.Sub(now).Hours() / 24)
		if ci.NotAfter.Before(now) {
			days = -int(now.Sub(ci.NotAfter).Hours()/24) - 1
		}
		ev := hc.Evidence{Source: "cert_store", NotAfter: msg.FormatTime(ci.NotAfter), DaysLeft: ip(clamp(days)), Path: ci.Path}
		if !absPathRe.MatchString(ev.Path) {
			ev.Path = ""
		}
		fix := ""
		switch {
		case strings.HasPrefix(ci.Path, "/etc/letsencrypt/"):
			fix = fixCertbot
		case strings.Contains(ci.Path, "/caddy/"):
			fix = fixCaddyReload
		}
		renew := " Normalerweise erneuert sich ein Let's-Encrypt-Zertifikat 30 Tage vor Ablauf von selbst; wenn nicht, hakt die automatische Erneuerung."
		switch {
		case ci.NotAfter.Before(now):
			c.add(sub(finding(id, area, "critical", "Zertifikat für "+s+" ist abgelaufen",
				"Browser zeigen eine Warnung und viele Besucher brechen ab. Erneuere das Zertifikat und lade den Webserver neu."+renew, fix, ev), s))
		case days <= 7:
			c.add(sub(finding(id, area, "high", "Zertifikat für "+s+" läuft in "+strconv.Itoa(days)+" Tagen ab",
				"Danach zeigen Browser eine Warnung."+renew, fix, ev), s))
		case days <= 14:
			c.add(sub(finding(id, area, "medium", "Zertifikat für "+s+" läuft in "+strconv.Itoa(days)+" Tagen ab",
				"Danach zeigen Browser eine Warnung."+renew, fix, ev), s))
		default:
			c.add(sub(ok(id, area, "Zertifikat für "+s+" gilt noch "+strconv.Itoa(days)+" Tage", "Das Zertifikat ist gültig bis "+ci.NotAfter.Format("02.01.2006")+".", ev), s))
		}
	}
}

func clamp(d int) int {
	if d < -36500 {
		return -36500
	}
	if d > 36500 {
		return 36500
	}
	return d
}
