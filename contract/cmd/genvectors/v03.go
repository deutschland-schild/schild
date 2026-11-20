//go:build !release

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// ---- v0.3: server check and agent (host-check.md, MVP-11) ----

const gatewayID = "gw-1"

func nonce(name string) string {
	h := sha256.Sum256([]byte("schild/vector-nonce/" + name))
	return hex.EncodeToString(h[:16])
}

func finding(id, area, subject, severity, status, title, explanation string, fix any, evidence map[string]any) map[string]any {
	f := map[string]any{"id": id, "area": area, "severity": severity, "status": status, "title": title,
		"explanation": explanation, "fix_command": fix, "evidence": evidence}
	if subject != "" {
		f["subject"] = subject
	}
	return f
}

func unreadableFinding(id, area, title, explanation, reason, needs string, evidence map[string]any) map[string]any {
	f := finding(id, area, "", "info", "unreadable", title, explanation, nil, evidence)
	u := map[string]any{"reason": reason}
	if needs != "" {
		u["needs"] = needs
	}
	f["unreadable"] = u
	return f
}

func inv(kind, name, version string, eol any, source string, extra ...string) map[string]any {
	m := map[string]any{"kind": kind, "name": name, "version": version, "eol": eol, "source": source}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return m
}

func reportBase(name, hostname, role string, keyid any, os map[string]any, asRoot bool) map[string]any {
	return map[string]any{
		"schema":    hostcheck.SchemaReport,
		"report_id": uuid("host-report/" + name),
		"host":      map[string]any{"hostname": hostname, "role": role, "agent_key_id": keyid, "os": os},
		"run": map[string]any{"started_at": ts(-3 * time.Minute), "duration_ms": 4210, "schild_version": "0.3.0",
			"eol_table": "2026-10-01", "as_root": asRoot},
		"findings":  []any{},
		"inventory": []any{},
	}
}

// gatewayReport: Debian 12 gateway, run as root.
func gatewayReport() map[string]any {
	r := reportBase("gateway", "gw-1.example", "gateway", nil, map[string]any{
		"id": "debian", "version_id": "12", "name": "Debian GNU/Linux 12 (bookworm)", "kernel": "6.1.0-26-amd64",
		"arch": "x86_64", "eol": "2026-06-10", "extended_support_until": "2028-06-30"}, true)
	r["findings"] = []any{
		finding("distribution.eol", "distribution", "", "low", "finding", "Debian 12 bekommt nur noch Langzeit-Support",
			"Die reguläre Unterstützung endete am 10.06.2026. Sicherheitsupdates kommen noch bis 30.06.2028 über Debian LTS. Plane das Upgrade auf Debian 13 in Ruhe.",
			nil, map[string]any{"source": "eol_table", "date": "2026-06-10"}),
		finding("updates.security_pending", "updates", "", "high", "finding", "3 Sicherheitsupdates warten",
			"Für installierte Pakete gibt es Sicherheitsupdates. Solange sie fehlen, bleiben bekannte Lücken offen.",
			"sudo apt-get update && sudo apt-get upgrade", map[string]any{"source": "apt", "count": 3, "packages": []any{"libssl3", "openssl", "openssh-server"}}),
		finding("updates.automatic", "updates", "", "info", "ok", "Automatische Sicherheitsupdates sind an",
			"unattended-upgrades spielt Sicherheitsupdates täglich ein.", nil, map[string]any{"source": "unattended_upgrades", "enabled": true}),
		finding("updates.reboot_required", "updates", "", "medium", "finding", "Neustart nötig",
			"Ein Update braucht einen Neustart, erst dann ist es wirksam.", "sudo systemctl reboot",
			map[string]any{"source": "reboot_required", "path": "/var/run/reboot-required"}),
		finding("ports.public_service", "ports", "tcp/6379", "high", "finding", "Redis ist aus dem Netz erreichbar",
			"Redis lauscht auf allen Adressen. Eine Datenbank oder ein Cache gehört nur an localhost oder ins interne Netz.",
			"sudo sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf && sudo systemctl restart redis-server",
			map[string]any{"source": "ss", "port": 6379, "protocol": "tcp", "address": "0.0.0.0", "process": "redis-server"}),
		finding("ports.public_service", "ports", "tcp/443", "info", "ok", "HTTPS ist erreichbar",
			"Schild nimmt Anfragen auf Port 443 entgegen. So soll es sein.", nil,
			map[string]any{"source": "ss", "port": 443, "protocol": "tcp", "address": "*", "process": "schild"}),
		finding("firewall.active", "firewall", "", "info", "ok", "Firewall ist aktiv",
			"nftables ist aktiv, eingehende Verbindungen werden standardmäßig verworfen.", nil,
			map[string]any{"source": "nft", "enabled": true, "policy": "drop"}),
		finding("firewall.docker_bypass", "firewall", "", "info", "ok", "Docker umgeht die Firewall nicht",
			"Es gibt keine veröffentlichten Docker-Ports auf öffentlichen Adressen.", nil, map[string]any{"source": "nft", "count": 0}),
		finding("ssh.password_authentication", "ssh", "", "medium", "finding", "SSH erlaubt Anmeldung mit Passwort",
			"Passwörter lassen sich durchprobieren. Mit Schlüsseln geht das nicht. Prüfe vorher, dass dein Schlüssel funktioniert.",
			"sudo sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload ssh",
			map[string]any{"source": "sshd_t", "setting": "PasswordAuthentication", "value": "yes", "expected": "no"}),
		finding("ssh.permit_root_login", "ssh", "", "info", "ok", "Root-Anmeldung nur mit Schlüssel",
			"root kann sich nicht mit Passwort anmelden.", nil,
			map[string]any{"source": "sshd_t", "setting": "PermitRootLogin", "value": "prohibit-password"}),
		finding("ssh.failed_logins", "ssh", "", "info", "finding", "412 fehlgeschlagene SSH-Anmeldungen in 24 Stunden",
			"Das ist im Internet üblich und kein Grund zur Sorge, solange Passwörter aus sind.", nil,
			map[string]any{"source": "journal", "count": 412, "window_hours": 24}),
		finding("tls.certificate_expiry", "tls", "shop.example", "info", "ok", "Zertifikat für shop.example gültig",
			"Das Zertifikat läuft in 61 Tagen ab und wird automatisch erneuert.", nil,
			map[string]any{"source": "cert_store", "not_after": "2026-12-26T09:14:02Z", "days_left": 61}),
		finding("tls.certificate_expiry", "tls", "alt.example", "high", "finding", "Zertifikat für alt.example läuft in 5 Tagen ab",
			"Die automatische Erneuerung hat nicht geklappt. Danach sehen Besucher eine Warnung.",
			"sudo journalctl -u schild --since -24h | grep -i acme",
			map[string]any{"source": "cert_store", "not_after": "2026-10-31T08:00:00Z", "days_left": 5}),
	}
	r["inventory"] = []any{
		inv("os_package", "openssl", "3.0.15-1~deb12u1", nil, "dpkg"),
		inv("server", "openssh-server", "1:9.2p1-2+deb12u3", nil, "dpkg"),
		inv("database", "redis", "5:7.0.15-1~deb12u1", "2026-07-31", "dpkg"),
		inv("runtime", "python3", "3.11.2-1+b1", "2027-10-31", "dpkg"),
	}
	return r
}

// agentReport: Ubuntu 24.04 app VM, unprivileged agent of key name k.
func agentReport(k string) map[string]any {
	r := reportBase("agent-"+k, "app-1.example", "agent", testkeys.Get(k).KeyID, map[string]any{
		"id": "ubuntu", "version_id": "24.04", "name": "Ubuntu 24.04.1 LTS", "kernel": "6.8.0-45-generic",
		"arch": "x86_64", "eol": "2029-05-31", "extended_support_until": "2034-04-25"}, false)
	r["findings"] = []any{
		finding("distribution.eol", "distribution", "", "info", "ok", "Ubuntu 24.04 wird unterstützt",
			"Sicherheitsupdates gibt es bis 31.05.2029.", nil, map[string]any{"source": "eol_table", "date": "2029-05-31"}),
		finding("updates.security_pending", "updates", "", "medium", "finding", "1 Sicherheitsupdate wartet",
			"Für PHP gibt es ein Sicherheitsupdate.", "sudo apt-get update && sudo apt-get upgrade",
			map[string]any{"source": "apt", "count": 1, "packages": []any{"php8.3-fpm"}}),
		finding("updates.automatic", "updates", "", "low", "finding", "Automatische Sicherheitsupdates sind aus",
			"Ohne sie hängt jedes Update davon ab, dass jemand daran denkt.", "sudo dpkg-reconfigure -plow unattended-upgrades",
			map[string]any{"source": "unattended_upgrades", "enabled": false}),
		finding("ports.public_service", "ports", "tcp/3306", "high", "finding", "MySQL ist aus dem Netz erreichbar",
			"Die Datenbank lauscht auf allen Adressen. Sie gehört nur an localhost oder ins interne Netz.",
			"sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf && sudo systemctl restart mysql",
			map[string]any{"source": "ss", "port": 3306, "protocol": "tcp", "address": "0.0.0.0", "process": "mysqld"}),
		unreadableFinding("firewall.active", "firewall", "Firewall nicht lesbar",
			"Der Agent läuft ohne Root und darf die nftables-Regeln nicht lesen.", "permission_denied", "CAP_NET_ADMIN",
			map[string]any{"source": "nft"}),
		finding("ssh.password_authentication", "ssh", "", "info", "ok", "SSH nur mit Schlüssel",
			"Passwort-Anmeldung ist aus.", nil,
			map[string]any{"source": "sshd_config", "path": "/etc/ssh/sshd_config", "setting": "PasswordAuthentication", "value": "no"}),
		unreadableFinding("ssh.failed_logins", "ssh", "Anmeldeversuche nicht lesbar",
			"Für das Journal braucht der Agent die Gruppe systemd-journal.", "permission_denied", "group:systemd-journal",
			map[string]any{"source": "journal"}),
		finding("software.app_outdated", "software", "wordpress", "medium", "finding", "WordPress 6.4.3 ist veraltet",
			"Für diese Version gibt es keine Sicherheitsupdates mehr. Aktualisiere im WordPress-Backend oder mit WP-CLI.",
			"sudo -u www-data wp core update --path=/var/www/shop",
			map[string]any{"source": "app_path", "path": "/var/www/shop", "installed_version": "6.4.3"}),
	}
	r["inventory"] = []any{
		inv("runtime", "php", "8.3.6-0ubuntu0.24.04.2", "2027-12-31", "dpkg"),
		inv("server", "nginx", "1.24.0-2ubuntu7.1", nil, "dpkg"),
		inv("database", "mysql-server", "8.0.39-0ubuntu0.24.04.2", "2026-04-30", "dpkg"),
		inv("app", "wordpress", "6.4.3", nil, "app_path", "path", "/var/www/shop"),
		inv("app", "contact-form-7", "5.9.3", nil, "app_path", "path", "/var/www/shop/wp-content/plugins/contact-form-7", "parent", "wordpress"),
	}
	return r
}

func rockyReport() map[string]any {
	r := reportBase("rocky", "app-2.example", "agent", testkeys.Get("agent-b").KeyID, map[string]any{
		"id": "rocky", "version_id": "9.4", "name": "Rocky Linux 9.4 (Blue Onyx)", "kernel": "5.14.0-427.13.1.el9_4.x86_64",
		"arch": "x86_64", "eol": "2032-05-31"}, true)
	r["findings"] = []any{
		finding("updates.security_pending", "updates", "", "info", "ok", "Keine Sicherheitsupdates offen",
			"Der dnf-Cache kennt keine offenen Sicherheitsupdates. Er wird nicht neu geladen.", nil, map[string]any{"source": "dnf", "count": 0}),
		finding("updates.automatic", "updates", "", "low", "finding", "dnf-automatic ist aus", "Updates kommen nur, wenn jemand sie startet.",
			"sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer", map[string]any{"source": "dnf_automatic", "enabled": false}),
		finding("updates.reboot_required", "updates", "", "medium", "finding", "Neustart nötig",
			"Der laufende Kernel ist älter als der installierte.", "sudo systemctl reboot",
			map[string]any{"source": "needs_restarting", "installed_version": "5.14.0-427.22.1.el9_4", "candidate_version": "5.14.0-427.22.1.el9_4"}),
		finding("firewall.active", "firewall", "", "info", "ok", "firewalld ist aktiv", "Eingehend ist nur erlaubt, was freigegeben ist.", nil,
			map[string]any{"source": "firewalld", "enabled": true, "policy": "reject"}),
		finding("firewall.docker_bypass", "firewall", "", "high", "finding", "Docker umgeht firewalld",
			"Ein Container veröffentlicht Port 8080 auf allen Adressen. Docker trägt eigene Regeln ein, die firewalld nicht sieht.",
			nil, map[string]any{"source": "iptables", "port": 8080, "protocol": "tcp", "address": "0.0.0.0"}),
	}
	r["inventory"] = []any{
		inv("runtime", "java-17-openjdk", "17.0.12.0.7-2.el9", "2027-12-31", "rpm"),
		inv("server", "tomcat", "9.0.87-1.el9", nil, "rpm"),
		inv("database", "postgresql-server", "13.14-1.el9", "2025-11-13", "rpm"),
	}
	return r
}

func eolReport() map[string]any {
	r := reportBase("eol", "legacy.example", "gateway", nil, map[string]any{
		"id": "centos", "version_id": "7", "name": "CentOS Linux 7 (Core)", "kernel": "3.10.0-1160.119.1.el7.x86_64",
		"arch": "x86_64", "eol": "2024-06-30", "extended_support_until": nil}, true)
	r["findings"] = []any{
		finding("distribution.eol", "distribution", "", "critical", "finding", "CentOS 7 bekommt keine Updates mehr",
			"Seit 30.06.2024 gibt es keine Sicherheitsupdates. Neue Lücken bleiben offen. Plane den Umzug auf ein unterstütztes System, zum Beispiel Rocky Linux 9 oder AlmaLinux 9.",
			nil, map[string]any{"source": "eol_table", "date": "2024-06-30"}),
		finding("software.runtime_eol", "software", "php", "high", "finding", "PHP 5.4 wird seit Jahren nicht mehr gepflegt",
			"Für PHP 5.4 gibt es keine Sicherheitsupdates.", nil,
			map[string]any{"source": "rpm", "package": "php", "installed_version": "5.4.16-48.el7", "date": "2015-09-03"}),
		unreadableFinding("updates.security_pending", "updates", "Updates nicht prüfbar",
			"yum hat keinen lesbaren Cache. Schild lädt ihn nicht neu.", "not_configured", "", map[string]any{"source": "yum"}),
	}
	r["inventory"] = []any{inv("runtime", "php", "5.4.16-48.el7", "2015-09-03", "rpm")}
	return r
}

func minimalReport() map[string]any {
	return reportBase("minimal", "box", "gateway", nil, map[string]any{
		"id": "alpine", "version_id": "3.20.3", "name": "Alpine Linux v3.20", "kernel": "6.6.49-0-lts", "arch": "aarch64", "eol": "2026-04-01"}, false)
}

func firstFinding(r map[string]any) map[string]any {
	return r["findings"].([]any)[0].(map[string]any)
}

const pemKey = "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ-----END OPENSSH PRIVATE KEY-----"

func genHostReport(g *gen) {
	const c = "host-report"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), nil)
	}
	add(true, "", "gateway-debian12", "Gateway (Debian 12, root): findings of every area, ok and finding.", gatewayReport())
	add(true, "", "agent-ubuntu2404", "App VM agent (Ubuntu 24.04, no root): unreadable checks name what they need; WordPress with a plugin.", agentReport("agent-a"))
	add(true, "", "agent-rocky9", "App VM agent (Rocky 9, dnf): Docker bypasses firewalld.", rockyReport())
	add(true, "", "eol-centos7", "End-of-life system: critical distribution finding, yum cache not readable.", eolReport())
	add(true, "", "minimal", "No findings and no inventory (a check that found nothing to report).", minimalReport())
	m := gatewayReport()
	m["findings"] = []any{}
	for i := 0; i < hostcheck.MaxFindings; i++ {
		m["findings"] = append(m["findings"].([]any), finding("ports.public_service", "ports", "tcp/"+itoa(1000+i), "info", "ok", "Port erreichbar", "Ein Dienst lauscht.", nil, map[string]any{"port": 1000 + i}))
	}
	add(true, "", "max-findings", "500 findings: the limit.", m)

	// Size, JSON.
	m = gatewayReport()
	pad := strings.Repeat("Sehr lange Erklärung. ", 26000)
	firstFinding(m)["explanation"] = pad
	add(false, contract.CodeOversize, "oversize", "Report over 512 KiB.", m)
	dup := strings.Replace(string(mustJSON(gatewayReport())), `"schema":`, `"schema":"schild.host_report/0.2","schema":`, 1)
	g.add(c, "duplicate-key", false, contract.CodeMalformed, "Duplicate key.", ctx, []byte(dup), nil)

	// Forbidden fields (before the schema).
	m = gatewayReport()
	m["environment"] = map[string]any{"PATH": "/usr/bin"}
	add(false, contract.CodeForbiddenField, "field-environment", "Environment variables are never part of a report.", m)
	m = agentReport("agent-a")
	firstFinding(m)["evidence"].(map[string]any)["password"] = "x"
	add(false, contract.CodeForbiddenField, "field-password-in-evidence", "A password field in evidence.", m)
	m = gatewayReport()
	m["inventory"].([]any)[0].(map[string]any)["File-Content"] = "x"
	add(false, contract.CodeForbiddenField, "field-file-content", "File contents, under any spelling of the key.", m)
	m = gatewayReport()
	firstFinding(m)["evidence"].(map[string]any)["Env"] = []any{"HOME=/root"}
	add(false, contract.CodeForbiddenField, "field-env-in-array", "Key env (case-insensitive) with an array value.", m)

	// Forbidden content.
	m = gatewayReport()
	firstFinding(m)["explanation"] = "Gefunden: " + pemKey
	add(false, contract.CodeForbiddenContent, "pem-private-key", "A PEM private key in an explanation.", m)
	m = gatewayReport()
	firstFinding(m)["evidence"].(map[string]any)["value"] = "-----BEGIN RSA PRIVATE KEY-----"
	add(false, contract.CodeForbiddenContent, "pem-in-evidence", "PEM armour in an evidence value (caught before the token pattern).", m)
	m = gatewayReport()
	firstFinding(m)["fix_command"] = "PATH=/usr/bin HOME=/root USER=root LANG=C.UTF-8"
	add(false, contract.CodeForbiddenContent, "env-dump", "An environment dump in fix_command.", m)
	m = gatewayReport()
	firstFinding(m)["title"] = "PATH=/usr/sbin\x00HOME=/root\x00MAIL=/var/mail/root"
	add(false, contract.CodeForbiddenContent, "env-dump-nul", "/proc/<pid>/environ style dump with NUL separators.", m)
	m = gatewayReport()
	firstFinding(m)["explanation"] = "In /var/www/.env steht DB_PASSWORD=hunter2"
	add(false, contract.CodeForbiddenContent, "secret-assignment", "A secret assignment copied from a config file.", m)
	m = gatewayReport()
	firstFinding(m)["fix_command"] = "mysql --user=root --password=geheim -e 'select 1'"
	add(false, contract.CodeForbiddenContent, "secret-option", "A password on a command line.", m)
	m = agentReport("agent-a")
	m["inventory"].([]any)[0].(map[string]any)["name"] = "aws_secret_access_key=abc"
	add(false, contract.CodeForbiddenContent, "secret-in-inventory", "Secret assignment in an inventory name (caught before the pattern).", m)

	// Schema.
	m = gatewayReport()
	m["schema"] = "schild.host_report/0.2"
	add(false, contract.CodeSchema, "schema-version", "Unknown report version.", m)
	m = gatewayReport()
	m["findings"].([]any)[1].(map[string]any)["severity"] = "urgent"
	add(false, contract.CodeSchema, "severity", "Unknown severity.", m)
	m = gatewayReport()
	m["findings"].([]any)[2].(map[string]any)["severity"] = "high"
	add(false, contract.CodeSchema, "ok-with-severity", "status ok is always severity info.", m)
	m = agentReport("agent-a")
	delete(m["findings"].([]any)[4].(map[string]any), "unreadable")
	add(false, contract.CodeSchema, "unreadable-without-reason", "status unreadable needs a reason.", m)
	m = gatewayReport()
	firstFinding(m)["unreadable"] = map[string]any{"reason": "timeout"}
	add(false, contract.CodeSchema, "reason-on-finding", "Only unreadable entries carry a reason.", m)
	m = gatewayReport()
	m["host"].(map[string]any)["agent_key_id"] = "test-agent-a"
	add(false, contract.CodeSchema, "gateway-with-agent-key", "The gateway has no agent key.", m)
	m = agentReport("agent-a")
	m["host"].(map[string]any)["agent_key_id"] = nil
	add(false, contract.CodeSchema, "agent-without-key", "An agent report names its key.", m)
	m = gatewayReport()
	firstFinding(m)["title"] = "Zeile eins\nZeile zwei"
	add(false, contract.CodeSchema, "title-newline", "Text is one line without control characters.", m)
	m = gatewayReport()
	firstFinding(m)["evidence"].(map[string]any)["value"] = "yes but also cat /etc/shadow"
	add(false, contract.CodeSchema, "evidence-free-text", "Evidence values are single tokens, never free text.", m)
	m = gatewayReport()
	firstFinding(m)["evidence"].(map[string]any)["note"] = "x"
	add(false, contract.CodeSchema, "evidence-unknown-field", "Evidence has a closed set of typed fields.", m)
	m = gatewayReport()
	m["findings"] = append(m["findings"].([]any), clone(m["findings"].([]any)[4].(map[string]any)))
	add(false, contract.CodeSchema, "duplicate-finding", "The same check and subject twice.", m)
	m = gatewayReport()
	delete(m["inventory"].([]any)[0].(map[string]any), "eol")
	add(false, contract.CodeSchema, "inventory-without-eol", "eol is required (null when unknown).", m)
	m = gatewayReport()
	firstFinding(m)["area"] = "metrics"
	add(false, contract.CodeSchema, "area", "Unknown area.", m)
	m = minimalReport()
	m["inventory"] = make([]any, hostcheck.MaxInventory+1)
	for i := range m["inventory"].([]any) {
		m["inventory"].([]any)[i] = inv("os_package", "pkg-"+itoa(i), "1.0", nil, "dpkg")
	}
	add(false, contract.CodeSchema, "inventory-limit", "More than 2000 inventory items.", m)
}

func agentPayload(name, k string, at time.Time, report map[string]any) map[string]any {
	return map[string]any{"schema": hostcheck.SchemaAgentReport, "gateway": gatewayID, "issued_at": at.Format("2006-01-02T15:04:05Z"),
		"nonce": nonce(name), "report": report}
}

func agentCtx() vectors.Context {
	return vectors.Context{Trust: []string{"agent-a", "agent-b", "agent-c", "site-a", "lab-a"}, Revoked: []string{"agent-c"},
		Gateway: gatewayID, SeenIDs: []string{nonce("seen")}}
}

func genAgentReport(g *gen) {
	const c = "agent-report"
	k := contract.KindAgentReport
	add := func(valid bool, code contract.Code, name, desc string, ctx vectors.Context, raw []byte, p []byte) {
		g.add(c, name, valid, code, desc, ctx, raw, decodedOf(p))
	}
	ok := func(name, desc string, signer string, p map[string]any) {
		b := mustJSON(p)
		add(true, "", name, desc, agentCtx(), signed(k, b, signer), b)
	}
	ok("agent-a", "Agent a delivers its report to gw-1.", "agent-a", agentPayload("a", "agent-a", Now, agentReport("agent-a")))
	ok("agent-b-rocky", "Agent b (Rocky 9) delivers.", "agent-b", agentPayload("b", "agent-b", Now.Add(-30*time.Second), rockyReport()))
	ok("future-edge", "issued_at 120 s in the future is inside the skew.", "agent-a", agentPayload("fe", "agent-a", Now.Add(120*time.Second), agentReport("agent-a")))
	ok("past-edge", "issued_at exactly 5 min old is inside the window.", "agent-a", agentPayload("pe", "agent-a", Now.Add(-5*time.Minute), agentReport("agent-a")))
	r := minimalReport()
	r["host"].(map[string]any)["role"] = "agent"
	r["host"].(map[string]any)["agent_key_id"] = testkeys.Get("agent-b").KeyID
	ok("empty-report", "An agent report without findings or inventory.", "agent-b", agentPayload("empty", "agent-b", Now, r))
	b := mustJSON(agentPayload("anygw", "agent-a", Now, agentReport("agent-a")))
	ctx := agentCtx()
	ctx.Gateway = ""
	add(true, "", "any-gateway", "Without a configured gateway name any gateway field is accepted.", ctx, signed(k, b, "agent-a"), b)

	good := mustJSON(agentPayload("x", "agent-a", Now, agentReport("agent-a")))
	// 1 oversize, 2 malformed, 3 envelope.
	big := agentReport("agent-a")
	firstFinding(big)["explanation"] = strings.Repeat("x", 600<<10)
	bb := mustJSON(agentPayload("big", "agent-a", Now, big))
	add(false, contract.CodeOversize, "oversize-envelope", "Envelope over 768 KiB.", agentCtx(), signed(k, bb, "agent-a"), nil)
	g.add(c, "trailing-data", false, contract.CodeMalformed, "Data after the envelope.", agentCtx(), append(signed(k, good, "agent-a"), []byte("{}")...), nil)
	add(false, contract.CodeEnvelope, "two-signatures", "One agent, one signature.", agentCtx(), signed(k, good, "agent-a", "agent-b"), good)
	// 4 oversize payload.
	big = agentReport("agent-a")
	firstFinding(big)["explanation"] = strings.Repeat("x", 520<<10)
	bb = mustJSON(agentPayload("big2", "agent-a", Now, big))
	add(false, contract.CodeOversize, "oversize-payload", "Payload over 512 KiB (envelope still under its limit).", agentCtx(), signed(k, bb, "agent-a"), nil)
	// 5 payload type: domain separation.
	add(false, contract.CodePayloadType, "signal-domain", "An agent report signed under the signal payload type.", agentCtx(), signed(contract.KindSignal, good, "agent-a"), good)
	add(false, contract.CodePayloadType, "enrolment-domain", "An agent report signed under the enrolment payload type.", agentCtx(), envBytes(sign(hostcheck.EnrolmentPayloadType, good, "agent-a")), good)
	sp := mustJSON(baseSignal("agent"))
	add(false, contract.CodePayloadType, "signal-envelope", "A signal envelope presented as agent report.", agentCtx(), signed(contract.KindSignal, sp, "site-a"), sp)
	// 6 signature / revoked.
	add(false, contract.CodeSignature, "unknown-key", "Signed by a key the gateway never enrolled.", agentCtx(), signed(k, good, "evil"), good)
	add(false, contract.CodeSignature, "site-key", "A site key has no agent purpose.", agentCtx(), signed(k, good, "site-a"), good)
	rv := mustJSON(agentPayload("revoked", "agent-c", Now, agentReport("agent-c")))
	add(false, contract.CodeRevoked, "revoked-key", "Valid signature by the revoked agent-c.", agentCtx(), signed(k, rv, "agent-c"), rv)
	e := sign(k.PayloadType(), good, "agent-a")
	e.Signatures[0].KeyID = testkeys.Get("agent-b").KeyID
	add(false, contract.CodeSignature, "keyid-swapped", "Signature of agent-a presented under agent-b's key id.", agentCtx(), envBytes(e), good)
	raw := ed25519Sign("agent-a", good)
	e = &dsse.Envelope{PayloadType: k.PayloadType(), Payload: base64.StdEncoding.EncodeToString(good), Signatures: []dsse.Signature{{KeyID: testkeys.Get("agent-a").KeyID, Sig: base64.StdEncoding.EncodeToString(raw)}}}
	add(false, contract.CodeSignature, "raw-payload-signature", "Signature over the raw payload instead of PAE.", agentCtx(), envBytes(e), good)
	// 7-9 malformed payload, forbidden, schema.
	np := []byte(`{"schema":"schild.agent_report/0.1","schema":"x"}`)
	add(false, contract.CodeMalformed, "payload-duplicate-key", "Payload with a duplicate key.", agentCtx(), signed(k, np, "agent-a"), nil)
	r = agentReport("agent-a")
	r["env"] = []any{"HOME=/root"}
	b = mustJSON(agentPayload("env", "agent-a", Now, r))
	add(false, contract.CodeForbiddenField, "field-env", "Environment in the report.", agentCtx(), signed(k, b, "agent-a"), b)
	r = agentReport("agent-a")
	firstFinding(r)["explanation"] = pemKey
	b = mustJSON(agentPayload("pem", "agent-a", Now, r))
	add(false, contract.CodeForbiddenContent, "pem", "A private key in the report.", agentCtx(), signed(k, b, "agent-a"), b)
	r = agentReport("agent-a")
	firstFinding(r)["fix_command"] = "APP_KEY=base64:abc DB_HOST=db DB_USER=shop"
	b = mustJSON(agentPayload("envdump", "agent-a", Now, r))
	add(false, contract.CodeForbiddenContent, "env-dump", "A Laravel .env dump in fix_command.", agentCtx(), signed(k, b, "agent-a"), b)
	r = agentReport("agent-a")
	r["host"].(map[string]any)["role"] = "gateway"
	r["host"].(map[string]any)["agent_key_id"] = nil
	b = mustJSON(agentPayload("role", "agent-a", Now, r))
	add(false, contract.CodeSchema, "role-gateway", "Agents deliver agent reports only.", agentCtx(), signed(k, b, "agent-a"), b)
	p := agentPayload("cmd", "agent-a", Now, agentReport("agent-a"))
	p["command"] = "x"
	b = mustJSON(p)
	add(false, contract.CodeSchema, "extra-field", "Unknown payload field.", agentCtx(), signed(k, b, "agent-a"), b)
	p = agentPayload("nonce", "agent-a", Now, agentReport("agent-a"))
	p["nonce"] = "1234"
	b = mustJSON(p)
	add(false, contract.CodeSchema, "nonce-format", "Nonce is 16 bytes hex.", agentCtx(), signed(k, b, "agent-a"), b)
	r = agentReport("agent-a")
	r["findings"] = append(r["findings"].([]any), clone(firstFinding(r)))
	b = mustJSON(agentPayload("dupf", "agent-a", Now, r))
	add(false, contract.CodeSchema, "duplicate-finding", "The same check and subject twice.", agentCtx(), signed(k, b, "agent-a"), b)
	// 10 semantic.
	b = mustJSON(agentPayload("bind", "agent-a", Now, agentReport("agent-b")))
	add(false, contract.CodeSignature, "report-of-other-agent", "The report names agent-b's key, agent-a signed it.", agentCtx(), signed(k, b, "agent-a"), b)
	b = mustJSON(agentPayload("future", "agent-a", Now.Add(5*time.Minute), agentReport("agent-a")))
	add(false, contract.CodeClockSkew, "future", "issued_at 5 min in the future.", agentCtx(), signed(k, b, "agent-a"), b)
	b = mustJSON(agentPayload("old", "agent-a", Now.Add(-5*time.Minute-time.Second), agentReport("agent-a")))
	add(false, contract.CodeExpired, "too-old", "issued_at 5 min 1 s old.", agentCtx(), signed(k, b, "agent-a"), b)
	p = agentPayload("gw2", "agent-a", Now, agentReport("agent-a"))
	p["gateway"] = "gw-2"
	b = mustJSON(p)
	add(false, contract.CodeChannel, "other-gateway", "Addressed to gw-2, replayed to gw-1.", agentCtx(), signed(k, b, "agent-a"), b)
	b = mustJSON(agentPayload("seen", "agent-a", Now, agentReport("agent-a")))
	add(false, contract.CodeReplay, "replay", "Nonce already accepted.", agentCtx(), signed(k, b, "agent-a"), b)
}

func ed25519Sign(name string, msg []byte) []byte {
	s := testkeys.Signer(name)
	sig, err := s.Sign(msg)
	if err != nil {
		panic(err)
	}
	return sig
}

func enrolPayload(name, k string, at time.Time) map[string]any {
	key := testkeys.Get(k)
	return map[string]any{"schema": hostcheck.SchemaEnrolment, "gateway": gatewayID, "code": "K7QM-2XRP-9HWD-T4NA",
		"keyid": key.KeyID, "public_key": key.Public, "hostname": "app-1.example", "issued_at": at.Format("2006-01-02T15:04:05Z"), "nonce": nonce("enrol/" + name)}
}

func genAgentEnrolment(g *gen) {
	const c = "agent-enrolment"
	pt := hostcheck.EnrolmentPayloadType
	ctx := func() vectors.Context {
		return vectors.Context{Gateway: gatewayID, SeenIDs: []string{nonce("enrol/seen")}}
	}
	add := func(valid bool, code contract.Code, name, desc string, x vectors.Context, raw, p []byte) {
		g.add(c, name, valid, code, desc, x, raw, decodedOf(p))
	}
	one := func(valid bool, code contract.Code, name, desc string, p map[string]any, signer string) {
		b := mustJSON(p)
		add(valid, code, name, desc, ctx(), envBytes(sign(pt, b, signer)), b)
	}
	one(true, "", "agent-a", "A new agent proves possession of its key and names the one-time code.", enrolPayload("a", "agent-a", Now), "agent-a")
	one(true, "", "agent-b", "Second agent.", enrolPayload("b", "agent-b", Now.Add(-time.Minute)), "agent-b")
	one(true, "", "future-edge", "issued_at 120 s in the future.", enrolPayload("fe", "agent-a", Now.Add(120*time.Second)), "agent-a")
	one(true, "", "past-edge", "issued_at 5 min old.", enrolPayload("pe", "agent-a", Now.Add(-5*time.Minute)), "agent-a")
	p := enrolPayload("host", "agent-c", Now)
	p["hostname"] = "db-2"
	one(true, "", "short-hostname", "Host names need no domain.", p, "agent-c")
	b := mustJSON(enrolPayload("any", "agent-a", Now))
	x := ctx()
	x.Gateway = ""
	add(true, "", "any-gateway", "Without a configured gateway name any gateway field is accepted.", x, envBytes(sign(pt, b, "agent-a")), b)

	good := mustJSON(enrolPayload("x", "agent-a", Now))
	add(false, contract.CodeOversize, "oversize", "Enrolment envelope over 16 KiB.", ctx(), append(envBytes(sign(pt, good, "agent-a")), []byte(strings.Repeat(" ", 16<<10))...), nil)
	g.add(c, "not-object", false, contract.CodeMalformed, "Top level must be an object.", ctx(), []byte(`[]`), nil)
	add(false, contract.CodeEnvelope, "two-signatures", "Exactly one signature.", ctx(), envBytes(sign(pt, good, "agent-a", "agent-b")), good)
	add(false, contract.CodePayloadType, "report-domain", "Signed under the agent report payload type.", ctx(), envBytes(sign(contract.KindAgentReport.PayloadType(), good, "agent-a")), good)
	p = enrolPayload("pk", "agent-a", Now)
	p["public_key"] = testkeys.Get("agent-b").Public
	one(false, contract.CodeSignature, "other-public-key", "Payload names agent-b's public key, agent-a signed.", p, "agent-a")
	p = enrolPayload("kid", "agent-a", Now)
	p["keyid"] = testkeys.Get("agent-b").KeyID
	one(false, contract.CodeSignature, "other-keyid", "Payload keyid differs from the signature's keyid.", p, "agent-a")
	b = mustJSON(enrolPayload("evil", "agent-a", Now))
	e := sign(pt, b, "evil")
	e.Signatures[0].KeyID = testkeys.Get("agent-a").KeyID
	add(false, contract.CodeSignature, "not-possessed", "Someone without agent-a's private key enrols agent-a's public key.", ctx(), envBytes(e), b)
	p = enrolPayload("code", "agent-a", Now)
	p["code"] = "k7qm-2xrp-9hwd-t4na"
	one(false, contract.CodeSchema, "code-format", "Codes are upper case without ambiguous characters.", p, "agent-a")
	p = enrolPayload("tok", "agent-a", Now)
	p["token"] = "x"
	one(false, contract.CodeForbiddenField, "field-token", "No tokens in an enrolment.", p, "agent-a")
	p = enrolPayload("pem", "agent-a", Now)
	p["hostname"] = "-----BEGIN PRIVATE KEY-----"
	one(false, contract.CodeForbiddenContent, "private-key", "A private key never travels, not even by mistake.", p, "agent-a")
	one(false, contract.CodeClockSkew, "future", "issued_at 5 min in the future.", enrolPayload("fut", "agent-a", Now.Add(5*time.Minute)), "agent-a")
	one(false, contract.CodeExpired, "too-old", "issued_at 10 min old.", enrolPayload("old", "agent-a", Now.Add(-10*time.Minute)), "agent-a")
	p = enrolPayload("gw", "agent-a", Now)
	p["gateway"] = "gw-2"
	one(false, contract.CodeChannel, "other-gateway", "Enrolment for another gateway.", p, "agent-a")
	one(false, contract.CodeReplay, "replay", "Nonce already seen.", enrolPayload("seen", "agent-a", Now), "agent-a")
}

func ackDoc(status string, errCode any) map[string]any {
	return map[string]any{"schema": hostcheck.SchemaAck, "status": status, "nonce": nonce("a"), "received_at": ts(0), "error": errCode}
}

func genAgentAck(g *gen) {
	const c = "agent-ack"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), nil)
	}
	add(true, "", "accepted", "Report stored.", ackDoc("accepted", nil))
	add(true, "", "duplicate", "Same nonce again (agent retried after a lost answer).", ackDoc("duplicate", nil))
	add(true, "", "pending", "Enrolment received, waits for confirmation in the dashboard.", ackDoc("pending", nil))
	add(true, "", "rejected-revoked", "Key revoked.", ackDoc("rejected", "revoked"))
	m := ackDoc("retry", nil)
	m["retry_after_s"] = 300
	add(true, "", "retry", "Gateway busy: retry in 5 minutes.", m)

	add(false, contract.CodeSchema, "rejected-without-error", "A rejection names its reason.", ackDoc("rejected", nil))
	add(false, contract.CodeSchema, "accepted-with-error", "Only rejections carry an error.", ackDoc("accepted", "schema"))
	add(false, contract.CodeSchema, "retry-without-delay", "retry needs retry_after_s.", ackDoc("retry", nil))
	m = ackDoc("accepted", nil)
	m["retry_after_s"] = 60
	add(false, contract.CodeSchema, "delay-on-accepted", "retry_after_s only with retry.", m)
	m = ackDoc("accepted", nil)
	m["command"] = "apt-get upgrade"
	add(false, contract.CodeSchema, "command", "The gateway never sends instructions.", m)
	m = ackDoc("accepted", nil)
	m["interval_minutes"] = 5
	add(false, contract.CodeSchema, "interval", "Not even a new interval: agent configuration is local.", m)
	add(false, contract.CodeSchema, "unknown-status", "Unknown status.", ackDoc("ok", nil))
	add(false, contract.CodeSchema, "unknown-error", "Unknown error code.", ackDoc("rejected", "nope"))
	m = ackDoc("accepted", nil)
	m["nonce"] = strings.ToUpper(nonce("a"))
	add(false, contract.CodeSchema, "nonce-upper", "Nonce is lower-case hex.", m)
	m = ackDoc("retry", nil)
	m["retry_after_s"] = 86401
	add(false, contract.CodeSchema, "delay-too-long", "Backoff at most one day.", m)
	add(false, contract.CodeOversize, "oversize", "Ack over 4 KiB.", map[string]any{"schema": hostcheck.SchemaAck, "pad": strings.Repeat("x", 4<<10)})
	g.add(c, "malformed", false, contract.CodeMalformed, "Not JSON.", ctx, []byte("accepted"), nil)
}

func genSiteConfigV03(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	agentKey := func(name string) map[string]any {
		k := testkeys.Get(name)
		return map[string]any{"keyid": k.KeyID, "public_key": k.Public}
	}
	hc := func(keys ...any) map[string]any {
		return map[string]any{"report_dir": "/var/lib/schild/host-check", "keep_reports": 30,
			"agents": map[string]any{"enabled": true, "listen": "0.0.0.0:8790", "tls_cert": "/etc/schild/tls/agents.crt", "tls_key": "/etc/schild/tls/agents.key",
				"interval_minutes": 1440, "enrolment_code_minutes": 30, "keys": keys}}
	}
	m := siteConfig()
	m["host_check"] = map[string]any{}
	add(true, "", "host-check-defaults", "v0.3: server check with defaults (local report only, no agents).", m)
	m = siteConfig()
	revoked := agentKey("agent-c")
	revoked["revoked"] = true
	revoked["hostname"] = "old-app.example"
	m["host_check"] = hc(agentKey("agent-a"), agentKey("agent-b"), revoked)
	add(true, "", "host-check-agents", "v0.3: agents enrolled by explicit public key, one revoked.", m)

	m = siteConfig()
	m["host_check"] = hc(agentKey("agent-a"), agentKey("agent-a"))
	add(false, contract.CodeConfig, "agent-duplicate-keyid", "v0.3: the same agent key id twice.", m)
	m = siteConfig()
	k := agentKey("agent-b")
	k["public_key"] = testkeys.Get("agent-a").Public
	m["host_check"] = hc(agentKey("agent-a"), k)
	add(false, contract.CodeConfig, "agent-duplicate-public-key", "v0.3: one public key under two agent key ids.", m)
	g.retire(c, false) // agent-key-is-lab-key (D72: no lab keys)
	m = siteConfig()
	m["host_check"] = map[string]any{"keep_reports": 0}
	add(false, contract.CodeSchema, "keep-reports-zero", "v0.3: keep at least one report per host.", m)
	m = siteConfig()
	m["host_check"] = map[string]any{"external_scan": true}
	add(false, contract.CodeSchema, "host-check-unknown-key", "v0.3: no external scan option in MVP-11.", m)
}
