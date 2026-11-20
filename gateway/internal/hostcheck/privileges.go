package hostcheck

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Privilege documents what one check reads and the minimal rights it needs
// (host-check.md section 4). Without them the check reports "unreadable".
type Privilege struct {
	Check   string
	Reads   string
	Without string // what works without extra rights
	Needs   string // group or capability for the rest
}

// Privileges is the table printed by `schild check --privileges` and
// documented in gateway/README.md.
var Privileges = []Privilege{
	{"distribution.eol, kernel_outdated", "/etc/os-release, uname -r/-m, /boot/vmlinuz-*", "everything", "root only where /boot is 0700 (Alma/Rocky hardening)"},
	{"updates.* (apt)", "apt list --upgradable (cache only), apt-get -s, /etc/apt/apt.conf.d, /var/run/reboot-required", "everything", "-"},
	{"updates.* (dnf)", "dnf's metadata cache (/var/cache/dnf) and the rpm database via a fixed hawkey script as nobody (dnf, yum and needs-restarting are never run: they write logs and caches); rpm install times and /proc/stat btime for the reboot rule; timer links", "everything", "as root: CAP_SETUID and CAP_SETGID to drop to nobody (else not run, \"nicht lesbar\"); yum hosts (RHEL 7 family): pending updates not readable without writes"},
	{"ports.*", "ss -tlnp, else /proc/net/tcp{,6}", "addresses and ports", "CAP_SYS_PTRACE (or root) for process names of other users' sockets"},
	{"firewall.*", "nft list ruleset, else iptables-save and ip6tables-save; /proc/net/if_inet6; /etc/ufw/*.conf, firewalld unit link", "ufw/firewalld on or off and default policy", "CAP_NET_ADMIN for the ruleset (input policy, Docker chains)"},
	{"ssh.password_authentication, permit_root_login, port", "sshd -T, else /etc/ssh/sshd_config + sshd_config.d/*.conf", "sshd_config where world-readable (Debian, Ubuntu)", "root for sshd -T and on RHEL-like systems (sshd_config is 0600)"},
	{"ssh.failed_logins", "journalctl _COMM=sshd (24 h, count only), else /var/log/auth.log or /var/log/secure", "-", "group systemd-journal (or adm for auth.log); root for /var/log/secure"},
	{"tls.certificate_expiry (gateway)", "certificate files of --cert globs (Let's Encrypt, Caddy); key files are never opened", "Caddy store when readable by the user", "root for /etc/letsencrypt/live (0700)"},
	{"logs.*", "/etc/docker/daemon.json, /var/lib/docker/containers/*/hostconfig.json (LogConfig only) and the size of *-json.log by stat; journald.conf and drop-ins, size of /var/log/journal; logrotate binary, timer link or cron.daily, mtime of the status file, /etc/logrotate.conf and logrotate.d/*; schild's Caddyfile (output files); a stat walk of /var/log (depth 4, 5000 entries, 200 ms). Never runs logrotate or docker, never the Docker socket, never reads a log file", "everything but Docker containers", "root for /var/lib/docker/containers and root-only log directories"},
	{"software.* and inventory", "dpkg-query -W or rpm -qa (filtered, as nobody), <java home>/release, node/php/python3 --version (as nobody; java -version only without a release file), version files under --app paths only", "everything world-readable", "read access to the app directories (e.g. group www-data)"},
}

// PrintPrivileges writes the table.
func PrintPrivileges(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tREADS\tWITHOUT EXTRA RIGHTS\tNEEDS FOR THE REST")
	for _, p := range Privileges {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Check, p.Reads, p.Without, p.Needs)
	}
	_ = tw.Flush()
	fmt.Fprintln(w, "\nCommands the check may run (fixed argv, nothing else; [nobody]: run as uid/gid 65534 when the check runs as root):")
	for _, c := range Commands {
		argv := c.Argv
		if c.ID == CmdDnfUpdates.ID || c.ID == CmdDnfUpdatesPlatform.ID {
			argv = append(append([]string{}, argv[:len(argv)-1]...), "<fixed hawkey script, see dnfscript.go>")
		}
		line := "  " + strings.Join(argv, " ")
		if c.Unprivileged {
			line += "  [nobody]"
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "Never: apt update, dnf, yum, needs-restarting, installs, writes outside the report directory (besides removing the -trigger-file request), network access, opening anything but regular files and directories.")
}
