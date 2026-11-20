package hostcheck

import (
	"regexp"
	"strconv"
	"strings"
)

// The gateway's own catalogue of findings (MVP-11 review, finding 7).
//
// A report from an agent is signed by an enrolled key, but its free text
// (title, explanation, fix_command) is whatever that agent's binary wrote: a
// compromised app VM could put a harmful command next to a copy button. The
// dashboard therefore shows, for agent reports, the title and explanation
// of this catalogue (keyed by finding id, written by the gateway's binary)
// and offers a copy button only for a fix command that this binary's own
// checks produce for that id (KnownFix). Agent text is shown marked as
// "vom Agent gemeldet".

// CatalogueEntry is the gateway-side text of one finding id.
type CatalogueEntry struct {
	Title       string
	Explanation string
}

// Catalogue has one entry per finding id of the check (a test keeps it
// complete).
var Catalogue = map[string]CatalogueEntry{
	"distribution.eol":             {"Supportende der Distribution", "Der Check vergleicht die Version der Distribution mit der mitgelieferten Liste der Supportenden. Nach dem Supportende kommen keine Sicherheitsupdates mehr."},
	"distribution.kernel_outdated": {"Laufender Kernel", "Der Check prüft, ob ein neuerer Kernel installiert ist, als gerade läuft. Der neue Kernel wirkt erst nach einem Neustart."},
	"updates.security_pending":     {"Ausstehende Sicherheitsupdates", "Der Check liest aus dem vorhandenen Paket-Cache, ob für installierte Pakete Sicherheitskorrekturen bereitstehen. Bis sie eingespielt sind, bleiben bekannte Lücken offen."},
	"updates.pending":              {"Weitere ausstehende Updates", "Der Check liest aus dem vorhandenen Paket-Cache, ob es weitere Updates gibt, etwa Fehlerkorrekturen."},
	"updates.automatic":            {"Automatische Updates", "Der Check prüft, ob Sicherheitsupdates von selbst eingespielt werden (unattended-upgrades, dnf-automatic)."},
	"updates.reboot_required":      {"Neustart nach Updates", "Der Check prüft, ob ein eingespieltes Update erst nach einem Neustart wirkt, etwa ein Kernel oder eine Systembibliothek."},
	"ports.public_service":         {"Dienst von außen erreichbar", "Der Check listet Dienste, die auf einer Netzwerkadresse statt nur lokal lauschen. Was niemand von außen braucht, gehört an localhost oder hinter die Firewall."},
	"ports.docker_api":             {"Docker-Schnittstelle im Netz", "Der Check prüft, ob die Docker-Schnittstelle über TCP erreichbar ist. Wer sie erreicht, kann den Server übernehmen."},
	"ports.admin_panel":            {"Verwaltungsoberfläche im Netz", "Der Check sucht nach Verwaltungsoberflächen (etwa phpMyAdmin, Portainer), die von außen erreichbar sind. Sie sind ein beliebtes Ziel für Passwort-Raten."},
	"firewall.active":              {"Firewall", "Der Check prüft, ob eine Firewall eingehende Verbindungen filtert (ufw, firewalld oder eigene Regeln)."},
	"firewall.default_incoming":    {"Standardregel für eingehende Verbindungen", "Der Check prüft, ob die Firewall eingehende Verbindungen standardmäßig ablehnt und nur Freigegebenes durchlässt."},
	"firewall.docker_bypass":       {"Docker umgeht die Firewall", "Der Check prüft, ob von Docker veröffentlichte Ports an ufw oder firewalld vorbei erreichbar sind."},
	"ssh.password_authentication":  {"SSH-Anmeldung mit Passwort", "Der Check prüft, ob sich jemand per SSH mit einem Passwort anmelden kann. Schlüssel sind gegen Passwort-Raten sicher."},
	"ssh.permit_root_login":        {"SSH-Anmeldung als root", "Der Check prüft, ob root sich per SSH direkt anmelden darf."},
	"ssh.port":                     {"SSH-Port", "Der Check zeigt, auf welchem Port SSH lauscht."},
	"ssh.failed_logins":            {"Fehlgeschlagene SSH-Anmeldungen", "Der Check zählt fehlgeschlagene SSH-Anmeldungen der letzten 24 Stunden (nur die Anzahl)."},
	"tls.certificate_expiry":       {"Ablauf der Zertifikate", "Der Check liest das Ablaufdatum der Zertifikate deiner Websites aus den Zertifikatsdateien."},
	"software.runtime_eol":         {"Laufzeitumgebung ohne Pflege", "Der Check vergleicht erkannte Laufzeitumgebungen (PHP, Node.js, Python, Java) mit der mitgelieferten Liste der Supportenden."},
	"software.server_eol":          {"Server-Software ohne Pflege", "Der Check vergleicht erkannte Server-Software (nginx, Apache, Tomcat) mit der mitgelieferten Liste der Supportenden."},
	"software.database_eol":        {"Datenbank ohne Pflege", "Der Check vergleicht erkannte Datenbanken mit der mitgelieferten Liste der Supportenden."},
	"software.app_outdated":        {"Anwendung", "Der Check liest die Version erkannter Anwendungen (WordPress, TYPO3, Laravel, Nextcloud) unter den angegebenen Pfaden."},
	// Area logs (v0.5, D38): texts of the MVP-11 addendum "Log-Hygiene".
	"logs.docker_unbounded":  {"Container-Logs ohne Obergrenze", "Der Check liest die Log-Einstellungen von Docker und jedem Container und die Größe der Logdateien. Mit einer Grenze behält Docker nur die letzten Dateien. Die Grenze gilt nur für neu gestartete Container, deploye danach also neu."},
	"logs.journald_size":     {"Größe des Journals", "Der Check vergleicht die Größe von /var/log/journal mit der Platte und liest die Grenzen in journald.conf. Eine feste Obergrenze hält das Journal kleiner."},
	"logs.logrotate_missing": {"logrotate läuft täglich", "Der Check prüft, ob logrotate installiert ist und über den Timer oder cron regelmäßig läuft. Sonst werden Logdateien unter /var/log nicht gekürzt."},
	"logs.logrotate_stale":   {"Letzter Lauf von logrotate", "Der Check liest, wann logrotate zuletzt gelaufen ist. Normal ist einmal am Tag. sudo logrotate -d /etc/logrotate.conf zeigt, woran es hängt, ohne etwas zu rotieren."},
	"logs.logrotate_config":  {"Regeln von logrotate", "Der Check prüft die Regeldateien von logrotate: Dateien, die logrotate überspringt, doppelte Logpfade und ob das Access-Log von Caddy mit copytruncate rotiert wird."},
	"logs.large_file":        {"Große Logdatei ohne Rotation", "Der Check sieht sich die Größe der Dateien unter /var/log an (nie ihren Inhalt) und wie stark sie seit dem letzten Check gewachsen sind. Eine logrotate-Regel hält eine Logdatei klein."},
}

// Fix commands the checks produce. Exact strings, or patterns whose
// variable parts are only digits or one of a few fixed words.
var (
	fixExact = map[string][]string{
		"distribution.kernel_outdated": {fixReboot},
		"updates.reboot_required":      {fixReboot},
		"updates.security_pending":     {aptFix, dnfSecFix},
		"updates.pending":              {aptFix, dnfFix},
		"updates.automatic":            {fixAptAutomatic, fixDnfAutomatic, fixYumCron},
		"firewall.active":              {fixUfwOn, fixFirewalldOn},
		"firewall.default_incoming":    {fixUfwOn, fixFirewalldOn},
		"tls.certificate_expiry":       {fixCertbot, fixCaddyReload},
		"logs.journald_size":           {fixJournaldRestart},
		"logs.logrotate_missing":       {fixLogrotateApt, fixLogrotateDnf, fixLogrotateTimer},
		"logs.logrotate_stale":         {fixLogrotateDebug},
	}
	fixLogrotateConfRe = regexp.MustCompile(`^sudo (chmod 0644|chown root:root) /etc/logrotate\.(conf|d/[A-Za-z0-9._@+-]{1,64})$`)
	fixPortRe          = regexp.MustCompile(`^(sudo ufw deny [0-9]{1,5}/tcp|sudo firewall-cmd --permanent --remove-port=[0-9]{1,5}/tcp && sudo firewall-cmd --reload)$`)
	fixSSHRe           = regexp.MustCompile(`^(echo '(PasswordAuthentication no|KbdInteractiveAuthentication no|PermitRootLogin prohibit-password)' \| sudo tee -a /etc/ssh/sshd_config\.d/00-schild\.conf|` +
		`sudo sed -i 's/\^#\\\?(PasswordAuthentication|KbdInteractiveAuthentication|PermitRootLogin) \.\*/(PasswordAuthentication no|KbdInteractiveAuthentication no|PermitRootLogin prohibit-password)/' /etc/ssh/sshd_config)` +
		` && sudo sshd -t && sudo systemctl reload (ssh|sshd)$`)
	// fixFirewallOn with sshd on a port other than 22.
	fixFirewallPortRe = regexp.MustCompile(`^(sudo apt install ufw && sudo ufw allow [0-9]{1,5}/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable|` +
		`sudo dnf install firewalld && sudo firewall-offline-cmd --add-port=[0-9]{1,5}/tcp && sudo systemctl enable --now firewalld)$`)
	fixPatterns = map[string]*regexp.Regexp{
		"firewall.active":             fixFirewallPortRe,
		"firewall.default_incoming":   fixFirewallPortRe,
		"ports.public_service":        fixPortRe,
		"ports.admin_panel":           fixPortRe,
		"ssh.password_authentication": fixSSHRe,
		"ssh.permit_root_login":       fixSSHRe,
		"logs.logrotate_config":       fixLogrotateConfRe,
	}
)

const (
	fixReboot       = "sudo systemctl reboot"
	dnfFix          = "sudo dnf upgrade"
	dnfSecFix       = "sudo dnf upgrade --security"
	fixAptAutomatic = "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
	fixDnfAutomatic = "sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer"
	fixYumCron      = "sudo yum install yum-cron && sudo sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf && sudo systemctl enable --now yum-cron"
	fixUfwOn        = "sudo apt install ufw && sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable"
	fixFirewalldOn  = "sudo dnf install firewalld && sudo systemctl enable --now firewalld"
	fixCertbot      = "sudo certbot renew"
	fixCaddyReload  = "sudo systemctl reload caddy"
)

// KnownFix reports whether cmd is a fix command this binary's checks
// produce for finding id.
func KnownFix(id, cmd string) bool {
	for _, x := range fixExact[id] {
		if cmd == x {
			return true
		}
	}
	if re := fixPatterns[id]; re != nil {
		return re.MatchString(cmd)
	}
	return false
}

// fixFirewallOn is the fix that switches a firewall on. fixUfwOn opens port
// 22 and firewalld's default zone allows the ssh service (port 22) before
// the firewall starts; with sshd on another port (sshPort from the SSH
// check, 0 when unknown) that port is opened instead, or the fix would lock
// the user out.
func fixFirewallOn(family string, sshPort int) string {
	custom := sshPort > 0 && sshPort < 65536 && sshPort != 22
	p := strconv.Itoa(sshPort)
	switch {
	case family == "rhel" && custom:
		return "sudo dnf install firewalld && sudo firewall-offline-cmd --add-port=" + p + "/tcp && sudo systemctl enable --now firewalld"
	case family == "rhel":
		return fixFirewalldOn
	case custom:
		return strings.Replace(fixUfwOn, "ufw allow 22/tcp", "ufw allow "+p+"/tcp", 1)
	}
	return fixUfwOn
}
