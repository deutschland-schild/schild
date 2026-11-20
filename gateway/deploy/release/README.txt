Schild Gateway (schild)
=======================

Reverse proxy with a web application firewall (Caddy, Coraza, OWASP CRS) and
a local dashboard. The OWASP CRS and your own rules block known attacks from
the start, and the limits for login, password reset and xmlrpc.php limit.
Four of five scenarios block after 14 days of learning. CrowdSec rules and
the other limits only record until you switch them in the dashboard.

Docs:    https://deutschland-schild.de/doku
Source:  https://github.com/deutschland-schild/schild
Issues:  https://github.com/deutschland-schild/schild/issues
Security reports: see SECURITY.md in the repository (not a public issue)

Files
-----

schild                  static binary for Linux, release build, dashboard embedded
schild.service          systemd unit, runs schild as the user "schild"
schild-firewall.service optional systemd unit for "schild firewall run" (nftables)
geo/                    IP geolocation data (DB-IP Lite, CC BY 4.0, see geo/ATTRIBUTION.txt)
LICENSE                 MIT license of schild
NOTICE                  copyright and third-party notices
THIRD_PARTY_LICENSES    license texts of every Go module and dashboard package in the binary

Install with systemd
--------------------

  sudo install -m 0755 schild /usr/local/bin/schild
  sudo install -m 0644 schild.service /etc/systemd/system/schild.service
  sudo install -d /usr/share/schild/geo
  sudo install -m 0644 geo/* /usr/share/schild/geo/
  sudo useradd --system --home-dir /var/lib/schild --create-home --shell /usr/sbin/nologin schild
  sudo systemctl daemon-reload

The geo data is optional: without it schild runs, shows no countries and
reports the missing data in the dashboard. Then pick one of the two setups.

A. You run Caddy: schild as your Caddy
--------------------------------------

schild is a Caddy distribution: Caddy with the WAF module built in. It
loads your Caddyfile, serves your sites on ports 80 and 443 and keeps
using your certificates. The OWASP CRS blocks known attacks from the start,
and schild is your web server from then on: while schild is down, your sites
are down.

  sudo /usr/local/bin/schild init -caddyfile /etc/caddy/Caddyfile

init writes /etc/schild/schild.yaml and prints what is left to do. It never
changes your Caddyfile:

  1. Add the lines it lists to the Caddyfile: the snippet

       (schild) {
           schild
       }

     once, and "import schild" in every site block that reaches a backend.
     Do not restart Caddy with these lines: it does not know "schild".
  2. Copy Caddy's certificate storage (init names the directory it found;
     this is the one of the Caddy package). schild works on the copy, so
     nothing is issued again and Caddy's own storage stays as it is:

       sudo mkdir -p /var/lib/schild/caddy
       sudo cp -a /var/lib/caddy/.local/share/caddy/. /var/lib/schild/caddy/
       sudo chown -R schild:schild /var/lib/schild/caddy

  3. Check as the service user, while Caddy still runs:

       sudo -u schild /usr/local/bin/schild ingress validate

     It checks the Caddyfile, the data directory, the copy of the
     certificates and the log files, and has to end with "result: PASS".
     On "result: REFUSE" do not swap yet; the line above names the
     reason, what it would mean and the command that fixes it.

  4. Swap (a moment without a web server):

       sudo systemctl disable --now caddy && sudo systemctl enable --now schild

The way back: put a "#" in front of the line "schild" inside the (schild)
snippet, then

  sudo systemctl disable --now schild && sudo systemctl enable --now caddy

schild runs as the user "schild", not as "caddy". Whatever your Caddyfile
needs beyond reading files everyone may read has to be given to that user.
Step 3 checks it and names the commands:

  - log files: sudo chown -R schild /var/log/caddy (the unit allows writing
    there; another directory needs a drop-in with ReadWritePaths, see
    schild.service). On the way back: sudo chown -R caddy /var/log/caddy
  - a php-fpm socket: the user schild needs its group, on Debian and Ubuntu
    usually sudo usermod -aG www-data schild

B. You run nginx, Apache or a load balancer: schild behind it
-------------------------------------------------------------

  sudo /usr/local/bin/schild init -upstream http://127.0.0.1:3000
  sudo systemctl enable --now schild

schild listens on port 8080 and passes requests on to the upstream. Nothing
changes for your visitors until your web server passes requests to port
8080. The way back: point the web server at the application again, then
sudo systemctl disable --now schild.

Dashboard
---------

The user "schild" must be able to read /etc/schild/schild.yaml. The
dashboard listens on 127.0.0.1:8788 only; from your own machine reach it
through a tunnel:

  ssh -N -L 8788:127.0.0.1:8788 you@your-server

Print the one-time code for the first login (it works until a password is
set; the start log has it too, in the field setup_code):

  sudo /usr/local/bin/schild dashboard setup-code

Allow your own address, from an SSH session on the server (sudo does not
pass SSH_CONNECTION on, so "sudo schild allow --mine" finds no address):

  sudo /usr/local/bin/schild allow "${SSH_CONNECTION%% *}"

Check and stop
--------------

  schild version
  systemctl status schild
  sudo systemctl disable --now schild

Verify the download
-------------------

  cosign verify-blob --bundle checksums.txt.sigstore.json \
    --certificate-identity-regexp '^https://github.com/deutschland-schild/schild/.github/workflows/release.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
  sha256sum -c --ignore-missing checksums.txt
  gh attestation verify schild_*_linux_*.tar.gz --repo deutschland-schild/schild
