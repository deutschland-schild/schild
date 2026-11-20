#!/bin/sh
# TEST ONLY: plants extra secret canaries in a disposable app VM container
# (schild-testlab-app-vm:dev) beyond the ones the image ships with
# (testlab/internal/hostcanary). Every value contains "rvwcanary" so one grep
# finds any leak. Runs inside the container as root.
set -eu
# sshd: secrets in a comment, in a command option and in an Include'd file.
cat > /etc/ssh/sshd_config.d/10-review.conf <<'X'
# deploy token=rvwcanary-sshd-comment-a1
AuthorizedKeysCommand /usr/local/bin/keys --token=rvwcanary-sshd-akc-a2
AuthorizedKeysCommandUser nobody
X
# MariaDB client credentials (classic Debian maintenance file).
mkdir -p /etc/mysql
printf '[client]\nuser = debian-sys-maint\npassword = rvwcanary-mysql-b1\n' > /etc/mysql/debian.cnf
chmod 600 /etc/mysql/debian.cnf
# A combined certificate + private key file for the TLS check (--cert glob):
# run.sh copies a fresh self-signed cert + key (with a canary comment) to
# /etc/ssl/review/site.pem before this script runs.
# A listening service with a token in its command line and environment.
cat > /usr/local/bin/rvw-svc <<'X'
#!/bin/sh
exec env RVW_API_TOKEN=rvwcanary-proc-env-d1 php -d x.token=rvwcanary-proc-argv-d2 -S 0.0.0.0:8099 -t /tmp
X
chmod 755 /usr/local/bin/rvw-svc
nohup /usr/local/bin/rvw-svc >/dev/null 2>&1 &
# Laravel app with secrets in .env.
mkdir -p /var/www/laravel
touch /var/www/laravel/artisan
printf 'APP_KEY=base64:rvwcanary-laravel-key-e1\nDB_PASSWORD=rvwcanary-laravel-db-e2\n' > /var/www/laravel/.env
printf '{"packages":[{"name":"laravel/framework","version":"v10.48.4"}]}\n' > /var/www/laravel/composer.lock
# Root's shell history and an SSH private key.
echo 'mysql -uroot -prvwcanary-history-f1' > /root/.bash_history
mkdir -p /root/.ssh && printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nrvwcanary-ssh-key-f2\n-----END OPENSSH PRIVATE KEY-----\n' > /root/.ssh/id_ed25519
chmod 600 /root/.ssh/id_ed25519
# A WordPress plugin with a secret in its option file next to the header.
mkdir -p /var/www/html/wp-content/plugins/rvw-plugin
printf '<?php\n/*\nPlugin Name: Review\nVersion: 1.2.3\n*/\ndefine("RVW_LICENSE_KEY", "rvwcanary-wp-plugin-g1");\n' > /var/www/html/wp-content/plugins/rvw-plugin/rvw-plugin.php
