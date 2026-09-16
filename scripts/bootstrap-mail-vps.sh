#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/bootstrap-mail-vps.sh"
  exit 1
fi

apt-get update
apt-get install -y ca-certificates curl gnupg ufw

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

. /etc/os-release
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 25/tcp comment 'SMTP server-to-server'
ufw allow 443/tcp comment 'Stalwart HTTPS/JMAP'
ufw allow 465/tcp comment 'SMTPS submission'
ufw allow 587/tcp comment 'SMTP submission'
ufw allow 993/tcp comment 'IMAPS'
ufw allow 4190/tcp comment 'ManageSieve'
ufw --force enable

mkdir -p /opt/quanticmail
cp docker-compose.production.yml /opt/quanticmail/docker-compose.yml
cd /opt/quanticmail

docker compose pull
docker compose up -d

echo
echo "QuanticMail Stalwart container started."
echo "Bootstrap admin credentials:"
docker logs quanticmail-stalwart 2>&1 | grep -A8 'bootstrap mode' || true

echo
echo "Initial setup is intentionally bound to localhost:8080."
echo "Use an SSH tunnel: ssh -L 8080:127.0.0.1:8080 <user>@<vps-ip>"
echo "Then open http://127.0.0.1:8080/admin"
