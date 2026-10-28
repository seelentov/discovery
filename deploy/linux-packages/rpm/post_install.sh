#!/bin/sh
# Same logic as ../debian/postinst -- see that file's comments for the reasoning.
set -e

if ! getent passwd discovery >/dev/null; then
    useradd --system --home-dir /var/lib/discovery-agent --shell /sbin/nologin discovery
fi

mkdir -p /var/lib/discovery-agent
chown -R discovery:discovery /var/lib/discovery-agent

ENV_FILE=/etc/discovery-agent/discovery.env
if [ ! -f "$ENV_FILE" ]; then
    echo "DISCOVERY_SECRET_KEY=$(openssl rand -base64 32)" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    chown discovery:discovery "$ENV_FILE"
fi

systemctl daemon-reload || true

# A fresh package install cannot start safely until the operator supplies the one-time
# bootstrap password. Do not create a failed service attempt (or ever invent a default
# password); enable it now and start it after the secret is present. Existing installs
# retain the normal automatic restart/upgrade behavior because the SQLite store exists.
DB_FILE=/var/lib/discovery-agent/discovery.sqlite3
if [ -f "$DB_FILE" ] || grep -Eq '^DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD=.+$' "$ENV_FILE"; then
    systemctl enable --now discovery-agent.service || echo "discovery-agent: could not enable/start the service automatically -- check 'systemctl status discovery-agent' and 'journalctl -u discovery-agent'"
else
    systemctl enable discovery-agent.service || echo "discovery-agent: could not enable the service automatically -- check 'systemctl status discovery-agent'"
    echo "discovery-agent: set DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD in $ENV_FILE, then run 'systemctl start discovery-agent'"
fi

exit 0
