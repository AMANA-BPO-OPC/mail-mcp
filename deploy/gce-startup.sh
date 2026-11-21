#!/bin/bash
# Mail MCP server bootstrap. Safe to re-run on every boot.
set -e
APP=/opt/mail-mcp
for i in $(seq 1 30); do
  if command -v caddy >/dev/null && dpkg -s python3-venv >/dev/null 2>&1; then break; fi
  (apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv caddy) && break || sleep 20
done
mkdir -p $APP /var/lib/mail-mcp
rm -rf /tmp/mm && mkdir -p /tmp/mm && curl -fsSL https://github.com/AMANA-BPO-OPC/mail-mcp/archive/refs/heads/main.tar.gz | tar -xz -C /tmp/mm --strip-components=1 && rm -rf $APP/app && cp -r /tmp/mm/app /tmp/mm/requirements.txt $APP/
id mailmcp >/dev/null 2>&1 || useradd --system --home /var/lib/mail-mcp --shell /usr/sbin/nologin mailmcp
chown -R mailmcp /var/lib/mail-mcp
[ -x $APP/venv/bin/python ] || python3 -m venv $APP/venv
$APP/venv/bin/pip install -q --upgrade pip
$APP/venv/bin/pip install -q -r $APP/requirements.txt
if [ ! -f /etc/mail-mcp.env ]; then
  KEY=$($APP/venv/bin/python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())")
  umask 077
  cat > /etc/mail-mcp.env <<ENV
PUBLIC_URL=https://mail-mcp.s4l.us
ENCRYPTION_KEY=$KEY
SESSION_SECRET=$(openssl rand -hex 32)
SETUP_CODE=$(openssl rand -hex 6)
GOOGLE_CLIENT_ID=795693787613-mig2fs1cpbfaekn3rsf3147pigmua4bg.apps.googleusercontent.com
DB_PATH=/var/lib/mail-mcp/db.sqlite3
HOST=127.0.0.1
PORT=8000
ENV
fi
cat > /etc/systemd/system/mail-mcp.service <<UNIT
[Unit]
Description=Multi-account Gmail MCP server
After=network-online.target
[Service]
User=mailmcp
EnvironmentFile=/etc/mail-mcp.env
WorkingDirectory=$APP
ExecStart=$APP/venv/bin/python -m app.main
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/mail-mcp
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/caddy/Caddyfile <<CADDY
mail-mcp.s4l.us {
    reverse_proxy 127.0.0.1:8000
}
CADDY
systemctl daemon-reload
systemctl enable mail-mcp caddy
systemctl restart mail-mcp
systemctl reload caddy || systemctl restart caddy
echo "MAIL-MCP BOOTSTRAP DONE"
