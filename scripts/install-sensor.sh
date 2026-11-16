#!/usr/bin/env bash
set -euo pipefail

# Sensor VPS 1-Line Bootstrap Installer (NO VPN Required — Direct mTLS 1.3 via Hive :9443)
HIVE_ADDR="${HIVE_ADDR:-}"
HIVE_SNI="${HIVE_SNI:-hive.internal}"
ENROLL_SNI="${ENROLL_SNI:-enroll.hive.internal}"
ENROLL_TOKEN="${ENROLL_TOKEN:-}"
CA_FINGERPRINT="${CA_FINGERPRINT:-}"
PUBLIC_IPV4="${PUBLIC_IPV4:-$(curl -fsSL https://api.ipify.org 2>/dev/null || true)}"
AI_GATEWAY_URL="${AI_GATEWAY_URL:-https://ai-proxy.internal-gw.local}"
STATE_DIR="${STATE_DIR:-/var/lib/honeypot-sensor}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

if [[ -z "${HIVE_ADDR}" || -z "${ENROLL_TOKEN}" || -z "${CA_FINGERPRINT}" ]]; then
  echo "Usage: HIVE_ADDR=<hive-domain:9443> ENROLL_TOKEN=<hpj_...> CA_FINGERPRINT=<sha256> $0" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root on the dedicated Sensor VPS." >&2
  exit 1
fi

id -u honeypot >/dev/null 2>&1 || useradd -r -m -u 1000 -s /usr/sbin/nologin honeypot
mkdir -p "${STATE_DIR}/traps" "${STATE_DIR}/artifacts" "${STATE_DIR}/certmagic"
chown -R honeypot:honeypot "${STATE_DIR}"

if [[ -f ./bin/docker-guard-proxy ]]; then
  install -m 0755 ./bin/docker-guard-proxy "${INSTALL_DIR}/docker-guard-proxy"
fi
if [[ -f ./bin/sensor-agent ]]; then
  install -m 0755 ./bin/sensor-agent "${INSTALL_DIR}/sensor-agent"
fi

# Apply egress nftables lockdown if available
if [[ -x ./scripts/lockdown-nftables.sh ]]; then
  ./scripts/lockdown-nftables.sh
fi

# Enroll node over SNI enroll.<hive> with pinned Root CA SHA-256 fingerprint
sudo -u honeypot "${INSTALL_DIR}/sensor-agent" \
  --state-dir "${STATE_DIR}" \
  --hive-addr "${HIVE_ADDR}" \
  --hive-sni "${HIVE_SNI}" \
  --enroll-sni "${ENROLL_SNI}" \
  --enroll-token "${ENROLL_TOKEN}" \
  --ca-fingerprint "${CA_FINGERPRINT}" \
  --public-ipv4 "${PUBLIC_IPV4}" \
  --ai-gateway-url "${AI_GATEWAY_URL}"

cat >/etc/systemd/system/honeypot-docker-guard.service <<EOF
[Unit]
Description=Honeypot Schema-Enforcing Docker Socket Proxy
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/docker-guard-proxy --listen 127.0.0.1:23750 --allowed-bind-root ${STATE_DIR}/traps
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/honeypot-sensor.service <<EOF
[Unit]
Description=Honeypot Deception Sensor Agent
After=network-online.target honeypot-docker-guard.service
Requires=honeypot-docker-guard.service

[Service]
Type=simple
User=honeypot
Group=honeypot
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${INSTALL_DIR}/sensor-agent --state-dir ${STATE_DIR} --hive-addr ${HIVE_ADDR} --hive-sni ${HIVE_SNI} --enroll-sni ${ENROLL_SNI} --ai-gateway-url ${AI_GATEWAY_URL} --docker-proxy http://127.0.0.1:23750 --http-addr :80 --https-addr :443
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-docker-guard.service honeypot-sensor.service
echo "Honeypot Sensor enrolled and started cleanly (LimitNOFILE=65536)."
