#!/usr/bin/env bash
set -euo pipefail

# Enforces strict dual-stack IPv4 + IPv6 egress isolation on honeypot trap containers
# so even a compromised container inside trap_isolated_net cannot dial C2 or internal metadata.
TRAP_BRIDGE_IF="${TRAP_BRIDGE_IF:-br-trap}"
HONEYPOT_UID="${HONEYPOT_UID:-$(id -u honeypot 2>/dev/null || echo 1000)}"

if ! command -v nft >/dev/null 2>&1; then
  echo "nftables (nft) binary is required" >&2
  exit 1
fi

nft -f - <<EOF
table inet honeypot_isolation
delete table inet honeypot_isolation

table inet honeypot_isolation {
    chain input_host_protect {
        type filter hook input priority filter - 10; policy accept;
        iifname "${TRAP_BRIDGE_IF}" ct state established,related accept
        iifname "${TRAP_BRIDGE_IF}" counter drop
    }

    chain forward_egress_drop {
        type filter hook forward priority filter - 10; policy accept;
        iifname "${TRAP_BRIDGE_IF}" ct state established,related accept
        iifname "${TRAP_BRIDGE_IF}" ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } counter drop
        iifname "${TRAP_BRIDGE_IF}" ip6 daddr { ::1/128, fe80::/10, fc00::/7, 64:ff9b::/96 } counter drop
        iifname "${TRAP_BRIDGE_IF}" ct state new counter drop
    }

    chain postrouting_clamp {
        type filter hook output priority filter - 10; policy accept;
        ip daddr 169.254.169.254 skuid ${HONEYPOT_UID} counter reject
        ip6 daddr fd00:ec2::254 skuid ${HONEYPOT_UID} counter reject
    }
}
EOF

echo "Applied dual-stack nftables inet trap egress isolation for ${TRAP_BRIDGE_IF}"
