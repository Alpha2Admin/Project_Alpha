#!/bin/bash
# ============================================================
#  SPLUNK VM — Static IP Assignment
#  Run this script DIRECTLY on the Splunk VM console
#  Target IP: 192.168.100.20
# ============================================================
set -e

NIC=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
echo "[*] Detected NIC: $NIC"

cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $NIC:
      dhcp4: no
      addresses:
        - 192.168.100.20/24
      routes:
        - to: default
          via: 192.168.100.2
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
EOF

chmod 600 /etc/netplan/00-installer-config.yaml

hostnamectl set-hostname splunk-siem
echo "192.168.100.20 splunk-siem" >> /etc/hosts

rm -f /etc/machine-id /var/lib/dbus/machine-id
systemd-machine-id-setup
echo "[*] New machine-id: $(cat /etc/machine-id)"

netplan apply
echo ""
echo "✅ Splunk VM IP set to 192.168.100.20"
echo "   Hostname: splunk-siem"
ip addr show $NIC | grep "inet "
