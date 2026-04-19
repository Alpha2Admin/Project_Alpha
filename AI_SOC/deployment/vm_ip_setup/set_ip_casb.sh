#!/bin/bash
# ============================================================
#  AI-CASB VM — Static IP Assignment
#  Run this script DIRECTLY on the AI_CASB VM console
#  Target IP: 192.168.100.10
# ============================================================
set -e

NIC=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
echo "[*] Detected NIC: $NIC"

# Write netplan config
cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $NIC:
      dhcp4: no
      addresses:
        - 192.168.100.10/24
      routes:
        - to: default
          via: 192.168.100.2
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
EOF

chmod 600 /etc/netplan/00-installer-config.yaml

# Set unique hostname
hostnamectl set-hostname ai-casb
echo "192.168.100.10 ai-casb" >> /etc/hosts

# Generate new machine-id (important — clones share the same machine-id)
rm -f /etc/machine-id /var/lib/dbus/machine-id
systemd-machine-id-setup
echo "[*] New machine-id: $(cat /etc/machine-id)"

# Apply
netplan apply
echo ""
echo "✅ AI_CASB VM IP set to 192.168.100.10"
echo "   Hostname: ai-casb"
ip addr show $NIC | grep "inet "
