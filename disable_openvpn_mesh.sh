#!/bin/bash
set -e

# Default values
pp_cert_name=""
dm_cert_name=""
ssh_cert_name=""
control_cert_name=""
edge_router_cert_name=""
eu_dm_cert_name=""

# Extract OpenVPN server IP (ex: 10.8.0.1) and subnet mask (ex: 255.255.0.0) from server.conf if available
extract_vpn_network_from_conf() {
  local conf_file="/etc/openvpn/server.conf"
  if [ -f "$conf_file" ]; then
    local line
    line=$(grep -E '^server ' "$conf_file" | head -n1)
    if [ -n "$line" ]; then
      network_addr=$(echo "$line" | awk '{print $2}')
      vpn_subnet_mask=$(echo "$line" | awk '{print $3}')
      # Calculate first usable IP (network address + 1)
      IFS=. read -r n1 n2 n3 n4 <<< "$network_addr"
      if [ "$n4" -lt 255 ]; then
        vpn_server_ip="$n1.$n2.$n3.$((n4+1))"
      else
        vpn_server_ip="$network_addr" # fallback
      fi
    fi
  fi
}

# Prompt for certificate names and VPN subnet if not provided as arguments
if [ -z "$pp_cert_name" ]; then
  read -p "Enter Partner Portal OpenVPN certificate name: " pp_cert_name
fi
if [ -z "$dm_cert_name" ]; then
  read -p "Enter Device Management OpenVPN certificate name: " dm_cert_name
fi
if [ -z "$ssh_cert_name" ]; then
  read -p "Enter Controller SSH Server OpenVPN certificate name: " ssh_cert_name
fi
if [ -z "$control_cert_name" ]; then
  read -p "Enter Controls OpenVPN certificate name: " control_cert_name
fi
if [ -z "$edge_router_cert_name" ]; then
  read -p "Enter Edge Router OpenVPN certificate name: " edge_router_cert_name
fi
if [ -z "$EUC" ]; then
  read -p "Enter EU Controls Tunnel IP: " EUC
fi
if [ -z "$EUDM" ]; then
  read -p "Enter EU Device Management Tunnel IP: " EUDM
fi


# Try to extract subnet and network address from server.conf
extract_vpn_network_from_conf

# Convert subnet mask to CIDR prefix length (255.255.0.0 --> /16)
mask2cidr() {
  local mask=$1
  local IFS=.
  local i sum=0
  for i in $mask; do
    case $i in
      255) sum=$((sum+8));;
      254) sum=$((sum+7));;
      252) sum=$((sum+6));;
      248) sum=$((sum+5));;
      240) sum=$((sum+4));;
      224) sum=$((sum+3));;
      192) sum=$((sum+2));;
      128) sum=$((sum+1));;
      0);;
      *) echo "Error: Invalid subnet mask."; return 1;;
    esac
  done
  echo $sum
}

cidr=$(mask2cidr "$vpn_subnet_mask")
VPN_SUBNET="$network_addr/$cidr"

echo "OpenVPN Subnet: $VPN_SUBNET"
echo "OpenVPN Server IP: $vpn_server_ip"

# Backend tun0 IPs
PP=$(awk '{print $2}' /etc/openvpn/ccd/"$pp_cert_name")
DM=$(awk '{print $2}' /etc/openvpn/ccd/"$dm_cert_name")
SSH=$(awk '{print $2}' /etc/openvpn/ccd/"$ssh_cert_name")
C=$(awk '{print $2}' /etc/openvpn/ccd/"$control_cert_name")
ER=$(awk '{print $2}' /etc/openvpn/ccd/"$edge_router_cert_name")

echo -e "\nBackend tun0 IPs:"
echo "PP: $PP"
echo "DM: $DM"
echo "SSH: $SSH"
echo "C: $C"
echo "ER: $ER"
echo "EUDM: $EUDM"
echo "EUC: $EUC"

# Flush existing rules
delete_tun0_rules() {
  local chains=("FORWARD" "INPUT")
  for chain in "${chains[@]}"; do
    while true; do
      num=$(sudo iptables -L $chain -v -n --line-numbers | grep "tun0" | head -n 1 | awk '{print $1}')
      [ -z "$num" ] && break
      echo "Deleting rule #$num"
      sudo iptables -D $chain $num
    done
  done
}

delete_tun0_rules
# Default policies
sudo iptables -P FORWARD DROP

echo "Applying OpenVPN isolation rules..."

# Block backend-to-backend communication
sudo iptables -A FORWARD -i tun0 -s $DM -d $PP -j DROP
sudo iptables -A FORWARD -i tun0 -s $DM -d $C -j DROP
sudo iptables -A FORWARD -i tun0 -s $DM -d $SSH -j DROP
sudo iptables -A FORWARD -i tun0 -s $DM -d $ER -j DROP

sudo iptables -A FORWARD -i tun0 -s $PP -d $DM -j DROP
sudo iptables -A FORWARD -i tun0 -s $PP -d $C -j DROP
sudo iptables -A FORWARD -i tun0 -s $PP -d $SSH -j DROP
sudo iptables -A FORWARD -i tun0 -s $PP -d $ER -j DROP
sudo iptables -A FORWARD -i tun0 -s $PP -d $EUDM -j DROP

sudo iptables -A FORWARD -i tun0 -s $C -d $DM -j DROP
sudo iptables -A FORWARD -i tun0 -s $C -d $PP -j DROP
sudo iptables -A FORWARD -i tun0 -s $C -d $SSH -j DROP
sudo iptables -A FORWARD -i tun0 -s $C -d $ER -j DROP
sudo iptables -A FORWARD -i tun0 -s $C -d $EUDM -j DROP

sudo iptables -A FORWARD -i tun0 -s $SSH -d $DM -j DROP
sudo iptables -A FORWARD -i tun0 -s $SSH -d $PP -j DROP
sudo iptables -A FORWARD -i tun0 -s $SSH -d $C -j DROP
sudo iptables -A FORWARD -i tun0 -s $SSH -d $ER -j DROP
sudo iptables -A FORWARD -i tun0 -s $SSH -d $EUDM -j DROP

sudo iptables -A FORWARD -i tun0 -s $ER -d $DM -j DROP
sudo iptables -A FORWARD -i tun0 -s $ER -d $PP -j DROP
sudo iptables -A FORWARD -i tun0 -s $ER -d $C -j DROP
sudo iptables -A FORWARD -i tun0 -s $ER -d $SSH -j DROP
sudo iptables -A FORWARD -i tun0 -s $ER -d $EUDM -j DROP

# Allow backend servers to reach gateways and vice-versa
sudo iptables -A FORWARD -i tun0 -s $DM -d $EUDM -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $EUDM -d $DM -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $EUDM -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $EUDM -d $VPN_SUBNET -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $C -d $EUC -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $EUC -d $C -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $EUC -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $EUC -d $VPN_SUBNET -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $DM -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $DM -d $VPN_SUBNET -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $PP -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $PP -d $VPN_SUBNET -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $C -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $C -d $VPN_SUBNET -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $SSH -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $SSH -d $VPN_SUBNET -j ACCEPT

sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $ER -j ACCEPT
sudo iptables -A FORWARD -i tun0 -s $ER -d $VPN_SUBNET -j ACCEPT

# Allow only PP and DM to access vpn certificate api hosted on port 5000
# Docker creates its own chains (DOCKER-USER) And it inserts NAT and filter rules at the top of the INPUT chains.
# Docker never touches or overwrites this chain. It is meant exactly for custom firewall rules.
sudo iptables -I DOCKER-USER 1 -p tcp --dport 5000 -j DROP   # -I inserts the rule at the top
sudo iptables -I DOCKER-USER 1 -p tcp -s $vpn_server_ip --dport 5000 -j ACCEPT
sudo iptables -I DOCKER-USER 1 -p tcp -s $EUDM --dport 5000 -j ACCEPT
sudo iptables -I DOCKER-USER 1 -p tcp -s $PP --dport 5000 -j ACCEPT
sudo iptables -I DOCKER-USER 1 -p tcp -s $DM --dport 5000 -j ACCEPT
sudo iptables -I DOCKER-USER 1 -p tcp -s $SSH --dport 5000 -j ACCEPT

# Disable client-to-client communication (VPN mesh)
sudo iptables -A FORWARD -i tun0 -s $VPN_SUBNET -d $VPN_SUBNET -j DROP
sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"

# Create /etc/rc.local for restoring iptables rules at boot
sudo tee /etc/rc.local > /dev/null <<'EOF'
#!/bin/bash
# Restore iptables rules at boot
if [ -f /etc/iptables.ipv4.nat ]; then
    iptables-restore < /etc/iptables.ipv4.nat
fi
exit 0
EOF

sudo chmod +x /etc/rc.local

# Create systemd service for rc.local compatibility, it will run /etc/rc.local on every reboot
sudo tee /etc/systemd/system/rc-local.service > /dev/null <<'EOF'
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the rc-local service
sudo systemctl daemon-reload
sudo systemctl enable rc-local
sudo systemctl start rc-local