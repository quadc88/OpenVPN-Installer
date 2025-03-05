#!/bin/bash
initialize() {
    clear

	set -e

	if [ ! -d "/var/log/openvpn/" ]; then
		mkdir -p "/var/log/openvpn/"
	fi

    # Log file path
    LOG_FILE="/var/log/openvpn/openvpn-install.log"

    # Check if running with root privileges
    if [[ $EUID -ne 0 ]]; then
        echo "This installer needs to be run with superuser privileges."
        exit 1
    fi

    # Set EASYRSA path
    EASYRSA_DIR="/etc/openvpn/easy-rsa"
	EASYRSA_vars_DIR="$EASYRSA_DIR/vars"
}

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Detect operating system
detect_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(awk -F'"' '/VERSION_ID/ {print $2}' /etc/os-release | tr -d '.')

        if [[ "$os_version" != "2004" && "$os_version" != "2204" && "$os_version" != "2404" ]]; then
            log "This script is only supported on Ubuntu 20.04, 22.04, and 24.04."
            exit 1
        fi
        group_name="nogroup"

    elif grep -qs "debian" /etc/os-release; then
        os="debian"
        os_version=$(awk -F'[/ ]' '{print $1}' /etc/debian_version | cut -d'.' -f1)

        if grep -q "/sid" /etc/debian_version || [[ "$os_version" -lt 11 ]]; then
            log "Unsupported Debian version. Please use Debian 11 or higher (stable)."
            exit 1
        fi
        group_name="nogroup"

    else
        log "This installer seems to be running on an unsupported distribution."
        exit 1
    fi
}

# Check if OpenVPN is installed
check_openvpn_installed() {
    if systemctl list-units --type=service --all | grep -q "openvpn-server@server.service"; then
		if systemctl is-active --quiet openvpn-server@server.service; then
			echo "OpenVPN Server is already installed and running."
		else
			systemctl start openvpn-server@server.service
		fi
		return 0
    else
        echo "OpenVPN Server is not installed."
        return 1
    fi
}

# Ask for OpenVPN configuration
ask_openvpn_config() {
    # Get public IP and allow user to confirm or modify
	if command -v curl >/dev/null 2>&1; then
	  default_public_ip=$(curl -s ifconfig.me || curl -s http://checkip.amazonaws.com || dig +short txt ch whoami.cloudflare @1.1.1.1 | tr -d '"' || echo "Unavailable")
	elif command -v dig >/dev/null 2>&1; then
	  default_public_ip=$(dig +short txt ch whoami.cloudflare @1.1.1.1 | tr -d '"' || echo "Unavailable")
	fi

    echo "What is the public IPv4 address or hostname?"
    read -p "Public IPv4 address / hostname [$default_public_ip]: " public_ip
    public_ip=${public_ip:-$default_public_ip}

    # Clear output
    for ((i = 0; i < 2; i++)); do
        tput cuu1
        tput el
    done

    log "User provided public IP: $public_ip"

    # Choose the local IP OpenVPN should listen on
    echo "Detecting available network interfaces..."
    declare -A ip_options
    option_index=1

    # Choose the local IP OpenVPN should listen on
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -E -v '^(lo|docker0|virbr0)$')
    for interface in $interfaces; do
        ip_list=$(ip -4 addr show "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        for ip in $ip_list; do
            ip_options["$option_index"]="$ip"
            echo "  $option_index) $ip"
            ((option_index++))
        done
    done

    # User selects the IP
    read -p "Which IPv4 address should be used? [1]: " user_choice
    user_choice=${user_choice:-1}
    local_ip=${ip_options[$user_choice]}
    
    if [[ -z "$local_ip" ]]; then
        echo "Invalid selection, using default IP."
        local_ip=${ip_options[1]}
    fi

    # Clear output
    for ((i = 0; i < option_index + 1; i++)); do
        tput cuu1
        tput el
    done

    log "Selected local IP: $local_ip"

    # Choose OpenVPN protocol
    echo "Which protocol should OpenVPN use?"
    echo "   1) UDP (recommended)"
    echo "   2) TCP"
    read -p "Protocol [1]: " protocol_choice

    case "$protocol_choice" in
        1|"") protocol="udp" ;;
        2) protocol="tcp" ;;
        *) 
            echo "Invalid option. Defaulting to UDP."
            protocol="udp"
            ;;
    esac

    # Clear output
    for ((i = 0; i < 4; i++)); do
        tput cuu1
        tput el
    done

    log "Selected protocol: $protocol"

    # Select OpenVPN port
    default_port=1194
    echo "What port should OpenVPN listen to?"
    read -p "Port [$default_port]: " port
    port=${port:-$default_port}

    # Check if the port is within the valid range (1-65535)
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        echo "Invalid port. Using default port $default_port."
        port=$default_port
    fi

    # Clear output
    for ((i = 0; i < 2; i++)); do
        tput cuu1
        tput el
    done

    log "Selected OpenVPN port: $port"

    # Select DNS server
    echo "Select a DNS server for the clients:"
    echo "   1) Google (8.8.8.8, 8.8.4.4)"
    echo "   2) Cloudflare (1.1.1.1, 1.0.0.1)"
    echo "   3) OpenDNS (208.67.222.222, 208.67.220.220)"
    echo "   4) Quad9 (9.9.9.9, 149.112.112.112)"
    echo "   5) AdGuard (94.140.14.14, 94.140.15.15)"
    read -p "DNS server [1]: " dns_choice

    case "$dns_choice" in
        1|"") 
            dns1="8.8.8.8"
            dns2="8.8.4.4"
            dns_name="Google"
            ;;
        2)
            dns1="1.1.1.1"
            dns2="1.0.0.1"
            dns_name="Cloudflare"
            ;;
        3)
            dns1="208.67.222.222"
            dns2="208.67.220.220"
            dns_name="OpenDNS"
            ;;
        4)
            dns1="9.9.9.9"
            dns2="149.112.112.112"
            dns_name="Quad9"
            ;;
        5)
            dns1="94.140.14.14"
            dns2="94.140.15.15"
            dns_name="AdGuard"
            ;;
        *) 
            echo "Invalid option. Defaulting to Current system resolvers."
            dns1=""
            dns2=""
            dns_name=""
            ;;
    esac

    # Clear output
    for ((i = 0; i < 7; i++)); do
        tput cuu1
        tput el
    done

    log "Selected DNS: $dns_name ($dns1 $dns2)"
}

# Permanently enable net.ipv4.ip_forward
enable_ip_forward() {
    log "Enabling net.ipv4.ip_forward permanently..."

    # Check if /etc/sysctl.conf is already configured
    if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]]; then
        log "net.ipv4.ip_forward=1 is already set in /etc/sysctl.conf."
    else
        # Add configuration to /etc/sysctl.conf
        echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf >> "$LOG_FILE" 2>&1
        log "Added net.ipv4.ip_forward=1 to /etc/sysctl.conf."
    fi

    # Reload sysctl configuration
    sudo sysctl -p >> "$LOG_FILE" 2>&1
    log "Reloaded sysctl configuration."

    # Check if it is enabled
    if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]]; then
        log "net.ipv4.ip_forward has been successfully enabled."
    else
        log "Failed to enable net.ipv4.ip_forward."
        exit 1
    fi
}

# Define cidr_to_netmask function
cidr_to_netmask() {
    local cidr=$1
    local mask=$(( 0xffffffff << (32 - cidr) ))
    printf "%d.%d.%d.%d\n" \
        $(( (mask >> 24) & 255 )) $(( (mask >> 16) & 255 )) \
        $(( (mask >> 8) & 255 )) $(( mask & 255 ))
}

# Define network_calculator function
network_calculator() {
    if [ -z "$1" ]; then
        echo "Usage: $0 <CIDR>"
        exit 1
    fi

    IFS=/ read -r ip cidr <<< "$1"

    # 计算子网掩码
    mask=$(( 0xFFFFFFFF << (32 - cidr) & 0xFFFFFFFF ))
    netmask="$(( (mask >> 24) & 255 )).$(( (mask >> 16) & 255 )).$(( (mask >> 8) & 255 )).$(( mask & 255 ))"

    # 计算网络地址
    IFS=. read -r i1 i2 i3 i4 <<< "$ip"
    IFS=. read -r m1 m2 m3 m4 <<< "$netmask"

    network="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))"

    # 输出计算结果
    echo "$network $netmask"
}

# Generate a new client
new_client() {
    echo "Select client type:"
    echo "   1) Regular client"
    echo "   2) Site-to-Site client"
    read -p "Option [1]: " client_type
    client_type=${client_type:-1}

    # Clear output
    for ((i = 0; i < 4; i++)); do
        tput cuu1
        tput el
    done

    # Log user selection
    if [[ "$client_type" == "2" ]]; then
        log "Selected to create Site-to-Site client"
    else
        log "Selected to create Regular client"
    fi

	while true; do
		read -p "Enter client name: " client
		# Clear output
		for ((i = 0; i < 1; i++)); do
			tput cuu1
			tput el
		done
		if [[ -n "$client" ]]; then
			break
		else
			echo "Client name cannot be empty. Please enter a valid name."
		fi
	done

    log "Creating client : $client"
    
    # Check if a client with the same name already exists, excluding revoked certificates
    if [[ -f "$EASYRSA_DIR/pki/issued/$client.crt" ]]; then
        if openssl crl -in "$EASYRSA_DIR/pki/crl.pem" -noout -text | grep -q "$(openssl x509 -in "$EASYRSA_DIR/pki/issued/$client.crt" -serial -noout | cut -d= -f2)"; then
            echo "Client '$client' was revoked. Re-issuing the certificate..."
            log "Client '$client' was revoked, reissuing certificate."
        else
            echo "Client '$client' already exists. Please choose a different name."
            log "Attempt to create duplicate client '$client' was blocked."
            return 1
        fi
    fi

	rm -f $EASYRSA_DIR/pki/vars
    log "Generating client certificate for $client..."
    # Generate client certificate
    EASYRSA_BATCH=1 "$EASYRSA_DIR/easyrsa" --pki-dir="$EASYRSA_DIR/pki" build-client-full "$client" nopass >> "$LOG_FILE" 2>&1

    log "Creating client config..."
    # Create client-config file
    client_config_file="/etc/openvpn/client/client-config/$client"

    if [[ "$client_type" == "2" ]]; then
        # Site-to-Site client configuration
        while true; do
            read -p "Enter static IP for client (e.g., 10.8.0.100, leave blank for dynamic IP): " client_ip
            
            # If user leaves it blank, skip static IP configuration
            if [[ -z "$client_ip" ]]; then
				# **Clear output**
				for ((i = 0; i < 1; i++)); do
					tput cuu1
					tput el
				done
				log "The client use dynamic IP"
                break
            fi

            # Check if the IP address is within the range 10.8.0.2-10.8.0.254
            if [[ "$client_ip" =~ ^10\.8\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]; then
                break
            else
                echo "Invalid IP address. Please enter an IP in the range 10.8.0.2-10.8.0.254."
            fi
			# **Clear output**
			for ((i = 0; i < 1; i++)); do
				tput cuu1
				tput el
			done
			log "The client use static IP : $client_ip"
        done

        while true; do
            read -p "Enter client's local network in CIDR notation (e.g., 192.168.1.0/24): " client_network_cidr

			# **Clear output**
			for ((i = 0; i < 1; i++)); do
				tput cuu1
				tput el
			done

            # Check if the input matches the CIDR format (IPv4 address + / + 1-32)
            if [[ "$client_network_cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[1-2][0-9]|3[0-2])$ ]]; then
				log "Client's local network : $client_network_cidr"
                break  # If input is valid, exit the loop
            else
                echo "❌ Invalid CIDR format. Please enter a valid CIDR (e.g., 192.168.1.0/24)."
            fi
        done

        # Extract network address and CIDR
        network_address=$(network_calculator "$client_network_cidr")

        # Iterate through all client-config files to find those containing iroute
		if [ -n "$(ls -A /etc/openvpn/client/client-config/)" ]; then
			for temp_client_config_file in /etc/openvpn/client/client-config/*; do
				if grep -q "iroute" "$temp_client_config_file"; then
					log "Found iroute in the file $temp_client_config_file, added push routing: push \"route $network_address\""
					# Add push route to the file
					echo "push \"route $network_address\"" >> "$temp_client_config_file"
				fi
			done
		fi
        
        # Record remote site network
        echo "push \"route $network_address\"" >> "/etc/openvpn/client/00-remote-site-network.txt"
        
        # If client_ip is not empty, add ifconfig-push
        if [[ -n "$client_ip" ]]; then
            echo "ifconfig-push $client_ip 255.255.255.0" > "$client_config_file"
        fi

        # Add iroute and push "route"
        echo "iroute $network_address" >> "$client_config_file"
        echo "push \"route-nopull\"" >> "$client_config_file"
        echo "push \"route 10.8.0.0 255.255.255.0\"" >> "$client_config_file"
        cat "/etc/openvpn/client/00-remote-site-network.txt" >> "$client_config_file"
		
		# Add routing
		echo "/sbin/ip route add $client_network_cidr dev tun0" >> "/etc/openvpn/server/add-routes.sh"

        # Generate OVPN configuration file
        ovpn_file="$client-site-to-site.ovpn"
    else
        touch "$client_config_file"
        # Regular client configuration
        ovpn_file="$client.ovpn"
    fi

    # Generate OVPN configuration file
    {
        cat /etc/openvpn/server/client-sample.txt
        echo "<ca>"
        cat "$EASYRSA_DIR/pki/ca.crt"
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' "$EASYRSA_DIR/pki/issued/$client.crt"
        echo "</cert>"
        echo "<key>"
        cat "$EASYRSA_DIR/pki/private/$client.key"
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' "$EASYRSA_DIR/pki/tc.key"
        echo "</tls-crypt>"
    } > /etc/openvpn/client/"$ovpn_file"

    systemctl stop openvpn-server@server.service
    systemctl start openvpn-server@server.service
    log "Client configuration file /etc/openvpn/client/$ovpn_file created successfully."
}

# Install OpenVPN
install_openvpn() {
    log "Starting OpenVPN installation..."

    ask_openvpn_config
    
	# Update system packages
	log "Updating system packages..."
	apt update -q >> "$LOG_FILE" 2>&1 || { log "Failed to update package list"; exit 1; }
	apt upgrade -y -q >> "$LOG_FILE" 2>&1 || { log "Failed to upgrade packages"; exit 1; }

    # Install necessary dependencies
    log "Installing dependencies..."
	if [[ "$os" = "ubuntu" ]]; then
		apt install -y -q openvpn easy-rsa >> "$LOG_FILE" 2>&1
	elif [[ "$os" = "debian" ]]; then
		apt install -y -q openvpn easy-rsa ufw >> "$LOG_FILE" 2>&1
	fi
    
    if [[ ! -d "$EASYRSA_DIR" ]]; then
        mkdir -p "$EASYRSA_DIR"
        cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"
        chown -R root:root "$EASYRSA_DIR"
        chmod -R 700 "$EASYRSA_DIR"
    else
        log "EasyRSA directory already exists."
    fi

    mkdir -p /etc/openvpn/client/client-config
    
    # Configure OpenVPN
    log "Configuring OpenVPN..."

	# Edit vars file
	log "Configuring vars file..."
cat <<EOF > "$EASYRSA_vars_DIR"
set_var EASYRSA_REQ_COUNTRY    "MY"
set_var EASYRSA_REQ_PROVINCE   "Wilayah Persekutuan"
set_var EASYRSA_REQ_CITY       "Kuala Lumpur"
set_var EASYRSA_REQ_ORG        "OpenVPN"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "Community"
EOF

    # Initialize PKI
	log "Initializing PKI..."
	EASYRSA_BATCH=1 EASYRSA_VARS_FILE="$EASYRSA_vars_DIR" $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" init-pki >> "$LOG_FILE" 2>&1

    # Build CA
    log "Building CA..."
    EASYRSA_BATCH=1 EASYRSA_VARS_FILE="$EASYRSA_vars_DIR" EASYRSA_REQ_CN="My OpenVPN CA" $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" build-ca nopass >> "$LOG_FILE" 2>&1

    # Generate Diffie-Hellman parameters
	log "Generating DH parameters..."
	EASYRSA_BATCH=1 EASYRSA_VARS_FILE="$EASYRSA_vars_DIR" $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" gen-dh >> "$LOG_FILE" 2>&1

	rm -f $EASYRSA_DIR/pki/vars
	# Generate Server Certificate
	log "Generating server certificate..."
	# EASYRSA_BATCH=1 EASYRSA_VARS_FILE="$EASYRSA_DIR/vars" $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" build-server-full server nopass >> "$LOG_FILE" 2>&1
	EASYRSA_BATCH=1 $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" build-server-full server nopass >> "$LOG_FILE" 2>&1

	# Generate a Certificate Revocation List (CRL) to manage revoked certificates
	log "Generating Certificate Revocation List"
	EASYRSA_BATCH=1 EASYRSA_VARS_FILE="$EASYRSA_vars_DIR" "$EASYRSA_DIR/easyrsa" --pki-dir="$EASYRSA_DIR/pki" gen-crl >> "$LOG_FILE" 2>&1

	OVPN_VERSION=$(openvpn --version | head -n 1 | awk '{print $2}')
    # Generate TLS authentication keys
	log "Generating TLS authentication keys"
	if [[ "$(echo -e "$OVPN_VERSION\n2.5" | sort -V | head -n1)" == "2.5" ]]; then
		openvpn --genkey secret $EASYRSA_DIR/pki/tc.key >> "$LOG_FILE" 2>&1
	else
		openvpn --genkey --secret $EASYRSA_DIR/pki/tc.key >> "$LOG_FILE" 2>&1
	fi

    # Configure OpenVPN Server
cat <<EOF > /etc/openvpn/server/server.conf
local $local_ip
port $port
proto $protocol
dev tun
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/server.crt
key $EASYRSA_DIR/pki/private/server.key
dh $EASYRSA_DIR/pki/dh.pem
auth SHA512
tls-crypt $EASYRSA_DIR/pki/tc.key
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1"
ifconfig-pool-persist /etc/openvpn/client/ipp.txt
push "dhcp-option DNS $dns1"
push "dhcp-option DNS $dns2"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
client-config-dir /etc/openvpn/client/client-config
verb 3
crl-verify $EASYRSA_DIR/pki/crl.pem
explicit-exit-notify
client-to-client
script-security 2
up "/etc/openvpn/server/add-routes.sh"
EOF

	# Configure routing
cat <<EOF > /etc/openvpn/server/add-routes.sh
#!/bin/bash
sleep 2
EOF
	chmod +x /etc/openvpn/server/add-routes.sh

	# Configure OpenVPN client sample
cat <<EOF > /etc/openvpn/server/client-sample.txt
client
dev tun
proto $protocol
remote $public_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-GCM
auth-nocache
ignore-unknown-option block-outside-dns
verb 3
EOF

	local_network_cidr=$(ip -o -f inet addr show | awk -v ip="$local_ip" '$4 ~ ip {print $4}')
	local_network_address=$(network_calculator "$local_network_cidr")
	echo "push \"route $local_network_address\"" >> "/etc/openvpn/client/00-remote-site-network.txt"

    # Enable IP forwarding
    log "Starting IP forward check..."

    if [[ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]]; then
        log "No action required."
    else
        enable_ip_forward
    fi

    log "IP forward check completed."
	
	# Setting up OepnVPN service
	iptables_path=$(command -v iptables)
cat <<EOF > /etc/systemd/system/openvpn-server@.service
[Unit]
Description=OpenVPN service for %I
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn/server

# Add firewall rules before starting OpenVPN
ExecStartPre=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $local_ip
ExecStartPre=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStartPre=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStartPre=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Start the OpenVPN service
ExecStart=/usr/sbin/openvpn --status %t/openvpn-server/status-%i.log --status-version 2 --suppress-timestamps --config %i.conf

# Remove firewall rules after stopping OpenVPN
ExecStopPost=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $local_ip
ExecStopPost=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStopPost=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStopPost=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
LimitNPROC=10
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
KillMode=process
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target

EOF

    # Configure Firewall
    log "Configuring firewall..."
    ufw allow $port/$protocol >> "$LOG_FILE" 2>&1
    ufw allow OpenSSH >> "$LOG_FILE" 2>&1

	# Check UFW Status
	ufw_status=$(ufw status | grep -o "Status: .*" | awk '{print $2}')

	if [[ "$ufw_status" == "inactive" ]]; then
		log "UFW is currently disabled. Keeping it disabled as per system settings."
	else
		log "UFW is enabled, updating rules..."
		ufw --force reload >> "$LOG_FILE" 2>&1
	fi

    # Start OpenVPN Service
    log "Starting OpenVPN service..."
	systemctl daemon-reload
	systemctl enable openvpn-server@server.service  >> "$LOG_FILE" 2>&1
	systemctl start openvpn-server@server.service  >> "$LOG_FILE" 2>&1

    log "OpenVPN installation completed."
}

# Revoke client
revoke_client() {
    read -p "Enter client name to revoke: " client
	# **Clear output**
	for ((i = 0; i < 1; i++)); do
		tput cuu1
		tput el
	done
    if [[ ! -f "$EASYRSA_DIR/pki/issued/$client.crt" ]]; then
        log "Error: Client $client does not exist."
        return 1
    fi
    log "Revoking client certificate for $client..."
    EASYRSA_BATCH=1 $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" revoke "$client" >> "$LOG_FILE" 2>&1
    EASYRSA_BATCH=1 $EASYRSA_DIR/easyrsa --pki-dir="$EASYRSA_DIR/pki" gen-crl >> "$LOG_FILE" 2>&1

    client_config_file="/etc/openvpn/client/client-config/$client"
	# Extract the network address and subnet mask from the iroute configuration
	network_address=$(grep "^iroute" "$client_config_file" | cut -d ' ' -f 2)
	netmask=$(grep "^iroute" "$client_config_file" | cut -d ' ' -f 3)

	# Delete the client configuration file
    if [[ -f "$client_config_file" ]]; then
        rm -f "$client_config_file"
        log "Deleted client config file: $client_config_file"
    fi

	if [[ -n "$network_address" && -n "$netmask" ]]; then
		# Delete the push route in /etc/openvpn/client/00-remote-site-network.txt
        push_route_line="push \"route $network_address $netmask\""
        sed -i "/^$push_route_line/d" /etc/openvpn/client/00-remote-site-network.txt
        log "Removed push route $network_address $netmask from 00-remote-site-network.txt"
		sed -i "\|$network_address|d" /etc/openvpn/server/add-routes.sh
		log "Removing route for $network_address from add-routes.sh"

        # Traverse all configuration files under /etc/openvpn/client/client-config/ and delete the push routes
        for temp_client_config_file in /etc/openvpn/client/client-config/*; do
            sed -i "/^$push_route_line/d" "$temp_client_config_file"
            log "Removed push route $network_address $netmask from $temp_client_config_file"
        done
	fi

    # Deleting the OpenVPN client configuration file (.ovpn)
    client_ovpn_file="/etc/openvpn/client/$client.ovpn"
    if [[ -f "$client_ovpn_file" ]]; then
        rm -f "$client_ovpn_file"
        log "Deleted client OVPN file: $client_ovpn_file"
    fi

    systemctl start openvpn-server@server.service
    log "Client $client has been revoked successfully."
}

# List all existing clients
list_existing_clients() {
	if ls /etc/openvpn/client/client-config/* >/dev/null 2>&1; then
	    echo "Existing clients:"
		echo "================="
		find /etc/openvpn/client/client-config -maxdepth 1 -type f -exec basename {} \;
		echo "================="
	else
		echo "No clients found."
	fi
}

# Uninstall OpenVPN
uninstall_openvpn() {
    read -p "Are you sure you want to uninstall OpenVPN? This cannot be undone. [yes/N]: " confirm

	# Clear output
    for ((i = 0; i < 1; i++)); do
        tput cuu1
        tput el
    done

	if [[ "$confirm" != "yes" ]]; then
        log "Uninstallation cancelled."
        return
    fi
    log "Uninstalling OpenVPN..."

    # 从 server.conf 中提取 port 和 protocol
    if [[ -f /etc/openvpn/server/server.conf ]]; then
        port=$(grep '^port ' /etc/openvpn/server/server.conf | awk '{print $2}')
        protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | awk '{print $2}')
        log "Extracted port: $port, protocol: $protocol from server.conf"
    else
        log "server.conf not found. Using default port 1194 and protocol udp."
        port=1194
        protocol="udp"
    fi

    # Stop and disable the OpenVPN service
    systemctl stop openvpn-server@server.service
    systemctl disable openvpn-server@server.service >> "$LOG_FILE" 2>&1

	# Delete the openvpn-server service
	rm -f /etc/systemd/system/openvpn-server@.service >> "$LOG_FILE" 2>&1

	# Reload the systemd configuration to ensure the service list is updated
	systemctl daemon-reload
	systemctl reset-failed

    # Remove OpenVPN and related packages
    apt remove --purge -y openvpn easy-rsa >> "$LOG_FILE" 2>&1
	apt autoremove -y >> "$LOG_FILE" 2>&1

    # Deleting OpenVPN configuration files and data
    rm -rf /etc/openvpn
	crontab -l | grep -v 'openvpn' | crontab - >> "$LOG_FILE" 2>&1

    # Deleting Firewall Rules
    ufw delete allow $port/$protocol >> "$LOG_FILE" 2>&1 || true
	ufw --force reload >> "$LOG_FILE" 2>&1

    log "OpenVPN has been uninstalled."
	
	# Exit the script directly
    exit 0
}

# Main menu
main_menu() {
    while true; do
        echo "┌───────────────────────────────────────────┐"
        echo "│ Select an option:                         │"
        echo "│   1) Add a new client                     │"
        echo "│   2) Revoke an existing client            │"
        echo "│   3) List existing clients                │"
		echo "│   4) Uninstall OpenVPN                    │"
        echo "│   5) Exit                                 │"
        echo "└───────────────────────────────────────────┘"
        read -p "Option: " option
		clear
        # **Show user selection**
        case "$option" in
            1) echo "You selected: Add a new client"; new_client ;;
            2) echo "You selected: Revoke an existing client"; revoke_client ;;
            3) echo "You selected: List existing clients"; list_existing_clients ;;
            4) echo "You selected: Uninstall OpenVPN"; uninstall_openvpn ;;
            5) echo "Exiting..."; break ;;
            *) echo "Invalid option. Please try again." ;;
        esac
    done
}

# Main function
main() {

	initialize
	detect_os

	if check_openvpn_installed; then
		main_menu
	else
		install_openvpn
		main_menu
	fi
}

# Execute the main function
main
