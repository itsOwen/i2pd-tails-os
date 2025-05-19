#!/bin/bash

# Complete I2P on Tails installation script with fixed persistence

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Script must be run as root. Please use a root terminal or sudo -i"
    exit 1
fi

clear
echo "**********************************"
echo "*                                *"
echo "*    I2P on Tails script v0.6    *"
echo "*           May 2025             *"
echo "*                                *"
echo "*--------------------------------*"
echo "*    Updated for Tails 6.x       *"
echo "*     (Debian 12 Bookworm)       *"
echo "*--------------------------------*"
echo "*                                *"
echo "*       Github: itsOwen          *"
echo "*      Thanks: Plowsker          *"
echo "*                                *"
echo "**********************************"
sleep 1

# Ask user about persistence
echo ""
echo "How would you like to install I2P?"
echo ""
echo "1) Normal installation (for one-time use, will be lost after reboot)"
echo "2) Persistence-enabled installation (will persist across reboots)"
echo ""
read -p "Enter your choice (1 or 2): " persistence_choice

if [[ "$persistence_choice" == "2" ]]; then
    # Check if persistence volume is available
    if [ ! -d "/live/persistence/TailsData_unlocked" ]; then
        echo ""
        echo "Error: Persistence volume not found or not unlocked."
        echo ""
        echo "Please follow these steps to prepare your persistence volume:"
        echo ""
        echo "1. Finish this installation first (it will work for this session)"
        echo "2. Shut down Tails"
        echo "3. Restart Tails and at the welcome screen, choose 'Configure persistent volume'"
        echo "4. Create a persistent volume with a strong password"
        echo "5. Enable at least the 'Dotfiles' and 'Additional Software' features"
        echo "6. Restart Tails and unlock your persistent volume"
        echo "7. Run this script again and choose option 2"
        echo ""
        echo "Would you like to continue with a temporary installation for now? (y/n)"
        read -p "> " continue_install
        
        if [[ "$continue_install" != "y" ]]; then
            echo "Installation cancelled. Please restart when ready."
            exit 0
        fi
        
        # Set flag for temporary installation
        TEMP_INSTALL=true
    else
        echo "Persistence volume found. Will set up persistence-enabled installation."
        TEMP_INSTALL=false
    fi
else
    echo ""
    echo "You've chosen normal installation."
    echo "I2P will work for this session but will be forgotten after restart."
    echo ""
    TEMP_INSTALL=true
fi

# Create necessary directories
mkdir -p /home/amnesia/.i2pd_script

# First download the current i2pd version for Bookworm
echo "[+] Downloading I2Pd for Debian 12 Bookworm..."
cd /home/amnesia
sudo -u amnesia wget https://github.com/PurpleI2P/i2pd/releases/download/2.56.0/i2pd_2.56.0-1bookworm1_amd64.deb

echo "[+] Installing I2Pd..."
apt-get update
apt-get install -y libboost-program-options1.74.0 libminiupnpc17
dpkg -i i2pd_2.56.0-1bookworm1_amd64.deb || apt-get -f -y install

# Mark packages for persistence
echo "[+] Marking I2P packages for persistence..."
apt-mark manual i2pd libboost-program-options1.74.0 libminiupnpc17

echo "[+] Stopping I2Pd service..."
systemctl stop i2pd
systemctl daemon-reload

# Create the tails-create-netns-i2p script
echo "[+] Creating network namespace script..."
cat > /home/amnesia/.i2pd_script/tails-create-netns-i2p << 'EOL'
#!/bin/sh

guestVeth="veth0"

set -ue

increment_ip_address() {
    echo "$1" | \
        python3  -c 'base, host = input().rsplit(".", 1); print("%s.%s" % (base, int(host)+1))'
}

decrement_ip_address() {
    echo "$1" | \
        python3  -c 'base, host = input().rsplit(".", 1); print("%s.%s" % (base, int(host)-1))'
}

get_netns_guest_address() {
    ns="$1"
    ip netns exec "$ns" ip -4 a show dev "$guestVeth" |  grep -Po 'inet \K[\d.]+'
}

get_netns_host_address() {
    ns="$1"
    decrement_ip_address "$(get_netns_guest_address "$ns")"
}

expose() {
    if [ $# -ne 3 ]
    then
        echo 'Wrong expose usage' >&2
        exit 2
    fi
    ns="$1"
    guestPort="$2"
    hostPort="$3"
    hostAddress="$(get_netns_host_address "$ns")"
    guestAddress="$(get_netns_guest_address "$ns")"
    hostVeth="veth-${ns}"
    # $1 is netNs name
    # $2 is netNs port
    # $3 is host port
    ip netns exec "$ns" iptables -t nat \
        -A OUTPUT -o lo -d 127.0.0.1 -p tcp --dport "$guestPort" \
        -j DNAT  --to-destination "$hostAddress:$hostPort"

}

delete_netns() {
    # $1 = netns basename
    basename="$1"
    nsName="${basename}"
    hostVeth="veth-${basename}"
    ip link del "$hostVeth" || true
    ip netns del "$nsName" || true
}

create_netns() {
    # $1 = netns basename
    # $2 = first address; implies /30
    if ! [ $# -eq 2 ]; then
        echo "Wrong usage for create_netns" >&2
        exit 2
    fi
    basename="$1"
    hostAddress="$2"
    netmask=30
    nsName="${basename}"
    hostVeth="veth-${basename}"
    if [ "${#hostVeth}" -ge 16 ]
    then
        echo "netns name too long '${hostVeth}'; it would have a veth name >= 16"
        exit 2
    fi
    guestAddress="$(increment_ip_address "$hostAddress")"
    ip netns add "$nsName"

    # create veth
    ip netns exec "$nsName" ip link set dev lo up
    ip link add "$hostVeth" type veth peer name "$guestVeth"

    # setup veth
    ip link set veth0 netns "$nsName"
    ip addr add "${hostAddress}/$netmask" dev "$hostVeth"
    ip link set dev "$hostVeth" up
    ip netns exec "$nsName" ip addr add "${guestAddress}/$netmask" dev "$guestVeth"
    ip netns exec "$nsName" ip link set dev "$guestVeth" up

    # setup iptables
    ## forbid IP spoofing
    ip netns exec "$nsName" iptables -A OUTPUT -o veth0 ! --src "$guestAddress" -j REJECT
    ip netns exec "$nsName" sysctl net.ipv4.ip_forward=0
    ip netns exec "$nsName" sysctl net.ipv4.conf.all.forwarding=0
    ip netns exec "$nsName" sysctl net.ipv4.conf.lo.forwarding=0
    ip netns exec "$nsName" sysctl net.ipv4.conf.all.route_localnet=1

    ip netns exec "$nsName" iptables -t nat -A POSTROUTING -j MASQUERADE

    sysctl net.ipv4.ip_forward=0
    sysctl net.ipv4.conf.all.forwarding=0
    sysctl "net.ipv4.conf.${hostVeth}.forwarding=0"
}

if [ "$#" -ne 1 ]
then
    echo "Wrong usage: $0 start|stop" >&2
    exit 2
fi

if [ "$1" = stop ]
then
    delete_netns tbb
    delete_netns onioncircs
    delete_netns tca
    delete_netns onionshare
    exit
fi

if [ "$1" = start ]
then
    modprobe veth
    modprobe xt_MASQUERADE
    modprobe xt_nat
    netBase='10.200.1'
    create_netns tbb "${netBase}.1"
    create_netns onioncircs "${netBase}.5"
    create_netns tca "${netBase}.9"
    create_netns onionshare "${netBase}.13"

    # Exposing specific services to applications confined in netns

    #i2pd
    expose tbb 4444 4444
    expose tbb 4447 4447
    expose tbb 7070 7070

    #local http server to get the proxy.pac file
    expose tbb 8181 8181

    #tor
    expose tbb 9050 9050
    expose tbb 9051 9051
    expose onioncircs 9051 9051
    expose tca 9051 9051
    expose onionshare 9050 9050
    expose onionshare 9051 9051
fi
EOL

chmod +x /home/amnesia/.i2pd_script/tails-create-netns-i2p

# Fix i2pd.conf file
echo "[+] Configuring I2P settings..."
cat > /etc/i2pd/i2pd.conf << 'EOL'
## Configuration file for a typical i2pd user

## Tunnels config file
## Default: ~/.i2pd/tunnels.conf or /var/lib/i2pd/tunnels.conf
# tunconf = /var/lib/i2pd/tunnels.conf

## Logging configuration section
loglevel = debug

## Daemon mode. Router will go to background after start
# daemon = true

## External IP address to listen for connections
## By default i2pd sets IP automatically
# host = 1.2.3.4

## Enable communication through ipv4
ipv4 = true
## Enable communication through ipv6
ipv6 = false

## Enable NTCP transport (default = true)
ntcp = true
## If you run i2pd behind a proxy server, you can only use NTCP transport with ntcpproxy option 
## Should be http://address:port or socks://address:port
# ntcpproxy = socks://localhost:9050
## Enable SSU transport (default = true)
ssu = true

## Should we assume we are behind NAT? (false only in MeshNet)
# nat = true

## Bandwidth configuration
## L limit bandwidth to 32KBs/sec, O - to 256KBs/sec, P - to 2048KBs/sec,
## X - unlimited
## Default is X for floodfill, L for regular node
bandwidth = P
## Max % of bandwidth limit for transit. 0-100. 100 by default
share = 100

[http]
## Web Console settings
## Address and port service will listen on
address = 10.200.1.1
port = 7070
strictheaders = false

[httpproxy]
## Address and port service will listen on
address = 10.200.1.1
port = 4444

[socksproxy]
## Address and port service will listen on
address = 10.200.1.1
port = 4447

[sam]
## Uncomment and set to 'true' to enable SAM Bridge
enabled = false

[bob]
## Uncomment and set to 'true' to enable BOB command channel
enabled = false

[i2cp]
## Uncomment and set to 'true' to enable I2CP protocol
enabled = false

[i2pcontrol]
## Uncomment and set to 'true' to enable I2PControl protocol
enabled = false

[precomputation]
## Enable or disable elgamal precomputation table
## By default, enabled on i386 hosts
# elgamal = true

[upnp]
## Enable or disable UPnP: automatic port forwarding (enabled by default in WINDOWS, ANDROID)
enabled = false

[reseed]
## Options for bootstrapping into I2P network, aka reseeding
## Enable or disable reseed data verification.
verify = true
## If you run i2pd behind a proxy server, set proxy server for reseeding here
## Should be http://address:port or socks://address:port
proxy = socks://localhost:9050

[addressbook]
## AddressBook subscription URL for initial setup
## Default: inr.i2p at 'mainline' I2P Network
# defaulturl = http://joajgazyztfssty4w2on5oaqksz6tqoxbduy553y34mf4byv6gpq.b32.i2p/export/alive-hosts.txt
EOL

# Also save configuration to persistence location
if [ "$TEMP_INSTALL" = false ]; then
    mkdir -p /live/persistence/TailsData_unlocked/etc/i2pd
    cp /etc/i2pd/i2pd.conf /live/persistence/TailsData_unlocked/etc/i2pd/
fi

# Clear out log
rm -rf /var/log/i2pd/i2pd.log

# Clearing out default I2Pd tunnels for security reasons
echo "[+] Clearing out default I2Pd tunnels..."
echo " " > /etc/i2pd/tunnels.conf

# Make a backup of tails-create-netns
cp /usr/local/lib/tails-create-netns /usr/local/lib/tails-create-netns_backup
/usr/local/lib/tails-create-netns stop

# Update netns with one which will work for I2Pd
echo "[+] Setting up network namespace for I2P..."
chmod +x /home/amnesia/.i2pd_script/tails-create-netns-i2p
sudo -u root /home/amnesia/.i2pd_script/tails-create-netns-i2p start

# IPtables rules to allow I2Pd software and corresponding ports
echo "[+] Setting firewall rules for I2P..."
iptables -I INPUT 3 -p tcp -s 10.200.1.2 -d 10.200.1.1 -i veth-tbb -j ACCEPT -m multiport --destination-ports 4447,7070,8181
iptables -I OUTPUT 3 -p tcp -j ACCEPT -m tcp --tcp-flags SYN,ACK,FIN,RST SYN -m state --state NEW -m owner --uid-owner i2pd
sleep 1

# Start i2pd
echo "[+] Starting I2Pd service..."
systemctl daemon-reload
systemctl start i2pd

# Create directory which will host our proxy script to redirect .i2p
sudo -u amnesia mkdir -p "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac"

# Modified proxy.pac file that handles direct console access
sudo -u amnesia cat > "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac" << 'EOL'
function FindProxyForURL(url, host)
{
  // Direct access to I2P console
  if (shExpMatch(host, "10.200.1.1") || shExpMatch(host, "127.0.0.1:7070")) {
    return "DIRECT";
  }
  // Route I2P traffic through I2P
  if (shExpMatch(host, "*.i2p$")) {
    return "SOCKS 127.0.0.1:4447";
  }
  // Everything else through Tor
  return "SOCKS 127.0.0.1:9050";
}
EOL

chmod +x "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac"
chown amnesia:amnesia "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac"

# Start simple local python server to serve the proxy pac file
echo "[+] Starting local server to handle .i2p proxifying..."

sudo -u amnesia python3 -m http.server --bind 10.200.1.1 --directory "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac" 8181 >/dev/null 2>&1 &

# Create a robust startup script that will run at boot
echo "[+] Creating comprehensive startup script..."
cat > /home/amnesia/.i2pd_script/i2p-startup.sh << 'EOL'
#!/bin/bash

# I2P comprehensive startup script for Tails persistence
# This script ensures I2P is fully functional after Tails boot

# Wait for system to fully initialize
sleep 30

# Logging
log_file="/tmp/i2p-startup.log"
exec > >(tee -a "$log_file") 2>&1

echo "$(date): I2P startup script beginning"

# Check for required files
if [ ! -f "/home/amnesia/.i2pd_script/tails-create-netns-i2p" ]; then
    echo "Error: Required files missing. I2P not properly installed."
    notify-send "I2P Error" "Required files missing. Please reinstall I2P."
    exit 1
fi

# Stop any potentially running instances
echo "Stopping any existing services..."
pkill python3 || true
pkill -f "http.server" || true
systemctl stop i2pd || true
/usr/local/lib/tails-create-netns stop || true

# Create directories if they don't exist
mkdir -p "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac"

# Copy i2pd.conf from persistent storage if available
if [ -f "/live/persistence/TailsData_unlocked/etc/i2pd/i2pd.conf" ]; then
    echo "Restoring i2pd configuration from persistence..."
    cp "/live/persistence/TailsData_unlocked/etc/i2pd/i2pd.conf" /etc/i2pd/
fi

# Set up network namespace
echo "Setting up network namespace..."
/home/amnesia/.i2pd_script/tails-create-netns-i2p start

# Set up firewall rules
echo "Setting up firewall rules..."
iptables -I INPUT 3 -p tcp -s 10.200.1.2 -d 10.200.1.1 -i veth-tbb -j ACCEPT -m multiport --destination-ports 4447,7070,8181
iptables -I OUTPUT 3 -p tcp -j ACCEPT -m tcp --tcp-flags SYN,ACK,FIN,RST SYN -m state --state NEW -m owner --uid-owner i2pd

# Start the I2P service
echo "Starting I2P service..."
systemctl daemon-reload
systemctl start i2pd

# Create proxy.pac file if it doesn't exist
if [ ! -f "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac" ]; then
    echo "Creating proxy.pac file..."
    cat > "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac" << 'EOF'
function FindProxyForURL(url, host)
{
  // Direct access to I2P console
  if (shExpMatch(host, "10.200.1.1") || shExpMatch(host, "127.0.0.1:7070")) {
    return "DIRECT";
  }
  // Route I2P traffic through I2P
  if (shExpMatch(host, "*.i2p$")) {
    return "SOCKS 127.0.0.1:4447";
  }
  // Everything else through Tor
  return "SOCKS 127.0.0.1:9050";
}
EOF
    chmod +x "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac"
fi

# Start proxy server
echo "Starting proxy server..."
python3 -m http.server --bind 10.200.1.1 --directory "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac" 8181 >/dev/null 2>&1 &

# Configure Tor Browser
echo "Configuring Tor Browser..."
PROFILE_DIR="/home/amnesia/.tor-browser/profile.default"
if [ -d "$PROFILE_DIR" ]; then
    cat > "$PROFILE_DIR/user.js" << 'EOF'
// I2P Configuration - Added by installer
user_pref("extensions.torbutton.use_nontor_proxy", true);
user_pref("network.proxy.allow_hijacking_localhost", false); 
user_pref("network.proxy.socks", "");
user_pref("network.proxy.autoconfig_url", "http://127.0.0.1:8181/proxy.pac");
user_pref("network.proxy.type", 2);
user_pref("network.proxy.no_proxies_on", "10.200.1.1");

// Enhanced HTTPS-only mode disabling
user_pref("dom.security.https_only_mode", false);
user_pref("dom.security.https_only_mode_ever_enabled", false);
user_pref("dom.security.https_only_mode_pbm", false);
user_pref("dom.security.https_only_mode_ever_enabled_pbm", false);
EOF
    chown amnesia:amnesia "$PROFILE_DIR/user.js"
    chmod 600 "$PROFILE_DIR/user.js"
fi

# Create desktop shortcuts if they don't exist
if [ ! -f "/home/amnesia/Desktop/enable_i2p.desktop" ]; then
    echo "Creating desktop shortcuts..."
    
    cat > /home/amnesia/Desktop/enable_i2p.desktop << 'EOF'
[Desktop Entry]
Type=Application
Exec=/home/amnesia/.i2pd_script/enable_i2p.sh
Name=Enable I2P
GenericName=I2P
StartupNotify=true
Categories=Network;
EOF

    cat > /home/amnesia/Desktop/disable_i2p.desktop << 'EOF'
[Desktop Entry]
Type=Application
Exec=/home/amnesia/.i2pd_script/disable_i2p.sh
Name=Disable I2P
GenericName=I2P
StartupNotify=true
Categories=Network;
EOF

    cat > /home/amnesia/Desktop/i2p-console.desktop << 'EOF'
[Desktop Entry]
Type=Application
Exec=firefox http://10.200.1.1:7070
Name=I2P Console
Comment=Access I2P Router Console
Icon=web-browser
Terminal=false
Categories=Network;
EOF

    chmod +x /home/amnesia/Desktop/*.desktop
    chown amnesia:amnesia /home/amnesia/Desktop/*.desktop
fi

# Verify that I2P is running
sleep 5
if systemctl is-active --quiet i2pd; then
    echo "I2P service is running."
    notify-send "I2P Enabled" "I2P has been successfully started. You can access the console at http://10.200.1.1:7070"
else
    echo "Error: I2P service failed to start."
    systemctl status i2pd
    notify-send "I2P Error" "I2P service failed to start. Check logs for details."
fi

echo "$(date): I2P startup script completed"
EOL

chmod +x /home/amnesia/.i2pd_script/i2p-startup.sh
chown amnesia:amnesia /home/amnesia/.i2pd_script/i2p-startup.sh

# Create enable/disable scripts with enhanced browser configuration
echo "[+] Creating enable/disable scripts..."

cat > /home/amnesia/.i2pd_script/enable_i2p.sh << 'EOL'
#!/bin/bash

# Kill Tor Browser if running
pkill -f firefox || true

# Run the comprehensive startup script
sudo /home/amnesia/.i2pd_script/i2p-startup.sh

echo '[+] I2P enabled.'
echo '[+] Browser has been configured automatically for I2P access.'
echo '[+] You can now access the I2P console at http://10.200.1.1:7070'

# Try to send notifications if possible
notify-send "I2P enabled" 2>/dev/null || true
notify-send "I2P console available at http://10.200.1.1:7070" 2>/dev/null || true
EOL

cat > /home/amnesia/.i2pd_script/disable_i2p.sh << 'EOL'
#!/bin/bash

# Kill Tor Browser if running
pkill -f firefox || true

# Stop I2P services
systemctl stop i2pd || true
pkill python3 || true
pkill -f "http.server" || true
sudo /usr/local/lib/tails-create-netns stop || true
sudo /usr/local/lib/tails-create-netns start || true

# Remove user.js to restore default browser configuration
PROFILE_DIR="/home/amnesia/.tor-browser/profile.default"
rm -f "$PROFILE_DIR/user.js"

echo '[-] I2P disabled.'

# Try to send notifications if possible
notify-send "I2P disabled" 2>/dev/null || true
EOL

chmod +x /home/amnesia/.i2pd_script/enable_i2p.sh
chmod +x /home/amnesia/.i2pd_script/disable_i2p.sh
chown amnesia:amnesia /home/amnesia/.i2pd_script/enable_i2p.sh
chown amnesia:amnesia /home/amnesia/.i2pd_script/disable_i2p.sh

echo "[+] Setting desktop icons..."

cat > /home/amnesia/Desktop/enable_i2p.desktop << 'EOL'
[Desktop Entry]
Type=Application
Exec=/home/amnesia/.i2pd_script/enable_i2p.sh
Name=Enable I2P
GenericName=I2P
StartupNotify=true
Categories=Network;
EOL

cat > /home/amnesia/Desktop/disable_i2p.desktop << 'EOL'
[Desktop Entry]
Type=Application
Exec=/home/amnesia/.i2pd_script/disable_i2p.sh
Name=Disable I2P
GenericName=I2P
StartupNotify=true
Categories=Network;
EOL

# Create a direct console access icon
cat > /home/amnesia/Desktop/i2p-console.desktop << 'EOL'
[Desktop Entry]
Type=Application
Exec=firefox http://10.200.1.1:7070
Name=I2P Console
Comment=Access I2P Router Console
Icon=web-browser
Terminal=false
Categories=Network;
EOL

chmod +x /home/amnesia/Desktop/enable_i2p.desktop
chmod +x /home/amnesia/Desktop/disable_i2p.desktop
chmod +x /home/amnesia/Desktop/i2p-console.desktop
chown amnesia:amnesia /home/amnesia/Desktop/enable_i2p.desktop
chown amnesia:amnesia /home/amnesia/Desktop/disable_i2p.desktop
chown amnesia:amnesia /home/amnesia/Desktop/i2p-console.desktop

# Now configure the browser using the enhanced user.js approach
echo "[+] Configuring browser with enhanced user.js approach..."
PROFILE_DIR="/home/amnesia/.tor-browser/profile.default"
sudo -u amnesia bash -c "cat > \"$PROFILE_DIR/user.js\"" << 'EOF'
// I2P Configuration - Added by installer
user_pref("extensions.torbutton.use_nontor_proxy", true);
user_pref("network.proxy.allow_hijacking_localhost", false);
user_pref("network.proxy.socks", "");
user_pref("network.proxy.autoconfig_url", "http://127.0.0.1:8181/proxy.pac");
user_pref("network.proxy.type", 2);
user_pref("network.proxy.no_proxies_on", "10.200.1.1");

// Enhanced HTTPS-only mode disabling
user_pref("dom.security.https_only_mode", false);
user_pref("dom.security.https_only_mode_ever_enabled", false);
user_pref("dom.security.https_only_mode_pbm", false);
user_pref("dom.security.https_only_mode_ever_enabled_pbm", false);
EOF

# Set proper permissions
chown amnesia:amnesia "$PROFILE_DIR/user.js"
chmod 600 "$PROFILE_DIR/user.js"

# Create a proper persistence setup for the admin password script
if [ "$TEMP_INSTALL" = false ]; then
    echo "[+] Setting up persistent admin password script..."
    
    mkdir -p /live/persistence/TailsData_unlocked/dotfiles/.config/tails-i2p
    
    cat > /live/persistence/TailsData_unlocked/dotfiles/.config/tails-i2p/admin-i2p-setup.sh << 'EOL'
#!/bin/bash

# This script runs with admin privileges at Tails startup
# It's called from the user autostart script

# Logging
log_file="/tmp/i2p-admin-setup.log"
exec > >(tee -a "$log_file") 2>&1

echo "$(date): I2P admin setup script beginning"

# Restore configuration if available
if [ -f "/live/persistence/TailsData_unlocked/etc/i2pd/i2pd.conf" ]; then
    echo "Copying I2P configuration from persistence..."
    cp /live/persistence/TailsData_unlocked/etc/i2pd/i2pd.conf /etc/i2pd/
fi

# Mark packages for persistence
echo "Marking I2P packages for persistence..."
apt-mark manual i2pd libboost-program-options1.74.0 libminiupnpc17

echo "$(date): I2P admin setup completed"
EOL

    chmod +x /live/persistence/TailsData_unlocked/dotfiles/.config/tails-i2p/admin-i2p-setup.sh
    chown -R amnesia:amnesia /live/persistence/TailsData_unlocked/dotfiles/.config/tails-i2p

    # Create the user script that uses sudo to run the admin script
    mkdir -p /live/persistence/TailsData_unlocked/dotfiles/.config/autostart
    
    cat > /live/persistence/TailsData_unlocked/dotfiles/.config/autostart/i2p-autostart.desktop << 'EOL'
[Desktop Entry]
Type=Application
Exec=/home/amnesia/.config/autostart/run-i2p.sh
Name=I2P Autostart
Comment=Automatically starts I2P when Tails boots
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
EOL

    chmod +x /live/persistence/TailsData_unlocked/dotfiles/.config/autostart/i2p-autostart.desktop
    
    cat > /live/persistence/TailsData_unlocked/dotfiles/.config/autostart/run-i2p.sh << 'EOL'
#!/bin/bash

# Run the admin script with sudo (this will prompt for password)
sudo /home/amnesia/.config/tails-i2p/admin-i2p-setup.sh &

# Then run the normal startup script
/home/amnesia/.i2pd_script/i2p-startup.sh &
EOL

    chmod +x /live/persistence/TailsData_unlocked/dotfiles/.config/autostart/run-i2p.sh
    
    # Copy all scripts to the persistent location
    mkdir -p /live/persistence/TailsData_unlocked/dotfiles/.i2pd_script
    cp /home/amnesia/.i2pd_script/* /live/persistence/TailsData_unlocked/dotfiles/.i2pd_script/
    chmod +x /live/persistence/TailsData_unlocked/dotfiles/.i2pd_script/*.sh
    chmod +x /live/persistence/TailsData_unlocked/dotfiles/.i2pd_script/tails-create-netns-i2p
    
    # Copy proxy.pac file
    mkdir -p "/live/persistence/TailsData_unlocked/dotfiles/Tor Browser/localhost-tbb-proxy-pac"
    cp "/home/amnesia/Tor Browser/localhost-tbb-proxy-pac/proxy.pac" "/live/persistence/TailsData_unlocked/dotfiles/Tor Browser/localhost-tbb-proxy-pac/"
    
    # Copy desktop files
    mkdir -p /live/persistence/TailsData_unlocked/dotfiles/Desktop
    cp /home/amnesia/Desktop/enable_i2p.desktop /live/persistence/TailsData_unlocked/dotfiles/Desktop/
    cp /home/amnesia/Desktop/disable_i2p.desktop /live/persistence/TailsData_unlocked/dotfiles/Desktop/
    cp /home/amnesia/Desktop/i2p-console.desktop /live/persistence/TailsData_unlocked/dotfiles/Desktop/
    
    # Set proper permissions for all persistence files
    chown -R amnesia:amnesia /live/persistence/TailsData_unlocked/dotfiles/.i2pd_script
    chown -R amnesia:amnesia /live/persistence/TailsData_unlocked/dotfiles/.config
    chown -R amnesia:amnesia /live/persistence/TailsData_unlocked/dotfiles/Desktop
    chown -R amnesia:amnesia "/live/persistence/TailsData_unlocked/dotfiles/Tor Browser"
    
    echo "[+] Persistence setup complete. I2P will be available after restart."
    
    # Create a README file with instructions
    cat > /home/amnesia/Desktop/I2P-PERSISTENCE-README.txt << 'EOL'
I2P PERSISTENCE INFORMATION

Your I2P installation has been configured to persist across Tails restarts.
When you restart Tails and unlock your persistent volume, you'll need to:

1. Enter your administration password when prompted after startup
   (This is needed to properly configure I2P's system settings)

2. If I2P doesn't start automatically, click the "Enable I2P" icon on your desktop

3. Wait 2-5 minutes for I2P to properly connect to the network

IMPORTANT: I2P will only work if you've unlocked your persistent volume at boot time.

If you have any issues, try manually running:
/home/amnesia/.i2pd_script/enable_i2p.sh

Enjoy using I2P on Tails!
EOL

    chmod +x /home/amnesia/Desktop/I2P-PERSISTENCE-README.txt
    chown amnesia:amnesia /home/amnesia/Desktop/I2P-PERSISTENCE-README.txt
fi

# Run the startup script to complete the installation
echo "[+] Running startup script to complete installation..."
/home/amnesia/.i2pd_script/i2p-startup.sh

echo ""
echo "IMPORTANT: Wait 2-5 minutes for I2P to connect properly."
echo "After you have waited, start Tor Browser and check if you can reach the I2Pd router console:"
echo ""
echo "http://10.200.1.1:7070"
echo ""
echo "###############################"
echo ""
echo "I2P BROWSING TIPS:"
echo ""
echo "1. Always use http:// (not https://) for I2P sites"
echo "2. b32.i2p addresses are more reliable than named .i2p addresses"
echo "3. Access may be slow until your router fully integrates into the network"
echo "4. Visit the I2P console and add address book subscriptions to improve site access"
echo ""
echo "###############################"
echo ""

if [[ "$persistence_choice" == "2" ]]; then
    if [ "$TEMP_INSTALL" = true ]; then
        echo "PERSISTENCE SETUP INSTRUCTIONS:"
        echo ""
        echo "You've chosen to set up I2P with persistence, but you don't have"
        echo "a persistent volume configured yet. Please follow these steps:"
        echo ""
        echo "1. Shut down Tails"
        echo "2. Restart Tails and configure a persistent volume at the welcome screen"
        echo "3. Enable at least the 'Dotfiles' and 'Additional Software' features"
        echo "4. Restart Tails and unlock your persistent volume"
        echo "5. Run this script again and choose persistence-enabled installation"
        echo ""
    else
        echo "PERSISTENCE SUCCESSFULLY CONFIGURED:"
        echo ""
        echo "I2P has been properly set up with persistence!"
        echo "When you restart Tails and unlock your persistent volume,"
        echo "I2P will be available after entering your admin password when prompted."
        echo ""
        echo "A README file has been created on your desktop with more information."
        echo ""
    fi
    echo "###############################"
    echo ""
fi

echo "[+] All done. Exiting..."

# Try to send notifications if possible
notify-send "I2P installation completed" 2>/dev/null || true
