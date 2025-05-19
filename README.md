# i2pd-tails-os

A script to install and run I2P (Invisible Internet Project) alongside Tor on Tails OS. Browse both `.onion` and `.i2p` sites simultaneously!

![I2P Logo](https://raw.githubusercontent.com/itsOwen/i2pd-tails-os/refs/heads/main/tails.png)

## 🔍 Overview

This script allows you to add I2P functionality to Tails OS, providing access to the I2P network while maintaining Tor capabilities. Browse .i2p sites and .onion sites simultaneously without compromising security.

## ✨ Features

- **Dual Network Access**: Use both Tor and I2P networks simultaneously
- **Easy Installation**: One-click setup process
- **Desktop Integration**: Simple desktop shortcuts to enable/disable I2P
- **Console Access**: Direct access to the I2P router console for monitoring and configuration
- **Browser Auto-configuration**: Automatically configures Tor Browser for seamless I2P access
- **Persistence Support**: Not Yet

## 📋 Requirements

- Tails OS 6.x (Debian 12 Bookworm-based)
- Root access (Administrator password) in Tails
- Internet connection

## 🔧 Installation

1. **Download the script** from the GitHub repository:
```bash
git clone https://github.com/itsOwen/i2pd-tails-os.git
cd i2pd-tails-os
```

2. **Enable admin privileges** in Tails:
   - At the Tails welcome screen, click "+" under "Additional Settings"
   - Choose "Administration Password"
   - Set a password and continue booting

3. **Run the script**:
   - Open a Terminal (Applications > System Tools)
   - Switch to root with:
   ```bash
   sudo -i
   ```
   - Navigate to the script directory and run:
   ```bash
   ./install_i2pd.sh
   ```

4. **Wait for installation to complete** (5-10 minutes)

## 🚀 Usage

After installation, you'll find these desktop shortcuts:

- **Enable I2P**: Activates I2P functionality
- **Disable I2P**: Deactivates I2P and restores normal Tor-only operation
- **I2P Console**: Opens the I2P router admin interface

To use I2P:

1. Click the **Enable I2P** desktop shortcut
2. Start Tor Browser
3. Browse .i2p sites:
   - For known sites: `http://site.i2p` (never use https://)
   - For more reliable access: Use .b32.i2p addresses

To monitor I2P status:
- Open the I2P console at `http://10.200.1.1:7070`

## 🔒 Privacy & Security Considerations

- I2P and Tor are separate anonymity networks with different design philosophies
- This script maintains isolation between networks while allowing access to both
- .i2p sites are accessed through the I2P network, .onion sites through Tor
- Regular websites continue to route through Tor
- I2P takes time (30+ minutes) to fully integrate into the network for optimal performance

## 📚 How It Works

The script:
1. Installs the I2Pd daemon (C++ implementation of I2P)
2. Creates isolated network namespaces for traffic separation
3. Configures proxy settings to route traffic appropriately:
   - .i2p domains → I2P network
   - .onion domains → Tor network
   - All other traffic → Tor network
4. Modifies browser settings for seamless operation

## ❓ Troubleshooting

**I2P sites are slow or unreachable**
- Wait 30+ minutes for full network integration
- Use .b32.i2p addresses when possible
- Check I2P console - network status should be "OK" or "Firewalled"
- Shows "testing" - Due to tails restrictive firewall

**Browser shows "HTTPS only" warnings**
- This is normal - I2P sites use HTTP
- The script disables HTTPS-only mode for I2P sites
- Always ensure you're using http:// for I2P sites

**Cannot access I2P console**
- Try accessing http://10.200.1.1:7070
- Use the "I2P Console" desktop shortcut

## 🙌 Credits

- **Github**: [itsOwen](https://github.com/itsOwen)
- **Thanks**: Plowsker for the original concept
- I2P Project: [geti2p.net](https://geti2p.net)
- PurpleI2P: [purplei2p.github.io](https://purplei2p.github.io)
- Tails OS: [tails.net](https://tails.net)

## 📜 License

This project is licensed under the BSD 3-Clause - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for legitimate privacy and security research purposes only. The authors are not responsible for any misuse or illegal activity conducted with this software.
