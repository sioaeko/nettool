# NetTool 🌐

A powerful CLI network utility for diagnostics, security checks, and performance analysis.

## ✨ Features and Usage

1. 🔍 Ping
   - Purpose: Test network connectivity to a target host.
   - Usage: python nettool.py ping <hostname/IP>

2. 🔎 Port scanning
   - Purpose: Check for open ports on a target host.
   - Usage: python nettool.py portscan <hostname/IP> -p <port1> <port2> ...

3. 📚 DNS lookup
   - Purpose: Resolve domain names to IP addresses and vice versa.
   - Usage: python nettool.py dnslookup <domain/IP>

4. 🌐 Public IP check
   - Purpose: Display your current public IP address.
   - Usage: python nettool.py publicip

5. ⚡ Internet speed test
   - Purpose: Measure your internet connection speed.
   - Usage: python nettool.py speedtest

6. ℹ️ WHOIS domain lookup
   - Purpose: Retrieve registration information for a domain.
   - Usage: python nettool.py whois <domain>

7. 🛣️ Traceroute
   - Purpose: Display the route packets take to reach a target host.
   - Usage: python nettool.py traceroute <hostname/IP>

8. 🛡️ DDOS attack detection
   - Purpose: Monitor incoming traffic for potential DDOS attacks.
   - Usage: python nettool.py ddosdetect

9. 🔍 Network device discovery
   - Purpose: Scan local network for active devices.
   - Usage: python nettool.py discover

10. 💻 Remote OS detection
    - Purpose: Attempt to identify the operating system of a remote host.
    - Usage: python nettool.py osdetect <hostname/IP>

11. 📡 Network interface listing
    - Purpose: Display information about network interfaces on your system.
    - Usage: python nettool.py interfaces

12. 📦 Packet capture
    - Purpose: Capture and analyze network packets.
    - Usage: python nettool.py capture -i <interface> -f <filter>

## 🚀 Quick Start

1. Clone and install:
   git clone https://github.com/sioaeko/nettool.git
   cd nettool
   pip install -r requirements.txt

2. Run a command:
   python nettool.py <action> [target] [options]

   Example:
   python nettool.py portscan 192.168.1.1 -p 80 443 8080

3. Get help:
   python nettool.py -h

## 📖 Documentation

For detailed usage and examples, visit our [Wiki](https://github.com/yourusername/nettool/wiki).

## 🛡️ Disclaimer

Use responsibly. Unauthorized network scanning may be illegal.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
