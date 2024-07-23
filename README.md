# NetTool

NetTool is a versatile command-line network utility for diagnostics, security checks, and performance analysis.

## Features

- Ping
- Port scanning
- DNS lookup
- Public IP check
- Internet speed test
- WHOIS domain lookup
- Traceroute
- DDOS attack detection
- Network device discovery
- Remote OS detection
- Network interface listing
- Packet capture

## Installation

1. Clone this repository:
   git clone https://github.com/yourusername/nettool.git

2. Install required packages:
   pip install -r requirements.txt

## Usage

Run the tool with Python:

python nettool.py [action] [target] [options]

For example:
python nettool.py ping example.com
python nettool.py portscan 192.168.1.1 -p 80 443 8080
python nettool.py speedtest

For more information on available actions and options, run:
python nettool.py -h

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Use this tool responsibly. Unauthorized scanning or testing on networks you don't own or have explicit permission to test may be illegal.
