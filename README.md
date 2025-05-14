# Network Mapping Tool

Comprehensive network discovery and mapping tool written in Python. This tool helps you identify active hosts, open ports, services, and creates network visualizations.

## Features

- Fast host discovery using ARP and ICMP
- Detailed port scanning with service detection
- OS fingerprinting through TTL analysis
- Network topology visualization
- Comprehensive terminal output with rich formatting
- Optional file exports (JSON, CSV, PNG, HTML)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/network-mapping-tool.git
cd network-mapping-tool

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python network_mapping_tool.py -t <target_network> [options]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target network in CIDR notation (e.g., 192.168.1.0/24) |
| `-p, --ports` | Comma-separated list of ports to scan (default: common ports) |
| `-o, --output` | Output file for HTML report (optional) |
| `-T, --timeout` | Scan timeout in seconds (default: 5) |
| `--threads` | Number of threads for scanning (default: 100) |
| `-A, --aggressive` | Enable aggressive scanning (OS detection, version detection) |
| `--save` | Save results to files (default: results are only displayed in terminal) |

### Examples

Basic scan of a network:
```bash
python network_mapping_tool.py -t 192.168.1.0/24
```

Scan specific ports with aggressive detection:
```bash
python network_mapping_tool.py -t 192.168.1.0/24 -p 22,80,443,8080 -A
```

Scan with longer timeout for more reliable results:
```bash
python network_mapping_tool.py -t 192.168.1.0/24 -T 10
```

Save results to files:
```bash
python network_mapping_tool.py -t 192.168.1.0/24 --save
```

## Requirements

- Python 3.6+
- Scapy
- Matplotlib
- NetworkX
- Rich

## License

MIT

## Created by

Ainthacker 
