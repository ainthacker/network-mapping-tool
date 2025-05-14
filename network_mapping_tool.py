#!/usr/bin/env python3
"""
Network Mapping Tool

This script performs network discovery and mapping, identifying hosts and open ports
on a specified network range. It creates a comprehensive report of active devices
and their services.

Features:
- Host discovery using ICMP and ARP
- Port scanning with service identification
- OS fingerprinting attempt
- Network mapping visualization
- Detailed report generation

Usage:
    python network_mapper.py -t <target_network> [options]
    
Example:
    python network_mapper.py -t 192.168.1.0/24 -p 22,80,443 -o network_map.html
"""

import argparse
import csv
import datetime
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Tuple, Union
import re

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy library not found. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "scapy"])
    import scapy.all as scapy

# Nmap bağımlılığını kaldırıyoruz
# try:
#     import nmap
# except ImportError:
#     print("python-nmap library not found. Installing...")
#     subprocess.call([sys.executable, "-m", "pip", "install", "python-nmap"])
#     import nmap

try:
    import matplotlib.pyplot as plt
    import networkx as nx
except ImportError:
    print("Visualization libraries not found. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "matplotlib networkx"])
    import matplotlib.pyplot as plt
    import networkx as nx
    
try:
    from rich.console import Console
    from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.tree import Tree
except ImportError:
    print("Rich library not found. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.console import Console
    from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.tree import Tree

# Initialize rich console
console = Console()

# Common ports to scan if not specified
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Servis isimlerini içeren dictionary
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5900: "vnc",
    8080: "http-proxy"
}

class PortScanner:
    """Kendi port tarama sınıfımız"""
    
    @staticmethod
    def scan_tcp_port(ip: str, port: int, timeout: float = 1.0) -> Dict:
        """Belirli bir TCP portu tarar ve sonucu döndürür"""
        result = {
            "port": port,
            "state": "closed",
            "service": COMMON_SERVICES.get(port, "unknown"),
            "product": "",
            "version": "",
            "banner": "",
            "powered_by": ""
        }
        
        try:
            # TCP soketi oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Port bağlantısını dene
            conn_result = sock.connect_ex((ip, port))
            
            # Bağlantı başarılıysa
            if conn_result == 0:
                result["state"] = "open"
                
                # Servis bilgisi almaya çalış - Geliştirilmiş Banner Grabbing
                try:
                    # FTP servisi için
                    if port == 21:
                        banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
                        if banner:
                            result["product"] = "FTP"
                            parts = banner.split(' ')
                            if len(parts) > 1:
                                # FTP banner genellikle "ProductName Version" formatındadır
                                result["product"] = parts[0]
                                if len(parts) > 1:
                                    result["version"] = parts[1]
                                # Tam banner bilgisini de ekleyelim
                                result["banner"] = banner
                    
                    # SSH servisi için
                    elif port == 22:
                        banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
                        if banner:
                            # SSH banner örneği: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
                            result["product"] = "SSH"
                            if "SSH-" in banner:
                                parts = banner.split('-')
                                if len(parts) >= 3:
                                    product_version = parts[2].split(' ')[0]
                                    if '_' in product_version:
                                        product, version = product_version.split('_', 1)
                                        result["product"] = product
                                        result["version"] = version
                                    else:
                                        result["product"] = product_version
                            result["banner"] = banner
                    
                    # SMTP servisi için
                    elif port == 25 or port == 587:
                        # İlk karşılama mesajını al
                        banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
                        if banner:
                            result["product"] = "SMTP"
                            parts = banner.split(' ')
                            if len(parts) > 1:
                                for part in parts:
                                    # Genellikle ESMTP Postfix, Microsoft ESMTP gibi bilgiler içerir
                                    if any(name in part.upper() for name in ["ESMTP", "POSTFIX", "EXCHANGE", "MICROSOFT"]):
                                        result["product"] = part
                                    # Versiyon numarası genellikle x.x.x formatındadır
                                    elif re.match(r'\d+\.\d+(\.\d+)?', part):
                                        result["version"] = part
                            result["banner"] = banner
                        
                        # EHLO komutu göndererek ek bilgiler alabiliriz
                        try:
                            sock.send(b"EHLO test\r\n")
                            response = sock.recv(1024).decode('utf-8', 'ignore')
                            if "Microsoft" in response or "Exchange" in response:
                                result["product"] = "Microsoft SMTP"
                            elif "Postfix" in response:
                                result["product"] = "Postfix"
                        except:
                            pass
                    
                    # HTTP/HTTPS servisleri için
                    elif port == 80 or port == 443 or port == 8080 or port == 8443:
                        # HTTP başlığı gönder
                        http_request = "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".format(ip)
                        sock.send(http_request.encode())
                        
                        # Yanıtı al - sadece header kısmını alalım
                        response = b""
                        try:
                            while True:
                                data = sock.recv(1024)
                                if not data:
                                    break
                                response += data
                                if b"\r\n\r\n" in response or len(response) > 4096:
                                    break
                        except:
                            pass
                        
                        response_text = response.decode('utf-8', 'ignore')
                        
                        # HTTP yanıtını parse et
                        if "HTTP/" in response_text:
                            result["product"] = "HTTP Server"
                            
                            # Server header'ı ara
                            server_match = re.search(r'Server: (.*?)\r\n', response_text)
                            if server_match:
                                server = server_match.group(1).strip()
                                if "/" in server:
                                    product, version = server.split("/", 1)
                                    result["product"] = product.strip()
                                    result["version"] = version.strip()
                                else:
                                    result["product"] = server
                            
                            # X-Powered-By header'ı ara (PHP, ASP.NET vs. için)
                            powered_match = re.search(r'X-Powered-By: (.*?)\r\n', response_text)
                            if powered_match:
                                result["powered_by"] = powered_match.group(1).strip()
                                
                            result["banner"] = "HTTP Response Headers"
                    
                    # MySQL servisi için
                    elif port == 3306:
                        banner = sock.recv(1024)
                        if banner:
                            try:
                                # MySQL protocol banner: ilk byte'ı atla, sonraki kısım versiyon bilgisidir
                                if len(banner) > 5:
                                    mysql_version = banner[5:].split(b'\x00')[0].decode('utf-8', 'ignore')
                                    result["product"] = "MySQL"
                                    result["version"] = mysql_version
                                    result["banner"] = mysql_version
                            except:
                                pass
                    
                    # RDP (Remote Desktop) servisi için
                    elif port == 3389:
                        # RDP bağlantı isteği gönder
                        rdp_request = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
                        sock.send(rdp_request)
                        response = sock.recv(1024)
                        if response:
                            result["product"] = "RDP"
                            # RDP protokol detaylarına göre versiyon çıkarma işlemi yapılabilir
                            if len(response) > 11:
                                rdp_version = response[11]
                                result["version"] = f"Protocol {rdp_version}"
                    
                    # PostgreSQL servisi için
                    elif port == 5432:
                        # PostgreSQL handshake paketi
                        # Format: int32 len, int32 protocol version, "user\0", "database\0", "additional\0"
                        pg_request = b'\x00\x00\x00\x08\x00\x03\x00\x00'
                        sock.send(pg_request)
                        response = sock.recv(1024)
                        if response and response[0] == 82:  # 'R' karakteri - authentication request
                            result["product"] = "PostgreSQL"
                            # Gerçek versiyonu almak için ek sorgular gerekir
                    
                    # Diğer yaygın servisler buraya eklenebilir
                    # Örn: LDAP, DNS, FTP Data, SNMP, VNC, vb.
                    
                except Exception as e:
                    # Banner grabbing'de hata olursa sessizce devam et
                    pass
            
            sock.close()
            
        except Exception as e:
            # Hata durumunda port kapalı olarak kabul edilir
            pass
            
        return result
    
    @staticmethod
    def scan_host(ip: str, ports: List[int], timeout: float = 1.0) -> Dict:
        """Belirli bir host'un belirtilen portlarını tarar"""
        results = {}
        
        for port in ports:
            port_result = PortScanner.scan_tcp_port(ip, port, timeout)
            if port_result["state"] == "open":
                results[port] = {
                    "service": port_result["service"],
                    "product": port_result["product"],
                    "version": port_result["version"],
                    "state": port_result["state"],
                    "banner": port_result["banner"],
                    "powered_by": port_result["powered_by"]
                }
                
        return results
    
    @staticmethod
    def detect_os(ip: str) -> str:
        """Basit OS tespiti yapar (TTL değeri üzerinden tahmini)"""
        try:
            # ICMP paketi gönder ve TTL değerine göre işletim sistemi tahmin et
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", str(ip)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            if "ttl=" in ping_result.stdout.lower():
                ttl_text = ping_result.stdout.lower().split("ttl=")[1].split(" ")[0]
                ttl = int(ttl_text)
                
                # TTL değerine göre işletim sistemi tahmini
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Cisco/Network Device"
            
            return "Unknown"
        except:
            return "Unknown"

class NetworkMapper:
    def __init__(self, target_network: str, ports: List[int] = None, output_file: str = None, 
                 scan_timeout: int = 5, threads: int = 100, aggressive: bool = False):
        """Initialize the network mapper."""
        self.target_network = target_network
        self.ports = ports or DEFAULT_PORTS
        self.output_file = output_file
        self.scan_timeout = scan_timeout
        self.thread_count = threads
        self.aggressive = aggressive
        self.discovered_hosts = {}
        # Nmap bağımlılığını kaldırdık
        # self.nm = nmap.PortScanner()
        
    def is_valid_target(self) -> bool:
        """Validate the target network input."""
        try:
            ipaddress.ip_network(self.target_network, strict=False)
            return True
        except ValueError:
            return False
            
    def discover_hosts(self) -> Dict:
        """
        Discover active hosts on the network using ARP and ICMP.
        Returns a dictionary of discovered hosts with MAC addresses.
        """
        # Live display kullanmadan mesaj
        console.print(f"[bold blue]Discovering hosts on {self.target_network}...[/bold blue]")
        
        # Create ARP request packet
        network = ipaddress.ip_network(self.target_network, strict=False)
        
        discovered = {}
        
        # For small networks, scan all hosts
        if network.num_addresses < 256:
            arp_request = scapy.ARP(pdst=self.target_network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[bold cyan]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[bold blue]Sending ARP requests...", total=100)
                
                # Send ARP request and wait for response
                progress.update(task, advance=50)
                answered_list = scapy.srp(arp_request_broadcast, timeout=self.scan_timeout, verbose=False)[0]
                progress.update(task, advance=50)
            
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                
                discovered[ip] = {"mac": mac, "hostname": hostname, "ports": {}}
        else:
            # For larger networks, use ping sweep instead of ARP
            console.print(f"[yellow]Large network detected ({network.num_addresses} addresses), using ping sweep...[/yellow]")
            
            def ping_host(ip):
                try:
                    # Using ping with timeout to check if host is alive
                    ping_result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", str(ip)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    if ping_result.returncode == 0:
                        try:
                            hostname = socket.gethostbyaddr(str(ip))[0]
                        except socket.herror:
                            hostname = "Unknown"
                        return str(ip), hostname
                    return None
                except:
                    return None
            
            # Use a subset of IPs for large networks
            sample_ips = list(network.hosts())
            if len(sample_ips) > 1000:
                # Get first, last, and 998 evenly distributed IPs in between
                step = len(sample_ips) // 999
                sample_ips = [sample_ips[i] for i in range(0, len(sample_ips), step)][:1000]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[bold cyan]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                ping_task = progress.add_task("[bold blue]Pinging hosts...", total=len(sample_ips))
                
                with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                    futures = []
                    for ip in sample_ips:
                        futures.append(executor.submit(ping_host, ip))
                    
                    for future in futures:
                        result = future.result()
                        if result:
                            ip, hostname = result
                            discovered[ip] = {"mac": "Unknown", "hostname": hostname, "ports": {}}
                        progress.update(ping_task, advance=1)
        
        console.print(f"[green]✓ Discovery complete. Found {len(discovered)} active hosts.[/green]")
        self.discovered_hosts = discovered
        
        # Display discovered hosts in a table
        if discovered:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("IP Address")
            table.add_column("Hostname")
            table.add_column("MAC Address")
            
            for ip, info in discovered.items():
                table.add_row(
                    ip,
                    info.get('hostname', 'Unknown'),
                    info.get('mac', 'Unknown')
                )
            
            console.print(Panel(table, title="[bold green]Discovered Hosts", border_style="green"))
        
        return discovered
    
    def scan_ports(self, host: str, progress=None, task_id=None) -> Dict:
        """
        Scan ports on a specific host.
        Returns dictionary of open ports with service info.
        """
        host_info = self.discovered_hosts.get(host, {"ports": {}})
        
        if progress:
            progress.update(task_id, description=f"[bold blue]Scanning {host}...")
        
        try:
            # Kendi Port Scanner'ımızı kullan
            ports_result = PortScanner.scan_host(host, self.ports, timeout=self.scan_timeout)
            
            # Port bilgilerini host_info'ya ekle
            host_info["ports"] = ports_result
            
            # Agresif mod etkinse OS tespiti yap
            if self.aggressive:
                host_info['os'] = PortScanner.detect_os(host)
            else:
                host_info['os'] = "Unknown"
                
            if progress:
                progress.update(task_id, advance=1)
                
            return host_info
        except Exception as e:
            console.print(f"[bold red]Error scanning {host}: {e}[/bold red]")
            if progress:
                progress.update(task_id, advance=1)
            return host_info
    
    def scan_network(self) -> Dict:
        """
        Perform the entire network scan.
        Discovers hosts and scans ports on each discovered host.
        """
        if not self.is_valid_target():
            console.print(f"[bold red]Invalid network target: {self.target_network}[/bold red]")
            return {}
        
        # Display scan parameters in a nice panel
        scan_info = Table.grid(padding=1)
        scan_info.add_column(style="green", justify="right")
        scan_info.add_column(style="cyan")
        
        scan_info.add_row("Target Network:", self.target_network)
        scan_info.add_row("Ports to Scan:", ", ".join(map(str, self.ports)))
        scan_info.add_row("Scan Timeout:", f"{self.scan_timeout} seconds")
        scan_info.add_row("Thread Count:", str(self.thread_count))
        scan_info.add_row("Aggressive Mode:", "Enabled" if self.aggressive else "Disabled")
        
        console.print(Panel(scan_info, title="[bold blue]Network Scan Parameters", border_style="blue"))
        
        # Step 1: Discover hosts
        self.discover_hosts()
        
        if not self.discovered_hosts:
            console.print("[bold red]No hosts discovered. Exiting.[/bold red]")
            return {}
        
        # Step 2: Scan ports on each host
        console.print(f"[bold blue]Starting port scan on {len(self.discovered_hosts)} hosts...[/bold blue]")
        
        # Use threading for faster scanning
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[bold cyan]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            scan_task = progress.add_task("[bold blue]Scanning hosts...", total=len(self.discovered_hosts))
            
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_to_host = {}
                
                for host in self.discovered_hosts.keys():
                    future = executor.submit(self.scan_ports, host, progress, scan_task)
                    future_to_host[future] = host
                
                for future in future_to_host:
                    host = future_to_host[future]
                    try:
                        host_info = future.result()
                        self.discovered_hosts[host].update(host_info)
                    except Exception as e:
                        console.print(f"[bold red]Error processing {host}: {e}[/bold red]")
        
        console.print(f"[bold green]✓ Network scan complete. Scanned {len(self.discovered_hosts)} hosts.[/bold green]")
        
        # Display results summary
        open_port_count = sum(len(host_info.get('ports', {})) for host_info in self.discovered_hosts.values())
        
        results_summary = Table.grid(padding=1)
        results_summary.add_column(style="green", justify="right")
        results_summary.add_column(style="cyan")
        
        results_summary.add_row("Hosts Scanned:", str(len(self.discovered_hosts)))
        results_summary.add_row("Open Ports Found:", str(open_port_count))
        
        console.print(Panel(results_summary, title="[bold green]Scan Results Summary", border_style="green"))
        
        return self.discovered_hosts
    
    def generate_network_graph(self) -> nx.Graph:
        """Generate a network graph visualization."""
        # Live display yerine normal mesaj kullanımı
        console.print("[bold blue]Generating network graph...[/bold blue]")
        
        G = nx.Graph()
        
        # Add gateway (assuming first IP in network is gateway)
        network = ipaddress.ip_network(self.target_network, strict=False)
        gateway_ip = str(list(network.hosts())[0])
        G.add_node(gateway_ip, type="gateway")
        
        # Add discovered hosts
        for ip, info in self.discovered_hosts.items():
            hostname = info.get('hostname', 'Unknown')
            label = f"{hostname}\n{ip}" if hostname != "Unknown" else ip
            
            # Count open ports
            open_ports = len(info.get('ports', {}))
            
            # Determine node type by open ports
            if any(port in info.get('ports', {}) for port in [80, 443, 8080]):
                node_type = "web_server"
            elif 22 in info.get('ports', {}):
                node_type = "ssh_server"
            elif open_ports > 5:
                node_type = "server"
            else:
                node_type = "host"
            
            G.add_node(ip, label=label, type=node_type, open_ports=open_ports)
            
            # Connect to gateway
            G.add_edge(gateway_ip, ip)
        
        console.print("[bold green]✓ Network graph generated.[/bold green]")
        return G

    def save_results(self) -> None:
        """Save scan results to files."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = os.path.join(os.getcwd(), f"network_scan_{timestamp}")
        os.makedirs(base_dir, exist_ok=True)
        
        # Live display yerine normal mesaj kullanımı
        console.print("[bold blue]Saving scan results...[/bold blue]")
        
        # Save JSON data
        json_file = os.path.join(base_dir, "scan_results.json")
        with open(json_file, 'w') as f:
            json.dump(self.discovered_hosts, f, indent=4)
        
        # Save CSV report
        csv_file = os.path.join(base_dir, "host_report.csv")
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Hostname", "MAC Address", "OS", "Open Ports", "Services"])
            
            for ip, info in self.discovered_hosts.items():
                ports_str = ", ".join([f"{port} ({info['ports'][port]['service']})" 
                                    for port in info.get('ports', {})])
                writer.writerow([
                    ip,
                    info.get('hostname', 'Unknown'),
                    info.get('mac', 'Unknown'),
                    info.get('os', 'Unknown'),
                    len(info.get('ports', {})),
                    ports_str
                ])
        
        # Generate and save visualization
        try:
            G = self.generate_network_graph()
            plt.figure(figsize=(12, 10))
            
            # Position nodes using spring layout
            pos = nx.spring_layout(G)
            
            # Draw nodes with different colors based on type
            node_colors = {
                'gateway': 'red',
                'web_server': 'green',
                'ssh_server': 'blue',
                'server': 'purple',
                'host': 'gray'
            }
            
            for node_type, color in node_colors.items():
                nx.draw_networkx_nodes(
                    G, pos,
                    nodelist=[n for n, d in G.nodes(data=True) if d.get('type') == node_type],
                    node_color=color,
                    node_size=800,
                    alpha=0.8,
                    label=node_type
                )
            
            # Draw edges
            nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5)
            
            # Draw labels
            labels = {n: d.get('label', n) for n, d in G.nodes(data=True)}
            nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)
            
            plt.title(f"Network Map: {self.target_network}")
            plt.legend()
            plt.axis('off')
            
            plt.tight_layout()
            plt.savefig(os.path.join(base_dir, "network_map.png"), dpi=300)
            
            # If HTML output is requested
            if self.output_file and self.output_file.endswith('.html'):
                html_path = os.path.join(base_dir, "network_map.html")
                self._generate_html_report(html_path)
            
        except Exception as e:
            console.print(f"[bold red]Error generating visualization: {e}[/bold red]")
        
        console.print(f"[bold green]✓ Results saved to {base_dir}[/bold green]")
        
        # Display a summary of the saved files
        saved_files = Table()
        saved_files.add_column("File", style="cyan")
        saved_files.add_column("Description", style="green")
        
        saved_files.add_row("scan_results.json", "Raw JSON data of all scan results")
        saved_files.add_row("host_report.csv", "CSV report of hosts and services")
        saved_files.add_row("network_map.png", "Network visualization image")
        
        if self.output_file and self.output_file.endswith('.html'):
            saved_files.add_row("network_map.html", "Interactive HTML report")
        
        console.print(Panel(saved_files, title="[bold blue]Saved Files", border_style="blue"))
    
    def _generate_html_report(self, html_path: str) -> None:
        """Generate detailed HTML report with interactive elements."""
        # Live display yerine normal mesaj kullanımı
        console.print("[bold blue]Generating HTML report...[/bold blue]")
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Map: {self.target_network}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; color: #333; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .container {{ max-width: 1200px; margin: 20px auto; display: flex; flex-wrap: wrap; gap: 20px; padding: 0 20px; }}
        .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }}
        .card-header {{ background: #3498db; color: white; padding: 15px; font-size: 18px; font-weight: bold; }}
        .card-body {{ padding: 20px; }}
        .network-map {{ flex: 1; min-width: 300px; }}
        .host-list {{ flex: 1; min-width: 300px; }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ flex: 1; min-width: 200px; background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #2980b9; margin: 10px 0; }}
        .stat-label {{ color: #7f8c8d; font-size: 14px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th {{ background-color: #f2f2f2; color: #333; text-align: left; padding: 12px; }}
        td {{ border-bottom: 1px solid #ddd; padding: 12px; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #7f8c8d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Scan Report</h1>
        <p>Comprehensive analysis of {self.target_network}</p>
    </div>
    
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Target Network</div>
                <div class="stat-value">{self.target_network}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Scan Date</div>
                <div class="stat-value">{datetime.datetime.now().strftime("%Y-%m-%d")}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Hosts Discovered</div>
                <div class="stat-value">{len(self.discovered_hosts)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Open Ports</div>
                <div class="stat-value">{sum(len(info.get('ports', {})) for info in self.discovered_hosts.values())}</div>
            </div>
        </div>
        
        <div class="network-map card">
            <div class="card-header">Network Map</div>
            <div class="card-body">
                <img src="network_map.png" alt="Network Map" style="max-width: 100%;">
            </div>
        </div>
        
        <div class="host-list card">
            <div class="card-header">Host Details</div>
            <div class="card-body">
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Open Ports</th>
                    </tr>
        """
        
        # Add table rows for each host
        for ip, info in self.discovered_hosts.items():
            ports_str = ", ".join([f"{port} ({info['ports'][port]['service']})" for port in info.get('ports', {})])
            html_content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{info.get('hostname', 'Unknown')}</td>
                        <td>{ports_str}</td>
                    </tr>"""
        
        html_content += """
                </table>
            </div>
        </div>
    </div>
    
    <div class="footer">
        Generated with Network Mapping Tool
    </div>
</body>
</html>
        """
        
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        console.print("[bold green]✓ HTML report generated.[/bold green]")

    def display_results(self) -> None:
        """Sonuçları sadece terminalde göster, dosya yaratma."""
        console.print("[bold blue]Displaying scan results...[/bold blue]")
        
        # Host ve port bilgilerini göster
        for ip, info in self.discovered_hosts.items():
            host_panel = Panel(
                f"[bold cyan]IP Address:[/bold cyan] {ip}\n"
                f"[bold cyan]Hostname:[/bold cyan] {info.get('hostname', 'Unknown')}\n"
                f"[bold cyan]MAC Address:[/bold cyan] {info.get('mac', 'Unknown')}\n"
                f"[bold cyan]OS:[/bold cyan] {info.get('os', 'Unknown')}",
                title=f"[bold blue]Host Details[/bold blue]",
                border_style="blue"
            )
            console.print(host_panel)
            
            # Port bilgilerini tablo olarak göster
            if info.get('ports'):
                port_table = Table(title="Open Ports", show_header=True, header_style="bold magenta")
                port_table.add_column("Port")
                port_table.add_column("Service")
                port_table.add_column("Product")
                port_table.add_column("Version")
                port_table.add_column("Banner/Details")
                
                for port, port_info in info.get('ports', {}).items():
                    # Uzun banner bilgisini kısalt
                    banner = port_info.get('banner', '')
                    if len(banner) > 50:
                        banner = banner[:47] + "..."
                    
                    # Powered By bilgisini ekle
                    if port_info.get('powered_by'):
                        if banner:
                            banner += f" (Powered by: {port_info.get('powered_by')})"
                        else:
                            banner = f"Powered by: {port_info.get('powered_by')}"
                    
                    port_table.add_row(
                        str(port),
                        port_info.get('service', 'unknown'),
                        port_info.get('product', ''),
                        port_info.get('version', ''),
                        banner
                    )
                
                console.print(port_table)
            else:
                console.print("[yellow]No open ports found on this host.[/yellow]")
            
        # Özet istatistikleri göster
        summary = Table.grid(padding=1)
        summary.add_column(style="green", justify="right")
        summary.add_column(style="cyan")
        
        summary.add_row("Target Network:", self.target_network)
        summary.add_row("Scan Date:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        summary.add_row("Hosts Scanned:", str(len(self.discovered_hosts)))
        summary.add_row("Open Ports Found:", str(sum(len(host_info.get('ports', {})) for host_info in self.discovered_hosts.values())))
        
        console.print(Panel(summary, title="[bold green]Scan Summary[/bold green]", border_style="green"))
        
        console.print("[bold green]✓ Scan results displayed. No files were created.[/bold green]")

def print_banner():
    """Print a stylish banner for the tool."""
    banner = """
    [bold blue]╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║  [bold cyan]███    ██ ███████ ████████ ███    ███  █████  ██████[/bold cyan]   ║
    ║  [bold cyan]████   ██ ██         ██    ████  ████ ██   ██ ██   ██[/bold cyan]  ║
    ║  [bold cyan]██ ██  ██ █████      ██    ██ ████ ██ ███████ ██████[/bold cyan]   ║
    ║  [bold cyan]██  ██ ██ ██         ██    ██  ██  ██ ██   ██ ██[/bold cyan]        ║
    ║  [bold cyan]██   ████ ███████    ██    ██      ██ ██   ██ ██[/bold cyan]        ║
    ║                                                       ║
    ║           [bold green]Advanced Network Mapping Tool v1.0[/bold green]           ║
    ║                [dim cyan]Created by AinThacker[/dim cyan]                ║
    ╚═══════════════════════════════════════════════════════╝[/bold blue]
    """
    console.print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Network Mapping Tool')
    parser.add_argument('-t', '--target', required=True, help='Target network (CIDR notation, e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Comma-separated list of ports to scan (default: common ports)')
    parser.add_argument('-o', '--output', help='Output file for report (default: auto-generated)')
    parser.add_argument('-T', '--timeout', type=int, default=5, help='Scan timeout in seconds (default: 5, increase for more reliable results on slower networks)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads for scanning (default: 100)')
    parser.add_argument('-A', '--aggressive', action='store_true', help='Enable aggressive scanning (OS detection, version detection)')
    parser.add_argument('--save', action='store_true', help='Save results to files (default: results are only shown in terminal)')
    
    args = parser.parse_args()
    
    ports = [int(p) for p in args.ports.split(',')] if args.ports else None
    
    try:
        mapper = NetworkMapper(
            target_network=args.target,
            ports=ports,
            output_file=args.output,
            scan_timeout=args.timeout,
            threads=args.threads,
            aggressive=args.aggressive
        )
        
        mapper.scan_network()
        
        if args.save:
            # Dosyaya kaydetme
            mapper.save_results()
        else:
            # Sonuçları sadece terminalde gösterme (varsayılan)
            mapper.display_results()
        
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
