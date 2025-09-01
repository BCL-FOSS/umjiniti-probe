import socket
import json
import psutil
import json
import requests
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import urllib.request
import pyshark
import subprocess
import platform
import re
import shutil
import logging
import urllib.request
import socket
import fcntl
import struct
from utils.network_utils.base.Network import Network


class NetworkInfo(Network):
    def __init__(self):
        super().__init__()
    
    def get_public_ip(self) -> str:
        """
        Retrieves public IP of probe host.

        Returns:
            pub_ip (str): Public IP Address
        """
        services = [
            'https://ident.me',
            'https://api.ipify.org',
            'https://ifconfig.me/ip'
        ]
        for service in services:
            pub_ip = urllib.request.urlopen(service, timeout=5).read().decode('utf8').strip()
            if not isinstance(pub_ip, str):
                continue
            else:
                return pub_ip

    def get_interface_ip(self, interface: str) -> str:
        """
        Retrieves IP address assigned to a specific interface

        Args:
            interface (str): Interface for IP discovery.

        Returns:
            ip (str): IP address of specified interface
        """

        match self.system:
            case 'Linux':
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = socket.inet_ntoa(
                        fcntl.ioctl(
                            sock.fileno(),
                            0x8915,  # SIOCGIFADDR
                            struct.pack('256s', interface.encode('utf-8')[:15])
                        )[20:24]
                    )

                if not ip:
                    output = subprocess.check_output(["ip", "addr", "show", interface], text=True)
                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
                    if match:
                        return match.group(1)
                    else:
                        return 2
                else:
                    return ip
                
            case 'FreeBSD':
                output = subprocess.check_output(["ifconfig", interface], text=True)
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
                if match:
                    return match.group(1)
                else:
                    return 2
            case _:
                self.logger.info('OS not supported')
                return 2       

    def get_default_interface(self) -> str:
        """
        Retrieves the default interface of the probe host

        Returns:
            ip (str): IP address of specified interface
        """

        match self.system:
            case 'Linux':
                output = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], text=True)
                match = re.search(r"dev (\w+)", output)
                if match:
                    return match.group(1)
                else:
                    return 2
            case 'FreeBSD':
                # Prefer route -n get default
                output = subprocess.check_output(["route", "-n", "get", "default"], text=True)
                if output:
                    match = re.search(r"interface: (\w+)", output)
                    if match:
                            return match.group(1)
                else:
                    output = subprocess.check_output(["netstat", "-rn"], text=True)
                    if output:
                        for line in output.splitlines():
                            if line.startswith("default") or line.startswith("0.0.0.0"):
                                parts = line.split()
                                if len(parts) >= 7:
                                    return parts[-1]  # Interface name    
                    else:
                        return 2       
            case _:
                self.logger.info('OS not supported')
                return 2
              
        
    def get_ifaces(self):
        """
        Retrieves all available interfaces of the probe host

        Returns:
            interfaces (list): List of all identified host interfaces 
        """

        interfaces = []

        match self.system:
            case 'linux':
                    if shutil.which('ip'):
                        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, check=True)
                        if result:
                            for line in result.stdout.splitlines():
                                if line and line[0].isdigit():
                                    iface = line.split(':')[1].strip().split('@')[0]  # Remove @altname if present
                                    if iface != 'lo':  # exclude loopback
                                        interfaces.append(iface)
                            return interfaces
                        else:
                            return 2
            case 'freebsd':
                    if shutil.which('ifconfig'):
                        result = subprocess.run(['ifconfig'], capture_output=True, text=True, check=True)
                        if result:
                            # Match interface names at start of lines like: `em0: flags=...`
                            for line in result.stdout.splitlines():
                                match = re.match(r'^([a-zA-Z0-9]+):', line)
                                if match:
                                    iface = match.group(1)
                                    if iface != 'lo0':  # optionally exclude loopback
                                        interfaces.append(iface)
                            return interfaces
                        else:
                            return 2   
            case _:
                self.logger.info('OS not supported')
                return 2

    def get_processes_by_names(self, process_names: list):
        """
        Retrieves all running processes, or processes according to list of specified names.

        Args:
            process_names (list): List of processes to find

        Returns:
            matching_processes (list): List of all or identified processes
        """
        matching_processes = []
        
        try:
            
            if process_names:

                lower_case_names = [name.lower() for name in process_names]
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        
                            proc_name = proc.info['name']
                            if proc_name and proc_name.lower() in lower_case_names:
                                matching_processes.append({
                                    'pid': proc.info['pid'],
                                    'name': proc_name,
                                    'cmdline': proc.info['cmdline']
                                })
                return matching_processes
            
            else:
               
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        
                    proc_name = proc.info['name']
                        
                    matching_processes.append({
                                    'pid': proc.info['pid'],
                                    'name': proc_name,
                                    'cmdline': proc.info['cmdline']
                                })
                return matching_processes
                        
        except Exception as e:
                self.logger.error(f"Error retrieving processes: {e}")
                return 2
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


    def open_listening_ports(self):
        """
        Retrieves all listening ports on supported linux and freebsd firewalls

        Returns:
            ports (list): List of all current opne ports on the probe's host firewall
        """

        ports = set()

        match self.system:
            case 'freebsd':
                self.logger.info("Detected FreeBSD...")
                if self.is_pf_enabled():
                    self.logger.info("PF is enabled. Parsing pf rules...")
                    result = subprocess.run(['pfctl', '-sr'], capture_output=True, text=True, check=True)
                    ports.update(self.parse_pf(result.stdout))
                elif self.is_ipfw_enabled():
                    self.logger.info("IPFW is enabled. Parsing ipfw rules...")
                    result = subprocess.run(['ipfw', 'list'], capture_output=True, text=True, check=True)
                    ports.update(self.parse_ipfw(result.stdout))
                else:
                    self.logger.info("No known firewall (pf/ipfw) enabled on FreeBSD.")
            case 'linux':
                os_release = subprocess.run(['cat', '/etc/os-release'], capture_output=True, text=True).stdout.lower()

                if 'debian' in os_release or 'ubuntu' in os_release:
                    self.logger.info("Detected Debian-based Linux...")
                    if shutil.which('iptables'):
                        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_iptables(result.stdout))
                    if shutil.which('nft'):
                        result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_nftables(result.stdout))

                elif 'rhel' in os_release or 'centos' in os_release or 'fedora' in os_release:
                    self.logger.info("Detected RHEL-based Linux...")
                    if shutil.which('iptables'):
                        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_iptables(result.stdout))
                    if shutil.which('firewall-cmd'):
                        try:
                            result = subprocess.run(['firewall-cmd', '--list-ports'], capture_output=True, text=True, check=True)
                            ports.update(self.parse_firewalld(result.stdout))
                        except subprocess.CalledProcessError:
                            self.logger.info("firewalld not running or not installed.")
                    if shutil.which('nft'):
                        result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True)
                        ports.update(self.parse_nftables(result.stdout))
                else:
                    self.logger.info("Unsupported Linux distro.")
            case _:
                self.logger.info('OS not supported')
                return 2

        for port in sorted(ports):
                self.logger.info(f"Open port {port} is ALLOWED")

        return sorted(ports) if ports else 2
       
    # Port Retrieval Helper Functions

    def parse_iptables(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'dpt:(\d+)', line)
            if match:
                ports.add(int(match.group(1)))
        return ports

    def parse_pf(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'port\s*=\s*(\d+)', line)
            if match:
                ports.add(int(match.group(1)))
            else:
                match = re.search(r'port\s+(\d+)', line)
                if match:
                    ports.add(int(match.group(1)))
        return ports

    def parse_ipfw(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'(?i)tcp\s+from.*to.*(\d{1,5})', line)
            if match:
                ports.add(int(match.group(1)))
        return ports

    def parse_firewalld(self, output):
        ports = set()
        for port_proto in output.strip().split():
            if '/' in port_proto:
                port, _ = port_proto.split('/')
                ports.add(int(port))
        return ports

    def parse_nftables(self, output):
        ports = set()
        for line in output.splitlines():
            match = re.search(r'(?i)dport\s+(\d+)', line)
            if match:
                ports.add(int(match.group(1)))
        return ports

    def is_pf_enabled(self):
        try:
            result = subprocess.run(['sysctl', 'net.pf.enabled'], capture_output=True, text=True)
            return 'net.pf.enabled: 1' in result.stdout
        except:
            return False

    def is_ipfw_enabled(self):
        try:
            result = subprocess.run(['sysctl', 'net.inet.ip.fw.enable'], capture_output=True, text=True)
            return 'net.inet.ip.fw.enable: 1' in result.stdout
        except:
            return False

    

    


            
       

        
        
        
    
        
         
