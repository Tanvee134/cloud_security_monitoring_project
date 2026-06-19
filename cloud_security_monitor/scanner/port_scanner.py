"""
Port Scanner Module
--------------------
Provides port scanning capabilities for the Cloud Security Monitor.
Scans common ports on target servers to identify open services
and potential security vulnerabilities.

Scanned Ports:
  - 22   (SSH)       → Medium risk if open
  - 80   (HTTP)      → Low risk
  - 443  (HTTPS)     → Low risk (expected to be open)
  - 3306 (MySQL)     → High risk if open
  - 5432 (PostgreSQL)→ High risk if open
  - 8080 (Alt HTTP)  → Medium risk if open
"""

import socket
from datetime import datetime


# Port metadata: port number → (service name, risk if open)
PORT_INFO = {
    22:   {'service': 'SSH',        'risk': 'Medium',   'description': 'Secure Shell'},
    80:   {'service': 'HTTP',       'risk': 'Low',      'description': 'Hypertext Transfer Protocol'},
    443:  {'service': 'HTTPS',      'risk': 'Low',      'description': 'HTTP Secure'},
    3306: {'service': 'MySQL',      'risk': 'High',     'description': 'MySQL Database'},
    5432: {'service': 'PostgreSQL', 'risk': 'High',     'description': 'PostgreSQL Database'},
    8080: {'service': 'HTTP-ALT',   'risk': 'Medium',   'description': 'Alternative HTTP'},
}

# Default ports to scan
DEFAULT_PORTS = [22, 80, 443, 3306, 5432, 8080]


class PortScanner:
    """
    Scans target servers for open ports and assesses security risks.
    
    Attributes:
        timeout (int): Socket connection timeout in seconds.
        ports (list): List of ports to scan.
    """

    def __init__(self, timeout=2, ports=None):
        """
        Initialize the port scanner.
        
        Args:
            timeout (int): Connection timeout in seconds (default: 2).
            ports (list): Custom list of ports to scan (default: DEFAULT_PORTS).
        """
        self.timeout = timeout
        self.ports = ports or DEFAULT_PORTS

    def scan_port(self, ip_address, port):
        """
        Scan a single port on the target IP address.
        
        Args:
            ip_address (str): Target IP address or hostname.
            port (int): Port number to scan.
        
        Returns:
            dict: Scan result with keys: port, status, service, risk_level, description.
        """
        port_meta = PORT_INFO.get(port, {
            'service': 'Unknown',
            'risk': 'Low',
            'description': 'Unknown Service'
        })

        try:
            # Create a socket connection attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()

            if result == 0:
                # Port is open
                return {
                    'port': port,
                    'status': 'open',
                    'service': port_meta['service'],
                    'risk_level': port_meta['risk'],
                    'description': port_meta['description']
                }
            else:
                # Port is closed
                return {
                    'port': port,
                    'status': 'closed',
                    'service': port_meta['service'],
                    'risk_level': 'None',
                    'description': port_meta['description']
                }

        except socket.gaierror:
            # Hostname could not be resolved
            return {
                'port': port,
                'status': 'error',
                'service': port_meta['service'],
                'risk_level': 'Unknown',
                'description': 'Host resolution failed'
            }
        except socket.error:
            # Connection error
            return {
                'port': port,
                'status': 'closed',
                'service': port_meta['service'],
                'risk_level': 'None',
                'description': port_meta['description']
            }

    def scan_all_ports(self, ip_address):
        """
        Scan all configured ports on the target server.
        
        Args:
            ip_address (str): Target IP address or hostname.
        
        Returns:
            dict: Complete scan results including:
                - ip_address: Target IP
                - scan_time: Timestamp of the scan
                - results: List of individual port scan results
                - summary: Aggregated scan statistics
        """
        results = []
        scan_time = datetime.utcnow()

        for port in self.ports:
            result = self.scan_port(ip_address, port)
            results.append(result)

        # Build summary statistics
        open_ports = [r for r in results if r['status'] == 'open']
        closed_ports = [r for r in results if r['status'] == 'closed']

        summary = {
            'total_ports_scanned': len(results),
            'open_ports': len(open_ports),
            'closed_ports': len(closed_ports),
            'open_port_list': [r['port'] for r in open_ports],
            'closed_port_list': [r['port'] for r in closed_ports]
        }

        return {
            'ip_address': ip_address,
            'scan_time': scan_time,
            'results': results,
            'summary': summary
        }


class RiskAssessor:
    """
    Calculates risk scores and generates security recommendations
    based on port scan results.
    
    Risk Rules:
        - Open SSH (22):                  +20 points → Medium Risk
        - Open Database (3306, 5432):     +30 points each → High Risk
        - Open HTTP without HTTPS:        +10 points → Low Risk
        - Open Alt-HTTP (8080):           +15 points → Medium Risk
        - Multiple critical ports open:   +25 bonus → Critical Risk
    
    Risk Levels:
        - 0-25:   Low
        - 26-50:  Medium
        - 51-75:  High
        - 76-100: Critical
    """

    # Points awarded for each open port
    RISK_POINTS = {
        22:   20,   # SSH open
        80:   5,    # HTTP open (minor risk)
        443:  0,    # HTTPS expected to be open
        3306: 30,   # MySQL exposed
        5432: 30,   # PostgreSQL exposed
        8080: 15,   # Alt-HTTP open
    }

    @staticmethod
    def calculate_risk(scan_results):
        """
        Calculate overall risk score from scan results.
        
        Args:
            scan_results (list): List of port scan result dicts.
        
        Returns:
            dict: Risk assessment with score, level, and color.
        """
        score = 0
        open_ports = []

        for result in scan_results:
            if result['status'] == 'open':
                port = result['port']
                open_ports.append(port)
                score += RiskAssessor.RISK_POINTS.get(port, 10)

        # Bonus penalty: multiple database ports open
        db_ports_open = len([p for p in open_ports if p in [3306, 5432]])
        if db_ports_open >= 2:
            score += 25

        # Bonus penalty: SSH + database port open together
        if 22 in open_ports and db_ports_open > 0:
            score += 15

        # Cap score at 100
        score = min(score, 100)

        # Determine risk level
        if score <= 25:
            level = 'Low'
            color = '#00e676'
        elif score <= 50:
            level = 'Medium'
            color = '#ffab00'
        elif score <= 75:
            level = 'High'
            color = '#ff5252'
        else:
            level = 'Critical'
            color = '#e91e63'

        return {
            'score': score,
            'level': level,
            'color': color,
            'open_ports': open_ports
        }

    @staticmethod
    def generate_recommendations(scan_results):
        """
        Generate security recommendations based on scan results.
        
        Args:
            scan_results (list): List of port scan result dicts.
        
        Returns:
            list: List of recommendation dicts with text, severity, and icon.
        """
        recommendations = []
        open_ports = [r['port'] for r in scan_results if r['status'] == 'open']

        # SSH recommendations
        if 22 in open_ports:
            recommendations.append({
                'text': 'Restrict SSH access using firewall rules. Allow only trusted IP addresses.',
                'severity': 'Medium',
                'icon': 'bi-shield-lock'
            })
            recommendations.append({
                'text': 'Disable password-based SSH authentication and use SSH key pairs instead.',
                'severity': 'Medium',
                'icon': 'bi-key'
            })

        # Database port recommendations
        if 3306 in open_ports:
            recommendations.append({
                'text': 'Close MySQL port (3306) to public access. Use private networking or VPN.',
                'severity': 'High',
                'icon': 'bi-database-x'
            })
            recommendations.append({
                'text': 'Ensure MySQL root login is disabled for remote connections.',
                'severity': 'High',
                'icon': 'bi-person-x'
            })

        if 5432 in open_ports:
            recommendations.append({
                'text': 'Close PostgreSQL port (5432) to public access. Use private networking.',
                'severity': 'High',
                'icon': 'bi-database-x'
            })
            recommendations.append({
                'text': 'Review PostgreSQL pg_hba.conf to restrict client authentication.',
                'severity': 'High',
                'icon': 'bi-file-earmark-lock'
            })

        # HTTP/HTTPS recommendations
        if 80 in open_ports and 443 not in open_ports:
            recommendations.append({
                'text': 'Enable HTTPS (port 443) and redirect all HTTP traffic to HTTPS.',
                'severity': 'High',
                'icon': 'bi-lock'
            })

        if 80 in open_ports and 443 in open_ports:
            recommendations.append({
                'text': 'Configure automatic HTTP to HTTPS redirect to enforce encrypted connections.',
                'severity': 'Low',
                'icon': 'bi-arrow-repeat'
            })

        # Alt-HTTP recommendations
        if 8080 in open_ports:
            recommendations.append({
                'text': 'Close alternative HTTP port (8080) if not required. It may expose admin panels.',
                'severity': 'Medium',
                'icon': 'bi-x-circle'
            })

        # General recommendations (always included)
        recommendations.append({
            'text': 'Enable cloud provider firewall (Security Groups / VPC Firewall) to restrict inbound traffic.',
            'severity': 'Info',
            'icon': 'bi-cloud-check'
        })

        recommendations.append({
            'text': 'Use a Web Application Firewall (WAF) to protect against common attacks.',
            'severity': 'Info',
            'icon': 'bi-shield-check'
        })

        recommendations.append({
            'text': 'Schedule regular security scans to monitor for configuration drift.',
            'severity': 'Info',
            'icon': 'bi-calendar-check'
        })

        # Critical: multiple database ports
        if 3306 in open_ports and 5432 in open_ports:
            recommendations.insert(0, {
                'text': 'CRITICAL: Multiple database ports are exposed. Immediately restrict access to prevent data breach.',
                'severity': 'Critical',
                'icon': 'bi-exclamation-triangle'
            })

        return recommendations
