"""
CYB 333 Security Automation Project
Project: Automated Port and Vulnerability Scanner
Author: Keinan Bass

Description:
This script scans a target host for common open ports and provides
basic security notes based on the services found.

Important:
Only scan systems you own or have permission to test.
"""

import socket
from datetime import datetime


COMMON_PORTS = {
21: "FTP",
22: "SSH",
23: "Telnet",
25: "SMTP",
53: "DNS",
80: "HTTP",
110: "POP3",
139: "NetBIOS",
143: "IMAP",
443: "HTTPS",
445: "SMB",
3306: "MySQL",
3389: "Remote Desktop Protocol",
8080: "HTTP Alternate"
}


SECURITY_NOTES = {
21: "FTP may send data in clear text. Use SFTP or FTPS when possible.",
22: "SSH is commonly used for remote access. Use strong passwords or key-based authentication.",
23: "Telnet is insecure because it sends data in plain text. It should be disabled.",
25: "SMTP should be protected to prevent spam relay and unauthorized mail use.",
53: "DNS should be monitored because misconfigurations can expose internal information.",
80: "HTTP is not encrypted. Sensitive websites should use HTTPS.",
110: "POP3 may expose email credentials if not secured with encryption.",
139: "NetBIOS can expose file-sharing information and should be restricted.",
143: "IMAP should use encryption to protect email login credentials.",
443: "HTTPS is encrypted, but certificates and web security still need to be checked.",
445: "SMB is commonly targeted by attackers and should not be exposed to the internet.",
3306: "MySQL should not be publicly exposed unless properly secured.",
3389: "Remote Desktop is often targeted by brute-force attacks and should be restricted.",
8080: "Alternate web ports should be reviewed for outdated web applications."
}


def scan_port(target, port):
    """
    Attempts to connect to a target port.
    Returns True if the port is open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            return True
        return False

    except socket.gaierror:
        print("Hostname could not be resolved.")
        return False

    except socket.error:
        print("Could not connect to the target.")
        return False


def create_report(target, open_ports):
    """
    Creates a text report with scan results.
    """
    filename = "scan_report.txt"

    with open(filename, "w") as report:
        report.write("CYB 333 Automated Port and Vulnerability Scanner Report\n")
        report.write("=" * 60 + "\n")
        report.write(f"Target Scanned: {target}\n")
        report.write(f"Scan Time: {datetime.now()}\n")
        report.write("=" * 60 + "\n\n")

        if not open_ports:
            report.write("No open common ports were found during this scan.\n")
        else:
            report.write("Open Ports Found:\n\n")

            for port in open_ports:
                service = COMMON_PORTS.get(port, "Unknown Service")
                note = SECURITY_NOTES.get(port, "Review this service for security risks.")

                report.write(f"Port: {port}\n")
                report.write(f"Service: {service}\n")
                report.write(f"Security Note: {note}\n")
                report.write("-" * 40 + "\n")

    print(f"\nScan report saved as {filename}")


def main():
    print("CYB 333 Automated Port and Vulnerability Scanner")
    print("Only scan systems you own or have permission to test.\n")

    target = input("Enter target IP address or hostname: ").strip()

    if not target:
        print("No target entered. Please run the program again.")
        return

    print(f"\nStarting scan on {target}...")
    print("Scanning common ports...\n")

    open_ports = []

    for port in COMMON_PORTS:
        if scan_port(target, port):
            open_ports.append(port)
            print(f"[OPEN] Port {port}: {COMMON_PORTS[port]}")
        else:
            print(f"[CLOSED] Port {port}: {COMMON_PORTS[port]}")

    print("\nScan complete.")

    if open_ports:
        print("\nPotential Security Findings:")
        for port in open_ports:
            print(f"- Port {port} ({COMMON_PORTS[port]}): {SECURITY_NOTES[port]}")
    else:
        print("No open common ports were detected.")

    create_report(target, open_ports)


if __name__ == "__main__":
    main()
