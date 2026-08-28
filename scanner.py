import sys
import socket
import logging
from scapy.all import sr1, send, IP, TCP, RandShort

# Suppress Scapy's verbose output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def syn_scan(target_ip, port):
    src_port = RandShort()

    # Craft and send SYN packet
    syn_packet = IP(dst=target_ip) / TCP(
        sport=src_port,
        dport=port,
        flags="S"
    )

    response = sr1(syn_packet, timeout=1, verbose=0)

    # No response
    if response is None:
        return "Filtered"

    if response.haslayer(TCP):
        tcp_flags = response.getlayer(TCP).flags

        # SYN + ACK = Open
        if tcp_flags == 0x12:
            # Send RST to close the half-open connection
            rst_packet = IP(dst=target_ip) / TCP(
                sport=src_port,
                dport=port,
                flags="R"
            )
            send(rst_packet, verbose=0)

            return "Open"

        # RST + ACK = Closed
        elif tcp_flags == 0x14:
            return "Closed"

    return "Unknown"


def identify_service(target_ip, port):
    # Try to get the default service name for the port
    try:
        service_name = socket.getservbyport(port, "tcp")
    except OSError:
        service_name = "Unknown"

    banner = ""

    try:
        # Create a socket and connect
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, port))

        # Send a basic HTTP request
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")

        # Receive the banner
        banner = s.recv(1024).decode(
            "utf-8",
            errors="ignore"
        ).strip()

        s.close()

    except Exception:
        pass

    return service_name, banner[:50]


def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Starting scan on target: {target}")

    # Scanning common ports
    ports_to_scan = [
        21, 22, 23, 25, 53, 80,
        110, 135, 139, 443,
        445, 3389, 8080
    ]

    for port in ports_to_scan:
        status = syn_scan(target, port)

        print(f"[+] Port {port}/tcp: {status}")

        if status == "Open":
            service, banner = identify_service(target, port)

            print(f"    -> Service: {service}")

            if banner:
                print(f"    -> Banner: {banner}")

    print("[*] Scan complete.")


if __name__ == "__main__":
    main()