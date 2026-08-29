import sys
import socket
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    parser = argparse.ArgumentParser(
        description="Python TCP SYN Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address"
    )

    parser.add_argument(
        "--ports",
        help="Comma-separated list of ports (example: 80,443,8080)"
    )

    parser.add_argument(
        "--start-port",
        type=int,
        help="Starting port for a port range"
    )

    parser.add_argument(
        "--end-port",
        type=int,
        help="Ending port for a port range"
    )

    args = parser.parse_args()

    target = args.target

    print(f"[*] Starting scan on target: {target}")

    # Determine which ports to scan
    if args.ports:
        try:
            ports_to_scan = [
                int(port.strip())
                for port in args.ports.split(",")
            ]
        except ValueError:
            print("[!] Invalid port list.")
            sys.exit(1)

    elif args.start_port is not None and args.end_port is not None:
        if not (1 <= args.start_port <= args.end_port <= 65535):
            print("[!] Invalid port range. Use ports 1-65535.")
            sys.exit(1)

        ports_to_scan = range(
            args.start_port,
            args.end_port + 1
        )

    else:
        ports_to_scan = [
            21, 22, 23, 25, 53, 80,
            110, 135, 139, 443,
            445, 3389, 8080
        ]

    print()
    print("[*] Scanning ports concurrently...")

    results = []

    with ThreadPoolExecutor(max_workers=20) as executor:

        future_to_port = {
            executor.submit(syn_scan, target, port): port
            for port in ports_to_scan
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]

            try:
                status = future.result()
            except Exception as e:
                status = "Error"
                print(f"[!] Port {port}: {e}")

            service = ""
            banner = ""

            if status == "Open":
                service, banner = identify_service(target, port)

            results.append({
                "port": port,
                "state": status,
                "service": service,
                "banner": banner
            })

    # Sort results by port number
    results.sort(key=lambda x: x["port"])

    print()
    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE'}")
    print("-" * 40)

    for result in results:
        print(
            f"{result['port']:<10}"
            f"{result['state']:<12}"
            f"{result['service']}"
        )

        if result["banner"]:
            print(f"    Banner: {result['banner']}")

    print()
    print("[*] Scan complete.")


if __name__ == "__main__":
    main()