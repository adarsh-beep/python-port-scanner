# Python TCP SYN Port Scanner

A Python-based TCP SYN port scanner built with Scapy and Python sockets.

The scanner identifies TCP ports as open, closed, or filtered and provides basic service identification and banner information.

## Features

- TCP SYN port scanning using Scapy
- Open, closed, and filtered port detection
- Concurrent port scanning
- Custom port lists
- Custom port ranges
- Basic TCP service identification
- Basic banner grabbing
- JSON scan report export
- Input validation
- Command-line interface

## Technologies

- Python
- Scapy
- TCP/IP
- Socket Programming
- ThreadPoolExecutor
- JSON

## Installation

Clone the repository:

```bash
git clone https://github.com/adarsh-beep/python-port-scanner.git

Install the required dependency:

pip install -r requirements.txt
Usage
Default Scan
python scanner.py 127.0.0.1
Scan Specific Ports
python scanner.py 127.0.0.1 --ports 80,135,445
Scan a Port Range
python scanner.py 127.0.0.1 --start-port 1 --end-port 1000
Save Results as JSON
python scanner.py 127.0.0.1 --ports 80,135,445 --output scan.json
Example Output
[*] Starting scan on target: 127.0.0.1
[*] Scanning ports concurrently...

PORT      STATE       SERVICE
----------------------------------------
80        Open        http
135       Open        epmap
445       Open        microsoft-ds

[*] Results saved to: scan.json
[*] Scan complete.
How It Works

The scanner sends TCP SYN packets to the specified ports.

SYN-ACK response → Port is considered open
RST-ACK response → Port is considered closed
No response → Port is considered filtered

Open ports are then tested using a TCP socket for basic service identification and banner information.

Limitations
Service detection is basic and may not accurately identify every service.
Banner information depends on whether the target service responds.
A timeout cannot always distinguish between filtering and packet loss.
This tool is intended for TCP scanning and does not perform UDP scanning.
Disclaimer

This project is intended for educational purposes and authorized security testing only.

Only scan systems that you own or have explicit permission to test.