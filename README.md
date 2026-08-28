# Python Port Scanner

A Python-based TCP SYN port scanner built using Scapy and Python sockets.

## Features

- TCP SYN port scanning
- Detects open, closed, and filtered ports
- Basic service identification
- Basic banner grabbing
- Scans commonly used TCP ports
- Command-line target input

## Technologies

- Python
- Scapy
- TCP/IP
- Socket Programming

## Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL

Install the required dependency:

pip install -r requirements.txt
Usage
python scanner.py 127.0.0.1
Example Output
[*] Starting scan on target: 127.0.0.1

[+] Port 135/tcp: Open
    -> Service: epmap

[+] Port 445/tcp: Open
    -> Service: microsoft-ds

[*] Scan complete.
Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Only scan systems that you own or have explicit permission to test.