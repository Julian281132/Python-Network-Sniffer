# Python-Network-Sniffer
This is a simple network sniffer that captures data packets and saves the results in a CSV file. This sniffer is cross-platform and collects key information such as MAC addresses, IP addresses, TCP/UDP ports, and more. 


## Features
- Multiplatform support, checking for admin permissions on Windows, Linux, and macOS to ensure proper access for packet sniffing. 
- Extracts detialed information from packets such as
-   Ethernet frame details (Source MAC, Destination MAC, EtherType
-   IP layer data (Source IP, Destination IP, Protocol)
-   Transport layer ports (TCP/UDP source and destination ports)
-   DNS queries and responses, including query names, query types, answers, and answer types
- Automatically saves the parsed packet data to a well-structured CSV file for easy viewing and further analysis.
- Handles user interrupts (Ctrl+C) cleanly, preventing abrupt termination.

## Requirements
- Python 3.6
- Scapy (Handles packet capturing and parsing)
- Windows / Linux OS
- Admin/root permissions (if wanting to use the network sniffer itself)

## Disclaimer
This network sniffer is intended for educational and authorized use only. Unauthorized capturing or monitoring of network traffic without proper consent may violate privacy laws and regulations in your jurisdiction.
