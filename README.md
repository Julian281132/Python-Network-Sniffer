# Python-Network-Sniffer
This is a simple network sniffer that captures data packets and saves the results in a CSV file. This sniffer is cross-platform and collects key information such as MAC addresses, IP addresses, TCP/UDP ports, and more. 


#Features
Multi-Platform Support
Checks for administrator/root permissions on Windows, Linux, and macOS to ensure proper access for packet sniffing.

User-Friendly Interface Selection
Lists all available network interfaces with IP addresses and allows the user to select which interface to sniff on.

Comprehensive Packet Parsing
Extracts detailed information from captured packets, including:

Ethernet frame details (Source MAC, Destination MAC, EtherType)

IP layer data (Source IP, Destination IP, Protocol)

Transport layer ports (TCP/UDP source and destination ports)

DNS queries and responses, including query names, query types, answers, and answer types

Filtered Data Collection
Filters and organizes relevant packet data for analysis instead of capturing raw packet dumps.

CSV Export
Automatically saves the parsed packet data to a well-structured CSV file for easy viewing and further analysis.

Packet Capture Controls
Supports a fixed packet count and timeout to manage the duration and volume of packet capture.

Graceful Shutdown
Handles user interrupts (Ctrl+C) cleanly, preventing abrupt termination.
