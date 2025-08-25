# Python-Network-Sniffer
This is a simple network sniffer that captures data packets and saves the results in a CSV file. This sniffer is cross-platform and collects key information such as MAC addresses, IP addresses, TCP/UDP ports, and more. 


Features
Input via IP address or domain name
Scan multiple ports and port ranges (e.g., 80,443,1000-1010)
Uses threading for faster scanning
Validates inputs and handles common errors
Planning to input feature where data is saved to a csv file for later review

Graceful Shutdown
Handles user interrupts (Ctrl+C) cleanly, preventing abrupt termination.
