from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.all import *
import csv
import ctypes, sys
import platform
import os



#check for UAC permissions
def check_uac():
    os_type = platform.system()
    if os_type == 'Windows':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except (PermissionError, AttributeError) as e:
            print("Permission denied. Need to run as admin or unsupported os\n Closing script....")
            sys.exit(1)

    elif os_type == "Linux" or os_type == "Darwin":
        admin = os.getuid()
        if admin == 0:
            print("You are an admin, you are good to continue")
            return True
        else:
            print("You are not an administrator, please be an admin to run")
            sys.exit(1)
    print("Not a valid operating system.")
    sys.exit(1)
# Get a list of available network interface names
interface_names = get_if_list()

# Print the list of interface names
for i, interface in enumerate(interface_names, start=1):
    ip_address = get_if_addr(interface)
    print(i, interface, ip_address)
while True:
    choice = input("Please choose number to decide which interface to sniff on.")
    number_of_items = len(interface_names)
    try:
        choice1 = int(choice)
        if 1 <= choice1 <= number_of_items:
            chosen_interface = interface_names[choice1 - 1]
            print(f"Will scan on {chosen_interface}")
            break
        else:
            print("Number is out of range.")
    except ValueError:
        print("Please type in a number, not anything else.")
        continue

def various_filter(packet):
    packet_parsing_info = {
        "Src MAC": None,
        "Dst MAC": None,
        "Ether Type": None,
        "Src IP": None,
        "Dst IP": None,
        "IP Protocol": None,
        "TCP Source Port": None,
        "TCP Destination Port": None,
        "UDP Source Port": None,
        "UDP Destination Port": None,
        "DNS Query Name": None,
        "DNS Query Type": None,
        "Reply Answer": None,
        "Reply Answer Type": None,
    }
    if packet.haslayer(Ether):
        packet_parsing_info["Src MAC"] = packet[Ether].src
        packet_parsing_info["Dst MAC"] = packet[Ether].dst
        packet_parsing_info["Ether Type"] = packet[Ether].type


        if IP in packet:
            packet_parsing_info["Src IP"] = packet[IP].src
            packet_parsing_info["Dst IP"] = packet[IP].dst
            packet_parsing_info["IP Protocol"] = packet[IP].proto

            if TCP in packet:
                packet_parsing_info["TCP Source Port"] = packet[TCP].sport
                packet_parsing_info["TCP Destination Port"] = packet[TCP].dport


            elif UDP in packet:
                packet_parsing_info["UDP Source Port"] = packet[UDP].sport
                packet_parsing_info["UDP Destination Port"] = packet[UDP].dsport

            if packet.haslayer(DNS):
                if packet[DNS].qr == 0:
                    packet_parsing_info["DNS Query Name"] = packet[DNS].qd.name.decode("utf-8", errors="replace")
                    packet_parsing_info["DNS Query Type"] = packet[DNS].qd.qtype

                elif packet[DNS].qr == 1:
                    if packet[DNS].an:
                        packet_parsing_info["Reply Answer"] = packet[DNS].an.rdata
                        packet_parsing_info["Reply Answer Type"] = packet[DNS].an.type
                    else:
                        packet_parsing_info["Reply Answer"] = "No answer"
                        packet_parsing_info["Reply Answer Type"] = "N/A"
    return packet_parsing_info

def csv_file(packet_data):
    header = ["Src MAC", "Dst MAC", "Ether Type", "Src IP", "Dst IP",
              "IP Protocol", "TCP Source Port", "TCP Destination Port",
              "UDP Source Port", "UDP Destination Port",
              "DNS Query Name", "DNS Query Type", "Reply Answer", "Reply Answer Type"]

    with open("Output File.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()
        writer.writerows(packet_data)

def packet_capture():
    local_list = []
    def wrapper(packet):
        various_packet_info = various_filter(packet)
        local_list.append(various_packet_info)
    try:
        sniff(
            iface = chosen_interface,
            count = 50,
            timeout = 60,
            prn = wrapper,
        )
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
    return local_list
def main():
    check_uac()
    packet_data = packet_capture()
    csv_file(packet_data)

if __name__ == "__main__":
    main()


