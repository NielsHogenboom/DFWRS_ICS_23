import json
from scapy.layers.inet import TCP, IP
from scapy.all import *
from datetime import datetime

def get_function_code_meaning(func_code):
    function_code_dict = {
        "01": "INIT_COMM (Initialize a UMAS communication)",
        "02": "READ ID (Request a PLC ID)",
        "03": "READ_PROJECT_INFO (Read Project Information)",
        "04": "READ_PLC_INFO (Get internal PLC Info)",
        "06": "READ_CARD_INFO (Get internal PLC SD-Card Info)",
        "0A": "REPEAT (Sends back data sent to the PLC (used for synchronization)",
        "10": "TAKE_PLC_RESERVATION (Assign an 'owner' to the PLC)",
        "11": "RELEASE_PLC_RESERVATION (Release the reservation of a PLC)",
        "12": "KEEP_ALIVE (Keep alive message)",
        "20": "READ_MEMORY_BLOCK (Read a memory block of the PLC)",
        "22": "READ_VARIABLES (Read System bits, System Words and Strategy variables)",
        "23": "WRITE_VARIABLES (Write System bits, System Words and Strategy variables)",
        "24": "READ_COILS_REGISTER (Read coils and holding registers from PLC)",
        "25": "WRITE_COILS_REGISTER (Write coils and holding registers into PLC)",
        "26": "PRESENT_SINGLE_REGISTER (Write single variable to a register",
        "28": "MASK_WRITE_REGISTER (Write single bits to a register without changing the other bits",
        "29": "WRITE_AND_READ_REGISTER (Write and read multiple registers)",
        "30": "INITIALIZE_UPLOAD (Initialize Strategy upload (copy from engineering PC to PLC))",
        "31": "UPLOAD_BLOCK (Upload (copy from engineering PC to PLC) a strategy block to the PLC)",
        "32": "END_STRATEGY_UPLOAD (Finish strategy Upload (copy from engineering PC to PLC))",
        "33": "INITIALIZE_UPLOAD (Initialize Strategy download (copy from PLC to engineering PC))",
        "34": "DOWNLOAD_BLOCK (Download (copy from PLC to engineering PC) a strategy block)",
        "35": "END_STRATEGY_DOWNLOAD (Finish strategy Download (copy from PLC to engineering PC))",
        "36": "READ_DEVICE_IDENTIFICATION (Find information about the over the PLC maker)",
        "39": "READ_ETH_MASTER_DATA (Read Ethernet Master Data)",
        "40": "START_PLC (Starts the PLC)",
        "41": "STOP_PLC (Stops the PLC)",
        "42": "READ_FIFO_QUEUE (Read the fifo queue of the PLC)",
        "50": "MONITOR_PLC (Monitors variables, Systems bits and words)",
        "58": "CHECK_PLC (Check PLC Connection status)",
        "6d": "User defined function",
        "70": "READ_IO_OBJECT (Read IO Object)",
        "71": "WRITE_IO_OBJECT (WriteIO Object)",
        "73": "GET_STATUS_MODULE (Get Status Module)",
        "74": "User defined function",
        "80": "User defined function",
        "81": "User defined function",
        "fe": "OK",
        "fd": "ERROR"
    }

    return function_code_dict.get(func_code, "Unknown Function Code")

def process_packet(packet):
    if IP in packet and TCP in packet and Raw in packet:
        if packet[TCP].dport == 502 or packet[TCP].sport == 502:
            packet_data = {}

            # Extracting source IP and destination IP
            packet_data["source_ip"] = packet[IP].src
            packet_data["destination_ip"] = packet[IP].dst

            # Transaction identifier
            transaction_id_hex = packet[Raw].load.hex()[:4]
            packet_data["transaction_id"] = int(transaction_id_hex, 16)

            # Packet type (Query or Response)
            packet_data["packet_type"] = "Query" if packet[TCP].dport == 502 else "Response"

            # Timestamp extraction
            timestamp = packet.time
            packet_data["timestamp"] = datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S UTC')

            # Function code
            hex_data = packet[Raw].load.hex()[14:]
            packet_data["network_code"] = hex_data[:2]

            # Connection ID
            packet_data["connection_id"] = packet[Raw].load.hex()[16:18]

            # Function code meaning
            function_code = packet[Raw].load.hex()[18:20]
            packet_data["function_code"] = function_code
            packet_data["function_meaning"] = get_function_code_meaning(function_code)

            # Package data
            packet_data["modbus_data"] = packet[Raw].load.hex()[20:]

            modbus_data.append(packet_data)

            print("---------------------------------------------")
            print(json.dumps(packet_data, indent=4))
            print("---------------------------------------------")

# PCAP bestandsnaam
pcap_file = 'Experiment push volledig nieuwe control logic.pcapng'
modbus_data = []

# Lees de PCAP file uit en sniff het packetje
sniff(offline=pcap_file, prn=process_packet)

# Sla de gegevens op in een JSON-bestand
output_file = 'packet_data.json'
with open(output_file, 'w') as json_file:
    json.dump(modbus_data, json_file, indent=4)

print(f"Packet data is opgeslagen in {output_file}")
