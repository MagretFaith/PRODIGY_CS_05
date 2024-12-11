Packet Sniffer 

This is a Python-based packet sniffer with a graphical user interface (GUI) built using tkinter. The tool captures network packets, displays their details in real time, and provides additional functionalities like saving captured packets and scanning for devices on the network.

Features

Packet Capture: Capture network packets in real-time and view details like source IP, destination IP, protocol, and ports.

Protocol Filtering: Apply filters to capture specific types of traffic (e.g., TCP, UDP).

Network Device Scanning: Discover devices on your local network using ARP requests.

Save Packets: Save captured packet details to a file for later analysis.

User-Friendly Interface: Intuitive GUI with buttons and input fields for ease of use.

Prerequisites

Python 3.6 or higher.

Required Python libraries:

scapy

tkinter (comes pre-installed with Python)

psutil

You can install the required dependencies using pip:

pip install scapy psutil
