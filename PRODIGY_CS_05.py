import scapy.all as scapy
from datetime import datetime
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import psutil

# Define a global variable to control sniffing
sniffing = False
saved_packets = []  # Store captured packets for saving later


def list_interfaces():
    """
    List available network interfaces for auto-suggestions in a user-friendly format.
    """
    try:
        interfaces = psutil.net_if_addrs()  # Get network interfaces using psutil
        # Return only interface names
        interface_names = [interface for interface in interfaces]
        return interface_names
    except Exception as e:
        messagebox.showerror("Error", f"Unable to list interfaces: {e}")
        return []


def packet_callback(packet):
    """
    Callback function to process each captured packet and update the GUI.
    """
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, "Other")

        message = (
            f"Time: {datetime.now()}\n"
            f"Source IP: {source_ip}\n"
            f"Destination IP: {destination_ip}\n"
            f"Protocol: {protocol_name}\n"
        )

        if packet.haslayer(scapy.TCP):
            message += (
                f"TCP Source Port: {packet[scapy.TCP].sport}\n"
                f"TCP Destination Port: {packet[scapy.TCP].dport}\n"
            )
        elif packet.haslayer(scapy.UDP):
            message += (
                f"UDP Source Port: {packet[scapy.UDP].sport}\n"
                f"UDP Destination Port: {packet[scapy.UDP].dport}\n"
            )

        if packet.haslayer(scapy.ARP):
            message += f"ARP Request: {packet[scapy.ARP].psrc} -> {packet[scapy.ARP].pdst}\n"

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            message += f"Raw Payload: {payload}\n"

        message += "=" * 40 + "\n"

        # Update the GUI text box with the captured packet details
        packet_display.insert(tk.END, message)
        packet_display.see(tk.END)

        # Add the packet to the saved_packets list
        saved_packets.append(message)


def start_sniffing(interface, filter_str):
    """
    Start packet sniffing on a separate thread.
    """
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=0, filter=filter_str, stop_filter=lambda x: not sniffing)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start sniffing: {e}")


def start_sniffer():
    """
    Start the sniffer when the Start button is clicked.
    """
    global sniffing
    if sniffing:
        messagebox.showwarning("Warning", "Sniffer is already running!")
        return

    interface = interface_combobox.get()
    filter_str = filter_entry.get()
    if not interface:
        messagebox.showerror("Error", "Please specify a network interface!")
        return

    sniffing = True
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface, filter_str))
    sniffing_thread.daemon = True
    sniffing_thread.start()
    status_label.config(text="Status: Sniffing started", fg="green")


def stop_sniffer():
    """
    Stop the sniffer when the Stop button is clicked.
    """
    global sniffing
    sniffing = False
    status_label.config(text="Status: Sniffing stopped", fg="red")


def save_packets():
    """
    Save captured packets to a file.
    """
    if not saved_packets:
        messagebox.showwarning("Warning", "No packets to save!")
        return

    save_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if not save_file:
        return

    try:
        with open(save_file, 'w') as f:
            for packet in saved_packets:
                f.write(packet + "\n")
        messagebox.showinfo("Success", f"Packets saved to {save_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save packets: {e}")


def display_network_devices():
    """
    Send ARP request to display devices in the network.
    """
    ip_range = "192.168.1.0/24"  # Adjust as necessary

    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        devices_text.delete(1.0, tk.END)

        if not answered_list:
            devices_text.insert(tk.END, "No devices found on the network.\n")
            return

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            devices_text.insert(tk.END, f"IP: {ip}   MAC: {mac}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to display network devices: {e}")


# Create the main GUI window
root = tk.Tk()
root.title("Packet Sniffer")

# Interface input with auto-suggestion
tk.Label(root, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
interface_combobox = ttk.Combobox(root, values=list_interfaces(), width=20)
interface_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

# Filter input
tk.Label(root, text="Filter (optional):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
filter_entry = tk.Entry(root, width=20)
filter_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

# Buttons to start, stop sniffing, save packets, and display network devices
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffer, bg="green", fg="white")
start_button.grid(row=2, column=0, padx=5, pady=10)
stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffer, bg="red", fg="white")
stop_button.grid(row=2, column=1, padx=5, pady=10)

save_button = tk.Button(root, text="Save Packets", command=save_packets, bg="blue", fg="white")
save_button.grid(row=3, column=0, padx=5, pady=10)

devices_button = tk.Button(root, text="Show Network Devices", command=display_network_devices, bg="orange", fg="white")
devices_button.grid(row=3, column=1, padx=5, pady=10)

# Status label
status_label = tk.Label(root, text="Status: Stopped", fg="red")
status_label.grid(row=4, column=0, columnspan=2, pady=5)

# Packet display area
packet_display = scrolledtext.ScrolledText(root, width=80, height=20)
packet_display.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# Devices display area
tk.Label(root, text="Network Devices:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
devices_text = scrolledtext.ScrolledText(root, width=80, height=10)
devices_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

# Run the GUI
root.mainloop()


