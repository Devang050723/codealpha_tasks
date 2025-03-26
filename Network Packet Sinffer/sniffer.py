import tkinter as tk
from tkinter import ttk, scrolledtext
import pyshark
import threading
import asyncio

class PacketSnifferApp:
    def __init__(self, root):
        """Initialize the GUI application and set up variables."""
        self.root = root
        self.root.title("Advanced Network Packet Sniffer")
        self.root.geometry("1200x600")

        self.is_sniffing = False
        self.capture_thread = None

        self.setup_ui()

    def setup_ui(self):
        """Create and arrange UI components."""
        # Start Capture Button
        self.start_button = tk.Button(self.root, text="Start Capture", command=self.start_sniffing, bg="green", fg="white")
        self.start_button.pack(pady=5, side=tk.LEFT, padx=10)

        # Stop Capture Button
        self.stop_button = tk.Button(self.root, text="Stop Capture", command=self.stop_sniffing, bg="red", fg="white", state=tk.DISABLED)
        self.stop_button.pack(pady=5, side=tk.LEFT, padx=10)

        # Define Table Columns
        columns = ("Time", "Source IP", "Destination IP", "Protocol", "Length", "Src MAC", "Dst MAC", "Src Port", "Dst Port")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        # Set up Table Headers
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.show_packet_details)

        # Scrolled Text Box for Packet Details
        self.packet_details = scrolledtext.ScrolledText(self.root, height=15)
        self.packet_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def start_sniffing(self):
        """Start packet capturing in a separate thread."""
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.capture_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.capture_thread.start()

    def stop_sniffing(self):
        """Stop packet capturing."""
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        """Capture packets in real-time using PyShark."""
        asyncio.set_event_loop(asyncio.new_event_loop())  # Fix asyncio issue
        capture = pyshark.LiveCapture(interface="Wi-Fi")  # Change interface if needed
        for packet in capture.sniff_continuously():
            if not self.is_sniffing:
                break
            self.root.after(0, self.add_packet_to_table, packet)

    def add_packet_to_table(self, packet):
        """Extract and display relevant packet details in the table."""
        try:
            time = packet.sniff_time
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            protocol = packet.highest_layer
            length = packet.length
            src_mac = packet.eth.src if hasattr(packet, 'eth') else "N/A"
            dst_mac = packet.eth.dst if hasattr(packet, 'eth') else "N/A"
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else "N/A"
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else "N/A"

            # Insert packet details into the table
            self.tree.insert("", tk.END, values=(time, src_ip, dst_ip, protocol, length, src_mac, dst_mac, src_port, dst_port))
        except Exception as e:
            print(f"Error: {e}")

    def show_packet_details(self, event):
        """Display detailed information about a selected packet."""
        selected_item = self.tree.selection()[0]
        packet_info = self.tree.item(selected_item, "values")

        detailed_info = f"📌 **Packet Details:**\n"
        detailed_info += f"Time: {packet_info[0]}\nSource IP: {packet_info[1]}\nDestination IP: {packet_info[2]}\n"
        detailed_info += f"Protocol: {packet_info[3]}\nLength: {packet_info[4]}\nSource MAC: {packet_info[5]}\n"
        detailed_info += f"Destination MAC: {packet_info[6]}\nSource Port: {packet_info[7]}\nDestination Port: {packet_info[8]}\n"

        # Extract HTTP details
        try:
            capture = pyshark.LiveCapture(interface="Wi-Fi")
            for packet in capture.sniff_continuously(packet_count=1):
                if "HTTP" in packet:
                    user_agent = packet.http.get("User-Agent", "N/A")
                    http_method = packet.http.get("Request Method", "N/A")
                    timestamp = packet.sniff_time
                    status_code = packet.http.get("Response Code", "N/A")
                    data = packet.http.get("Data", "N/A")
                    
                    detailed_info += f"\n📌 **HTTP Details:**\nUser-Agent: {user_agent}\nMethod: {http_method}\nTimestamp: {timestamp}\n"
                    detailed_info += f"Status Code: {status_code}\nData: {data}\n"
                    break
        except Exception as e:
            detailed_info += f"\n⚠ Error Extracting HTTP Data: {e}\n"

        # Extract DNS Queries
        try:
            if "DNS" in packet:
                dns_query = packet.dns.qry_name if hasattr(packet.dns, "qry_name") else "N/A"
                detailed_info += f"\n📌 **DNS Query:** {dns_query}\n"
        except Exception as e:
            detailed_info += f"\n⚠ Error Extracting DNS Data: {e}\n"

        # Show raw packet data in Hex & ASCII
        raw_data = f"\n📌 **Raw Packet Data (Hex & ASCII View):**\n"
        try:
            raw_data += packet.show()  # Display raw data in hex
        except Exception as e:
            raw_data += f"⚠ Error: {e}\n"

        self.packet_details.delete("1.0", tk.END)
        self.packet_details.insert(tk.END, detailed_info + raw_data)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
