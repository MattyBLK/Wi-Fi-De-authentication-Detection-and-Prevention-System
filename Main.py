# Wi-Fi De-authentication Detection and Provention System
# This system will first detect then mitigate deauth attacks by chnaging the HOSTs MAC address.
# This may cause some Network errors in certain systems. Use in a controlled enviroment. 

import subprocess
import re
import random
import time
import logging
import tkinter as tk
from threading import Thread
from scapy.all import sniff, Dot11, Dot11Deauth

#Define a class for sniffing packets with Scapy.
class PacketSniffer:
    def __init__(self, interface):
        self.interface = interface #Network interface to sniff on

    # Method to start for de-authentication packets
    def start_sniffing(self, callback):
        sniff(iface=self.interface, prn=callback, store=False, lfilter=lambda x: x.haslayer(Dot11Deauth))

# Class to detect de-authentication attacks
class DeauthDetector:
    def __init__(self, threshold, time_window, alert_manager, mac_changer, event_logger, thread_manager, target_interface):
        # Initialize with configuration perameters and helper objects
        self.threshold = threshold  # Packet count threshold for attack detection
        self.time_window = time_window  # Not used, but intended for future enhancement
        self.deauth_counts = {}  # Dictionary to keep track of deauth packets
        self.alert_manager = alert_manager  # Handles alert pop-ups
        self.mac_changer = mac_changer  # Manages MAC address changes
        self.event_logger = event_logger  # Logs events
        self.thread_manager = thread_manager  # Manages threading
        self.target_interface = target_interface  # Network interface being protected
        # Fetch and print the current MAC address of the target interface
        self.current_target_mac = self.mac_changer.get_current_mac(self.target_interface)
        print(f"Current MAC address of {self.target_interface}: {self.current_target_mac}")

    # Method to handle each sniffed packet
    def detect_deauth(self, packet):
        # Check if the packet is relevant to the current target MAC
        if packet.addr1.lower() == self.current_target_mac.lower() or packet.addr2.lower() == self.current_target_mac.lower():
            attacker_mac = packet.addr2 # Assume the second address is the attacker
            target_mac = packet.addr1  # Corrected from 'packet.addr'
            current_time = time.time()  # Get the current time for timestamping
            # Update or initialize the deauth packet count for this attacker
            if attacker_mac in self.deauth_counts: 
                count, first_time, last_time, _ = self.deauth_counts[attacker_mac]
                elapsed_time_since_last_packet = current_time - last_time  # Time since last packet from this MAC
                self.deauth_counts[attacker_mac] = (count + 1, first_time, current_time, elapsed_time_since_last_packet)
            else:
                # Store first_time as current_time when first packet is detected
                self.deauth_counts[attacker_mac] = (1, current_time, current_time, 0)
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} - Deauth packet detected directed at our MAC")
            self.check_and_react(attacker_mac)

    # Check if an attack is detected and react by changing the MAC address
    def check_and_react(self, attacker_mac):
        count, first_time, last_time, elapsed_time_since_last_packet = self.deauth_counts[attacker_mac]
        if count >= self.threshold:
            total_elapsed_time = last_time - first_time  # Calculate total elapsed time from first to threshold packet
            log_message = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} - De-authentication attack detected from MAC: {attacker_mac}. Count: {count}. Total elapsed time: {total_elapsed_time:.2f} seconds."
            self.event_logger.log_event(log_message)
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} - Initiating MAC address change...")
            self.alert_manager.display_mac_change_alert(count, total_elapsed_time, attacker_mac)  # Updated to include total_elapsed_time
            new_mac = self.mac_changer.change_mac_address(self.target_interface)
            self.current_target_mac = new_mac
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} - MAC address changed to {new_mac}")
            self.deauth_counts.pop(attacker_mac, None) 
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} - Initiating MAC address change...")
            new_mac = self.mac_changer.change_mac_address(self.target_interface)
            self.current_target_mac = self.mac_changer.get_current_mac(self.target_interface)  # Fetch the MAC again to verify
            print(f"Verified current MAC address: {self.current_target_mac}")  # Verification step


    # Method to start detection in a separate thread
    def run_detection(self, packet_sniffer):
        self.thread_manager.create_thread(target=lambda: packet_sniffer.start_sniffing(self.detect_deauth))

# Class to manage changing the MAC address
class MACChanger:
    def __init__(self, interface):
        self.interface = interface  # Target network interface

    # Change the MAC address of the target interface
    def change_mac_address(self, interface):
        # Generate a random MAC address with a specific prefix
        new_mac = "00:11:22:33:44:" + ":".join(["%02x" % random.randint(0, 255) for _ in range(2)])
        # Commands to change the MAC address
        subprocess.call(["sudo", "ifconfig", interface, "down"])
        subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["sudo", "ifconfig", interface, "up"])
        return new_mac

    # Retrieve the current MAC address of the target interface
    def get_current_mac(self, interface):
        result = subprocess.check_output(["ifconfig", interface]).decode('utf-8')
        mac_address_search_result = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', result)
        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            logging.error("Could not read current MAC address.")
            return None

# Class to manage alert pop-ups using tkinter
class AlertManager:
    def display_mac_change_alert(self, count, total_elapsed_time, attacker_mac):
        def run_gui():
            root = tk.Tk()
            root.title("Security Alert")
            root.geometry("600x400")  # Width x Height

            # Display message about the detected attack
            message = (f"Potential attack detected. Suspicious activity\n"
                       f"Initiating MAC address change...\n\n"
                       f"Reason for initiation:\n"
                       f"Number of packets detected: {count} within {total_elapsed_time:.2f} seconds from {attacker_mac}.")

            label = tk.Label(root, text=message, font=("Arial", 12), justify=tk.LEFT)
            label.pack(padx=20, pady=20)

            button = tk.Button(root, text="Acknowledge", command=root.destroy)
            button.pack(pady=20)

            root.mainloop()

        # Run the GUI in a separate thread to prevent blocking
        Thread(target=run_gui).start()

class ThreadManager:
    def create_thread(self, target):
        thread = Thread(target=target)
        thread.daemon = True
        thread.start()

class EventLogger:
    def log_event(self, message):
        logging.info(message)

if __name__ == "__main__":
    logging.basicConfig(filename='deauth_detector.log', level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    print("Starting the system...")

    # Configuration parameters
    interface = "wlan0mon"  # Your WLAN interface for sniffing
    target_interface = "wlp0s20f3"  # Interface whose MAC will be changed upon attack detection
    threshold = 5 # Number of deauth packets to trigger alert and MAC address change
    time_window = 5  # Time window in seconds to consider for deauth packet threshold

    # Instantiate components
    alert_manager = AlertManager()
    mac_changer = MACChanger(target_interface)
    event_logger = EventLogger()
    thread_manager = ThreadManager()
    sniffer = PacketSniffer(interface)
    detector = DeauthDetector(threshold, time_window, alert_manager, mac_changer, event_logger, thread_manager, target_interface)

    detector.run_detection(sniffer)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping the system...")
