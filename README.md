# User Manual 

## Installation and Setup
 
### System Requirements
Ensure that your Linux system has Python3 installed, and that the user has the necessary permissions to execute system commands.

### Installing Dependencies
The following are the instruction to make sure that the following dependencies are installed correctly. 
1.	Open a terminal.
2.	Install ‘scapy’ by running: ‘pip install scapy’.
3.	If the pip command doesn’t work, make sure that it is installed using ‘sudo apt install Python3-pip’ 

### Download the System
The next step is to download the Wi-Fi De-authentication, Detection and Prevention System.

### Ruining the system 
Open a terminal in the directory where the script is located.
Run the script by executing: ‘sudo python ‘WDDPS.py’.

## Configuring Network Interfaces

### Identifying Network interfaces
Next determine the network interface names by using the ‘iwconfig’ command. For this system to work there needs to be a network interface card (NIC) that supports monitor mode.

### Monitor Mode
After identifying the NICs and what one is the one that supports monitor mode. Perform the following commands:
•	sudo Ifconfig [Interface] down
•	sudo iwconfig [interface] mode monitor
•	sudo ifconfig [interfcae] up

### Editing Script
Next edit the script and if necessary, edit the ‘interface’ and the ‘target_interface’ variables in the script to match your systems network interface names.
Note: After turning a NIC into monitor mode it is likely that the interface name has changed to check this type the iwconfig command again. 

## Detecting Deauth Attacks
The system automatically starts detecting de-authentication attacks upon running. Detected attacks will be logged, and if the number of de-auth packets from a single source exceeds the threshold, the system will respond accordingly.

## Responding to attacks

### Automatic MAC address Change
Upon detecting an attack surpassing the defined threshold, the system automatically changes the MAC address of the protected interface. 

### Alert Notifications
A graphical alert will be displayed, informing you about the attack detection and MAC address change. 

## Viewing Logs
The system logs all detected de-auth attacks and responses in a log file named ‘deauth_detector.log’. Review this file for detailed information about system activity and detected threats.

## Troubleshooting and Support

### Common Issues
•	Permission Denied: Ensure you are running the script with sufficient permissions (sudo on Linux/macOS).
•	Network Interface Not Found: Verify the interface names in the script match those on your system.
•	Dependency Errors: Ensure all required Python packages are installed (scapy, tkinter).

### Getting Help
•	For further assistance, refer to the scapy documentation for troubleshooting packet sniffing issues.
•	Check Python and tkinter documentation for issues related to GUI alerts.

### Additional Features and Customization
Customize the detection threshold and time window and the network interfaces directly in the script to tailor the system's sensitivity and targeted interfaces to your specific needs.
