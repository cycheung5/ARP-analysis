# ARP-analysis

This program is designed to extract ARP packets from a captured pcap file exchange and then to analyze the ARP packets.  Attached to this program is a captured pcap file used to test this the analysis_pcap_arp.py file. The analysis_pcap_arp.py file performs byte-level manipulation to read each packet from a pcap file and identify it as an ARP packet.  The file also uses byte-level manipulation to read each byte and convert it to the ARP header element: sender MAC address, target MAC address, protocol type, etc.  

# API used

The analysis_pcap_arp.py is written in Python3 and it imports the following external libraries: dpkt, ipaddress, sys. You will need the dpkt library installed to run this program. The dpkt library is from the dpkt API.  This API was used to help read in the given information in the given PCAP file and turn it into a pcap object.  In the program, the IP Addresses from the packet's header information were extracted out into byte form and then converted into int form.  The ipaddress library was used to turn these int form of the IP Address into readable ip address form.  

# How to run
To run the analysis_pcap_arp.py file, open the command prompt.  On the command line, type 'python' followed by a space and then the path name of the directory.
Example: <br />
python analysis_pcap_arp.py  <br />
You will be prompted with the prompt: "Please input pcap file"  <br />
Type in the directory path of the pcap file.  <br />
my_arp.pcap

# Output
When  the program is run, the first output will be the number of ARP messages in the captured pcap file. The next output will be a printout of the header information for all of the ARP messages in the captured pcap file.  Finally, the final output will be the printout for one ARP packet exchange which are the first ARP exchange 
