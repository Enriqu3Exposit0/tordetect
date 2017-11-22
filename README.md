# Tordetect

Detection of TOR Network connections through different methods analyzing a PCAP capture file.

- Connection to exit nodes
- Detection of TOR standard ports
- Identification of non-standard digital certificates

REQUIREMENTS:

- Needs a file nodes.txt with the list of TOR exit nodes. Download an updated list from https://www.dan.me.uk/torlist/
- Needs as an argument the PCAP file to analyze.
- Tshark has to be installed in the system.

USAGE: 

user@linux:~/# python tordetect.py file.pcap'
