#!/usr/bin/python

# 
# Detection of TOR Network connections through different methods in a PCAP capture file.
#
# 1- Connection to exit nodes
# 2- Detection of TOR standard ports
# 3- Identification of non-standard digital certificates
#
# Enrique Exposito 
# https://twitter.com/Enriqu3Exposit0
# https://github.com/Enriqu3Exposit0
#


import re
import sys
import os

print ' #########################################################'
print ' #               TOR CONNECTION DETECTION                #'
print ' #                                                       #'
print ' #########################################################'
print 
print ' ---------------------------------------------------------'
print '- REQUIREMENTS:'
print '- Needs a file nodes.txt with the list of TOR exit nodes'
print '- Download updated list from https://www.dan.me.uk/torlist/'
print '- We must pass as an argument the PCAP file to analyze'
print '- Tshark has to be installed in the system'
print ' ---------------------------------------------------------'
print ' usage: user@linux:~/# python tordetect.py file.pcap'

pcapfile = sys.argv[1]
nodefile = 'nodes.txt'
torports = ["9001","9002","9030","9031","9040","9050","9051","9150"]

flpt = open(nodefile,'r')

print 
print ' 1- Detecting TOR nodes'
print 

cmd= 'tshark -2 -r ' + pcapfile + ' -T fields -e ip.dst | sort -u'
ipdst = os.popen(cmd).readlines()

cmd= 'tshark -2 -r ' + pcapfile + ' -T fields -e ip.src | sort -u'
ipsrc = os.popen(cmd).readlines()

ips = dict([(a,1) for a in ipdst+ipsrc]).keys()

nodosidentificados = []
for lnpt in flpt:
    if lnpt in ips:
	print ' TOR node detected in the following IP: ' + lnpt.rstrip('\n')
        nodosidentificados.append(lnpt)

flpt.close

print 
print ' 2- Detecting TOR ports'
print 

cmd= 'tshark -2 -r ' + pcapfile + ' -T fields -e tcp.port | sort -u'
tcpports = os.popen(cmd).readlines()

for lnpt in tcpports:
	for port in torports:
		if re.match(port, lnpt.rstrip('\n')):
			print ' Detecting standard TOR port (dst,src): ' + lnpt.rstrip('\n')

print 
print ' 3- Detecting TOR digital certificates'
print 

cmd= 'tshark -2 -r ' + pcapfile + ' -R "ssl.handshake.certificates" -T fields -e x509sat.printableString -e ip.src -e ip.dst'
certificados = os.popen(cmd).readlines()

for lnpt in certificados:
	emisor = re.search(r'www.\w+.com', lnpt.rstrip('\n'))
	objeto = re.search(r'www.\w+.net', lnpt.rstrip('\n'))
	if emisor and objeto:
		print ' TOR certificate detected (issuer,subject src dst): ' + lnpt.rstrip('\n')

print 
print '------------ End of execution -----------'
exit

