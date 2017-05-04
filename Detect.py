
from scapy.all import *
import outils
import time


serverID=""
macs={}

def detect_arp_poison(subnet,interface):
	
	global macs 
	subnetID , mask = outils.cidr(subnet)
	ip_addrs= outils.get_addresses(subnetID , mask)

	for ip in ip_addrs:
		t1=time.time()
		while True:
			macs={}	
			sniff(iface=interface, filter = "arp", prn=analyse_reply,timeout=10)
			if time.time()-t1>=10:
				break
		
				
				
def analyse_reply(pkt):
	global serverID
	global macs
	attack=True
	if pkt.haslayer(ARP):
		if pkt[ARP].psrc==ip:
			mac=pkt[ARP].hwsrc
			ip=pkt[ARP].psrc
			if len(macs)==0:
				macs[mac]=1
			else:
				for m in macs:
					if m==mac:
						macs[mac]+=1
						break
				else:
					macs.append(mac)
		
		
			for m in macs.keys():
				if macs[m]>=2:
					break
			else :
				attack=False
			if attack or len(macs.keys())>1:	
				print "[!] L'hote %s est une victime potentielle ."
				print "L'adresse mac de l'attaquant est parmi les suivantes :"
				for mac in macs.keys():
					print mac
	
	elif pkt.haslayer(DHCP):
		options=pkt[DHCP].options
		for op in options:
               		if op[0]=="server_id":
                        	serverID=op[1]
                                break
		print "[+] Une offre DHCP recu du serveur d'identifiant : %s "%serverID
		ans=raw_input("Tapper sur  Enter pour continuer la decouverte des offres ou ctlc pour quitter :") 
		
			
	
			
def detect_DHCP_servers(interface):
	
	mac=outils.randomMac()
        xid_disc=random.randint(0xfff00000,0xfffff000)
  	
	DHCPdisc=IP(dst="255.255.255.255", src="0.0.0.0")/UDP(sport=68 , dport=67)/BOOTP(op=1 ,xid=xid_disc,ciaddr="0.0.0.0",yiaddr="0.0.0.0",
 flags=0x8000,chaddr=mac)/DHCP(options=[("message-type","discover"),"end"])
	send(DHCPdisc,loop=0,verbose=0,iface=interface)
	sniff(iface=interface , lfilter = lambda x : x.haslayer(DHCP) and x[BOOTP].xid==xid_disc , prn=analyse_reply)



