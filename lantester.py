#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys, signal, getopt, Queue, socket
import outils
from scapy.all import *
conf.verb=0

interface=None
scanType=None
protocol=None
flags=None
target_ip=None
port_range=None
sniff=False
reverse=False
detection=""

def usage():
        print "LANTESTER"
        print "Usage: lantester.py [-rs] [-p <protocol>] [-f <flags>] [-d <scan_type>] [-t <targetIP>]"
        print """
                -s --sniff                            -Sniffer la communication tcp d'une cible .
		-d --detect                           -Detecter une attaque arp poisoning ou un serveur DHCP malveillant.
                -S --scan=scanType                    -Specifier le type de scan : tcp , udp , icmp-echo.
                -P --proto=protocol                   -Specifier le protocol a tester: dhcp , dns, arp.  
		-f --flags=flags                      -Specifier le type de scan si le scan est sur TCP: SYN, FIN, ACK, NULL, XMAS.
		-t --target=target_ip                 -Specifier une cible pour le scan.
                -p --port=port_range                  -Specifier une plage de ports a scanner.
		-r --reverse                          -Lancer un paylaod reverseShell.
		-i --interface                        -Specifier l'interface pour la detection 
		-h --help                             -Afficher ce menu d'usage .
		Examples :
			    python lantester.py -s -p tcp -P 80 192.168.1.100
                    	    python lantester.py -d tcp -f SYN 192.168.1.10
			    python lantester.py -d dhcpserver -i eth0
			    python lantester.py -d arppoison - i wlan0 -t 192.168.1.0/24
			    python lantester.py -P dhcp 
			    python lantester.py -s -i eth0
			    python lantester.py -d udp -p 1,108 192.168.1.10  
			    python lantester.py -d tcp -p 80 -f FIN 192.168.1.10/24
			    python lantester.py -d tcp -p 23 -f SYN serv.domaine.com
                """

def main():

	global interface , sniff , protocol , flags, target_ip, port_range, reverse, scanType , detection

	if len(sys.argv[1:]):
		try:
			opts, args=getopt.getopt(sys.argv[1:],"sS:P:f:t:p:rd:h:",["sniff","scan=","proto=","flags=","target=","port=","reverse","detect=","help"])
		except :
			usage()
			sys.exit()	
	try :	
		
		for o,a in opts:
			if o in ("-h","--help"):
				usage()
				sys.exit()
			elif o in ("-s","--sniff"):
				sniff=True
			elif o in ("-S","--scan"):
				scanType=a
			elif o in ("-P","--proto"):
				protocol=a
			elif o in ("-f","--flags"):
				flags=a
			elif o in ("-t","--target"):
				if outils.is_valid_ip(a):
					target_ip=a
				else:
					try:
						target_ip=socket.gethostbyname(a)
					except :
						print "Impossible de trouver l'adresse IP correspondante ."
						usage()	
						sys.exit()		

			elif o in ("-p","--port"):
				list=a.split(",")
				if len(list)==2:
					p, q = map(int,list)
					port_range=range(p,q+1)
				elif len(list)==1:
					port_range=[int(a)]
			elif o in ("-r","--reverse"):
				reverse=True
			elif o in ("-i","--interface"):
				interface=a
			elif o in ("-d","--detect"):
				detection=a
			elif o in ("-h","--help"):
				usage()
				sys.exit()
	except :
		
		sys.exit()


				
	if scanType:
		if sniff or reverse or protocol or (scanType=="udp" and flags) or (scanType=="icmp-echo" and (flags or port_range)):
			usage()
			sys.exit()
		
		import scanner
		queue = Queue.Queue()
		cidr=outils.cidr(target_ip)
		if len(cidr)==2:					
			ip_list=outils.get_addresses(cidr[0],cidr[1])
		else :
			ip_list=cidr
	
		startTime=time.time()
		if scanType!="icmp-echo":
			for ip in ip_list:
				scanner.target_ip=ip
       		 		for j in range(15):
                  			if scanType=="tcp":
                        			scan = scanner.TCPScanner(queue,flags)
                        			scan.setDaemon(True)
                        			scan.start()
              				elif scanType=="udp":
                       				scan = scanner.UDPScanner(queue)
                        			scan.setDaemon(True)
                        			scan.start()
        			if port_range:
                			for port in port_range:
                        			queue.put(port)
        			else:                		
					for port in range(1,1025):
						queue.put(port)
        			queue.join()
				
				scanner.scan_report(startTime,scanType,port_range)
	
		else:
			for j in range(15):
				scan=scanner.pingScan(queue)
				scan.setDaemon(True)
				scan.start()
			for ip in ip_list:
				queue.put(ip)
		
			queue.join()

			scanner.scan_report(startTime,scanType,None)
		
	elif detection:
		import Detect
		if detection=="dhcpserver":
			Detect.detect_DHCP_servers(interface)
		elif detection=="arppoison":
			Detect.detect_arp_poison(target_ip,interface)
			
	elif protocol :	
		if  sniff or scanType or flags or target_ip or reverse:
			usage()
			sys.exit()
		if protocol=="dhcp":
			import DHCPtester
			DHCPtester.DHCPtester()
		elif protocol=="dns":
			import DNS
			DNS.DNStester()
		elif protocol=="arp":
			import ARP_attaque
			ARP_attaque.menu()		
	elif reverse :
		if sniff or scanType or flags or target_ip or port_range or protocol:
			usage()
			sys.exit()
		import Reverse
		Reverse.reverse()
	elif sniff:
		if scanType or flags or not(target_ip) or port_range or not(interface) or reverse or protocol :
			import Sniffer
			sniffer =Sniffer.Sniffer(interface,"tcp", 80 ,target_ip)
 		 	sniffer.sniff()
if __name__=="__main__":
	main()
	
