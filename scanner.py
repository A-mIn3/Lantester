import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
from datetime import date
import threading
conf.verb=0

pingSw_subnet=None
IN=False
target_ip=""

		
def port_mapping(proto):
        services = {}
        file=open("/etc/services","r")
        for line in file.readlines():
                if not(line[:1]=="#" or line[:1]==" "):
                        if "/tcp" in line :
                                list=line.strip("\n").split("\t")
                                if not ( " " in list[0]):
                                        i=1
                                        while True :
                                                if len(list[i])!=0:
                                                        break
                                                else:
                                                        i+=1
                                        port=int(list[i].split("/")[0])
                                        services[port]=list[0]
                                else :
                                        list=list[0].split(" ")
                                        port=int(list[1].split("/")[0])
                                        services[port]=list[0]
                                        
        file.close()
	return services


def scan_report (startTime,scanType,port_range):
	global target_ip , IN
	if not IN: 
		print"-------------------------------------------------------------------------------------------------"
		print "-Lancement du Scan  : %s .  "%time.ctime(startTime) 
		print "-Duree du scan : %s seconds . "%str( time.time()-startTime)
		IN=True
	
	if scanType=="icmp-echo":
		dic=pingScan.host_state
		if not pingSw_subnet:
			host=dic.keys()[0]
			if dic[host]=="up":
				print "[+] L'hote %s semble up. "%host
		else:
			 print "------------------- Rapport de probe icmp-echo de la plage %s ---------------- : "%pingSw_subnet
	
			 for host in dic.keys():
				if dic[host]=="up":
					print "[+] %s est up ."%host
				else:
					print "[-] %s est down ."%host
	else:
		print "----------------- Rapport de scan des ports de l'hote %s --------------- : "%target_ip
		if len(port_range)>=2:
			print "Plage de ports : %d-%d/%s ."%(port_range[0],port_range[len(port_range)-1],scanType)
		else:
			print " Scan du port %d/%s."%(port_range[0],scanType)
		if scanType=="tcp":
               	
			services=port_mapping("tcp")

			if len(TCPScanner.open_ports)==0 and TCPScanner.closed_ports==0:
				print "[-]L'hote %s semble down . "%target_ip
			else:
				print "[+]L'hote %s semble up ."%target_ip
        		if TCPScanner.open_ports:
				print "\tLes ports TCP ouverts :"
       				for port in TCPScanner.open_ports:
        				if services.has_key(port):
                				print '\t\t[+] %d/tcp , service %s .'%(port,services[port])
	
			print "[-]%d ports fermes . "%TCPScanner.closed_ports	
        		print '[-]%d ports filtres .'%(len(port_range)-len(TCPScanner.open_ports)-TCPScanner.closed_ports)
		
			TCPScanner.closed_ports=0
	        	TCPScanner.open_ports=[]

		elif scanType=="udp":
			if UDPScanner.closed_ports!=0:
				print "[+] L'hote %s semble up ."%target_ip
			else :
				print "[-] L'hote %s semble down ."%target_ip
		
			UDPScanner.closed_ports=0
	
class pingScan(threading.Thread):
        host_state={}
        def __init__(self,queue):
                threading.Thread.__init__(self)
                self.queue=queue


        def run(self):
                while True:
                       	t_ip=self.queue.get()
                        ip=IP(dst=t_ip)
                        icmp= ICMP()
                        echo_req=ip/icmp
                        ans = sr1(echo_req,timeout=4)
                        if ans:
				if ans.src==t_ip:
                        		pingScan.host_state[t_ip]="up"
                        else :
                                pingScan.host_state[t_ip]="down"
                        self.queue.task_done()
	
			

class TCPScanner (threading.Thread):
	
	open_ports= []
	closed_ports=0
	
	
	def __init__(self, queue,type):
		threading.Thread.__init__(self)
		self.queue=queue
		self.type=type
		
		
	
	def get_type(self):
		if self.type=="SYN":
			return 2
		elif self.type=="FIN":
			return 1
		elif self.type=="NULL":
			return 0
		elif self.type=="XMAS":
			return 31
		
	def run(self):
		
		while True :
			port = self.queue.get()
			tcp=TCP()
			tcp.flags=self.get_type()
			tcp.sport=random.randint(0xff10, 0xffe0)
			tcp.dport=port
			ip=IP()
			ip.dst=target_ip
			tcp_pkt=ip/tcp
			ans = sr1(tcp_pkt,timeout=6)
			
		        if ans :
			
				if ans[TCP].flags==18:
					TCPScanner.open_ports.append(port)			
					sr1(IP(dst=target_ip)/TCP(sport=ans[TCP].dport, dport=ans[TCP].sport, flags=20))
				elif ans[TCP].flags==20:
					TCPScanner.closed_ports+=1
			self.queue.task_done()
				

class UDPScanner(threading.Thread):
	
	closed_ports=0

	
	def __init__(self,queue):
		threading.Thread.__init__(self)		
		self.queue=queue
		

	def run(self):
		while True:
			port=self.queue.get()
			udp = UDP(sport=random.randint(0xff00,0xfff0), dport=port)
			ip=IP(dst=target_ip)
			sr1(ip/udp)
			sniff(prn=self.udp_anaylser,timeout=5)
	 		self.queue.task_done()

	def udp_analyser(self,pkt):
		if pkt.has_layer(ICMP):
			if pkt.src==target_ip and pkt[ICMP].type==3 and pkt[ICMP]==3:
				closed_ports+=1
		return
		

		
