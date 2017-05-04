from scapy.all import *



class Sniffer():
	
	def __init__(self, interface , proto, port, target_ip):
		self.interface=interface
		self.proto=proto
		self.port=port
		self.target_ip=target_ip

	def sniff(self):
		if self.target_ip and self.proto :
			sniff(iface = self.interface , filter = "%s and src or dst %s and tcp port %d "%(self.proto,self.target_ip,self.port), prn =self.analyse_tcp, store=0)
		else :
			sniff(iface = self.interface , filter = "%s and tcp port %s "%(self.proto, self.port), prn =self.analyse_tcp, store=0)
	
	def analyse_tcp(self,pkt):
		if pkt[TCP].flags==2  or pkt[TCP].flags==18 :
			print ' TCP :  %s:%d ----------------> %s:%d\t:Etablissement de connexion . '%(pkt[IP].src, pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport)
		elif pkt[TCP].flags>=16 and pkt[TCP].flags%2==0:
			print ' TCP :  %s:%d ----------------> %s:%d\t:Connexion etablie . '%(pkt[IP].src, pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport)
			if (pkt[TCP].dport==80 or pkt[TCP].sport==80 ) and pkt[TCP].payload:
				HTTPfields=pkt[Raw].load.split("\r\n")
				print "\n\t-".join(HTTPfields[:len(HTTPfields)-2]) 
		elif pkt[TCP].flags==20 or pkt[TCP].flags==1 :
			print ' TCP :  %s:%d ----------------> %s:%d\t:Fermeture de connexion . '%(pkt[IP].src, pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport)	
		


	
	
	
	
