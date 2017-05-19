   
       <b>"LANTESTER"</b>
           "Usage: lantester.py [-rs] [-p <protocol>] [-f <flags>] [-d <scan_type>] [-t <targetIP>]"
       
                -s --sniff                            -Sniffer la communication tcp d'une cible .
            	-d --detect                           -Detecter une attaque arp poisoning ou un serveur DHCP malveillant.
                -S --scan=scanType                    -Specifier le type de scan : tcp , udp , icmp-echo.
                -P --proto=protocol                   -Specifier le protocol a tester: dhcp , dns, arp.  
	        -f --flags=flags                      -Specifier le type de scan si le scan est sur TCP: SYN, FIN,    
                                                       ACK, NULL, XMAS.
	        -t --target=target_ip                 -Specifier une cible pour le scan.
                -p --port=port_range                  -Specifier une plage de ports a scanner.
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
          
          
