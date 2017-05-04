import sys, random, struct, socket
from ast import literal_eval 
import scanner

def randomMac():
        mac="\\x70\\x77"
        for i in range(4):
               mac+=("\\x"+(format((random.randint(0,255)),'02x')))
        return literal_eval("'%s'"%mac)

def get_subnetID(ip, mask):
        ip_num= struct.unpack("!L",socket.inet_aton(ip))[0]
        mask_num = struct.unpack("!L", socket.inet_aton(mask))[0]
        subID_num = ip_num & mask_num
        subID=socket.inet_ntoa(struct.pack("!L",subID_num))
        return str(subID)

def in_subnet(ip,netID,mask):
        mask_bytes=mask.split('.')
        netID_bytes=netID.split('.')
        broad_bytes=[]
        i =0
        while i<4 :
                if int(mask_bytes[i])==0:
                        break
                else :
                        i+=1
        j=0
        while j<i-1:
                broad_bytes.append(netID_bytes[j])
                j+=1
        inc=256-int(mask_bytes[i-1])
        broad_bytes.append(str(int(netID_bytes[i-1])+inc-1))
        k=i
        while k>i-1 and k<4:
                broad_bytes.append(str(255))
                k+=1
        broad='.'.join(broad_bytes)
        ip_num=struct.unpack("!L",socket.inet_aton(ip))
        netID_num=struct.unpack("!L",socket.inet_aton(netID))
        broad_num=struct.unpack("!L",socket.inet_aton(broad))
        return netID_num<ip_num and ip_num<broad_num



def cidr(ip):
	
	list = ip.split("/")
	if len(list)==2:
		mask=""	
		j=0
		n=int(list[1])/8
		for i in range(n):
			mask+="255"
			if i<3:
				mask+="."	
			j+=1
		n=int(list[1])%8
		l=0
		for i in range(n):
			l+=2**(7-i)
		mask+=str(l)
		j+=1
		while j<4:
			mask+="."+str(0)
			j+=1
		scanner.pingSw_subnet=ip
		return (get_subnetID(list[0],mask),mask)
		
	else :
		return list

def get_addresses(subnetID,mask):
	
	ip_addr=[]
	subnetID_num=struct.unpack("!L",socket.inet_aton(subnetID))[0]
	mask_num=struct.unpack("!L",socket.inet_aton(mask))[0]
	ip_num=subnetID_num+1
	ip=socket.inet_ntoa(struct.pack("!L",ip_num))
	
	while in_subnet(ip,subnetID,mask):
		ip_addr.append(ip)
		ip_num=ip_num+1
       		ip=socket.inet_ntoa(struct.pack("!L",ip_num))

	return ip_addr

def is_valid_ip(str):
	 ip = " " 
	 list=str.split("/")
         if len(list)==2:
		ip=list[0]
		if not(8<=int(list[1])<=31):
			return False
	 elif len(list)==1:
		ip=list
	 else:
		return True
	 try:
	 	list=map(int,ip.split("."))
	 	return True
	 except:
	 	return False
		 	
	
def main():
	list=get_addresses(cidr(sys.argv[1])[0],cidr(sys.argv[1])[1])
	for ip in list:
		print ip

if __name__=="__main__":
	main()
