#!/usr/bin/python

from scapy.all import *
import netifaces, threading, logging, time, urllib, re, os
import logging.handlers as handlers

LOG_DIR= "/tmp/"
RULE_FILE="/root/oakenshield/rules.txt"
DATE=time.strftime("/%Y/%m/")
LOG_FILE= time.strftime("%d.log")
LOG_FILE2= time.strftime("%d-all.log")
INTERFACE=""
POD_PKT_ID = -1
POD_PKT_SIZE = 0
PACKETS=dict()
rules=[]

def all_nics():
	return netifaces.interfaces()
	
def remove_duplicate(interface):
	path = LOG_DIR + str(interface) + DATE + LOG_FILE
	os.system("sort %s | uniq > %s" %(path, LOG_DIR + str(interface) + DATE +"log"))

def pkt_test(pkt):
	pkt.show()

def url_decode(payload):
	return urllib.unquote(payload).decode('utf8')

def read_rule():
	with open(RULE_FILE) as f:
		lines = f.readlines()
		for line in lines:
			rules.append(line.rstrip("\r\n"))

def match_pattern(payload):
	payload = """%s"""%payload
	pattern=r"(\'|\"| )|([\w|\'|\"]+[\'|\"|\;| |+|\#|])|(\-\-|\#|\;)"
	result=re.match(pattern, payload)
	if result != None:	
		for group in re.match(pattern, payload).groups():
			if group != None:
				return payload

def pkt_callback(pkt):
	create_log_folder(INTERFACE)
	log = pkt.summary()
	name = "log_all_data"
	log_to_file2(INTERFACE, log, name)
	if IP in pkt:
		if pkt["IP"].get_field('proto').i2s[pkt.proto] == "icmp":
			pingOfDeath(pkt["IP"])
		# TCP packets
		# Can be SQLi or Nmap scanner
		# Detect NMap SYN Stealth scan for opened port and closed port
		elif pkt["IP"].get_field('proto').i2s[pkt.proto] == "tcp":
			tcp_pkt = pkt["TCP"]
			src_ip = pkt["IP"].src
			src_dest = pkt["IP"].dst
			src_port = tcp_pkt.sport
			dst_port = tcp_pkt.dport
			flags = tcp_pkt.flags
			seq = tcp_pkt.seq
			ack = tcp_pkt.ack
			# First request is SYN
			# Nmap scan for open port
			# SYN.seq: n (n is integer)
			# SYN/ACK.ack = n + 1
			# R.seq = n + 1

			#Nmap scan for closed port
			# SYN.seq: n (n is integer)
			# RA.ack: SYN.seq(n) + 1
			if flags == "S":
				PACKETS[seq] = tcp_pkt
			elif (flags=="SA") and (ack - 1 in PACKETS) and (src_port == PACKETS.get(ack - 1).dport):
				PACKETS[ack] = tcp_pkt
				PACKETS.pop(ack - 1)
			elif (flags=="RA") and (ack - 1 in PACKETS) and (dst_port == PACKETS.get(ack - 1).sport):
				PACKETS.pop(ack - 1)
				log="%s -> %s. Detected SYN Stealth scan for closed port %s." %(src_ip, src_dest, src_port)
				name="SYN Stealth Scan"
				log_to_file(INTERFACE, log, name)
			elif (flags=="R") and (seq in PACKETS) and (src_port == PACKETS[seq].dport):
				PACKETS.pop(seq)
				log="%s -> %s. Detected SYN Stealth scan for opened port %s." % (src_ip, src_dest, dst_port)
				name="SYN Stealth Scan"
				log_to_file(INTERFACE, log, name)
	#Detect sql injection
	if Raw in pkt:
		data = pkt["Raw"].load
		http_method = data.split("\r\n")[0]
		if "GET" in http_method:
			payload = http_method.split(" ")[1]
			if payload.startswith("/?"):
				if "&" in payload.split("/?")[1]:
					args=payload.split("/?")[1].split("&")
					for arg in args:
						result = """%s""" %match_pattern(url_decode(arg.split("=",1)[1]))
						if result != "None":
							log = """%s -> %s.Param: %s .Payload: %s""" %(src_ip, src_dest, arg.split("=",1)[0],result)
							name="SQL Injection - GET parameter"
							log_to_file(INTERFACE, log, name)
				else:
					arg=payload.split("/?")[1]		
					result = """%s""" %match_pattern(url_decode(arg.split("=",1)[1]))
					print result
					if result != "None":
							log = """%s -> %s.Param: %s .Payload: %s""" %(src_ip, src_dest, arg.split("=",1)[0],result)
							name="SQL Injection - GET parameter"
							log_to_file(INTERFACE, log, name)
					
		if "POST" in http_method:
			payload_length=len(data.split("\n"))
			payload = data.split("\n")[payload_length-1]
			if "&" in payload:
				args = payload.split("&")
				for arg in args:
					result = """%s""" %match_pattern(url_decode(arg.split("=",1)[1]))
					if result != "None":
						log = """%s -> %s.Param: %s .Payload: %s""" %(src_ip, src_dest, arg.split("=",1)[0],result)
						name="SQL Injection - POST param"
						log_to_file(INTERFACE, log, name)
			else:
				result = """%s"""%match_pattern(url_decode(payload.split("=",1)[1]))
				if result != "None":
					log = "%s -> %s.Param: %s .Payload: %s"%(src_ip, src_dest,payload.split("=",1)[0] ,result)
					name="SQL Injection - POST param"
					log_to_file(INTERFACE, log, name)

def pingOfDeath(packet):
	global POD_PKT_ID
	global POD_PKT_SIZE

	ip_pkt = packet['IP']
	flags = packet.sprintf('%IP.flags%')

	if ip_pkt.len >= 1500 and flags == 'MF' and ip_pkt.frag == 0 and ICMP in packet and packet['ICMP'].type == 0:
		POD_PKT_ID = ip_pkt.id
	elif flags == '' and ip_pkt.id == POD_PKT_ID:
		POD_PKT_ID = -1
		POD_PKT_SIZE += ip_pkt.len
		log = "%s -> %s" % (ip_pkt.dst, ip_pkt.src)
		name = "Ping Of Death"
		log_to_file(INTERFACE, log, name)

def create_log_folder(interface):
	path = LOG_DIR + str(interface) + DATE
	if not os.path.exists(path):
		os.makedirs(path)
	if not os.path.isfile(path+LOG_FILE):
		file = open(path+LOG_FILE, "w+")
		file.close()

def log_to_file(interface,payload,name):
	path = LOG_DIR + str(interface) + DATE + LOG_FILE
    # Set event log name
	logger = logging.getLogger(name)
    # Set log format
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
    # Set log file
	fh = logging.FileHandler(path)
    # Set log level
	fh.setLevel(logging.WARN)
    # Set log format
	fh.setFormatter(formatter)
	logger.addHandler(fh)
    # Generate log data
	logger.warn(payload)
	fh.close()
	remove_duplicate(interface)
def log_to_file2(interface,payload,name):
	path = LOG_DIR + str(interface) + DATE + LOG_FILE2
    # Set event log name
	logger = logging.getLogger(name)
    # Set log format
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
    # Set log file
	fh = logging.FileHandler(path)
    # Set log level
	fh.setLevel(logging.WARN)
    # Set log format
	fh.setFormatter(formatter)
	logger.addHandler(fh)
    # Generate log data
	logger.warn(payload)
	fh.close()
	remove_duplicate(interface)
if __name__=="__main__":
	#nics=all_nics()
	#for interface in nics:
	#	INTERFACE=str(interface)
	#	create_log_folder(INTERFACE)
	#	th = threading.Thread(
    #  		target=sniff(iface=INTERFACE, prn=pkt_callback, filter="", store=0)
    #	)
	#	th.start()
	INTERFACE="ens33"
	read_rule()
	sniff(iface=INTERFACE,prn=pkt_callback ,filter="", store=0)