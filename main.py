import socket
import struct
import textwrap
import datetime
import db
import requests

from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context
from time import sleep
from threading import Thread, Event
from random import random
from hexdump import hexdump

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True


#displayData Thread
thread = Thread()
thread_stop_event = Event()


socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True) #turn the flask app into a socketio app
dataArray = [] #global variable to store table data
database = db.myDB #create database object

localhost_ip = "10.0.2.4"#change this
dict = {}

#unpack ethernet frame
def ethernet_frame(data):
	# struct.unpack format : ! == network, 6s == 6bytes/characters, H=proto
	# What is data[:14]? Start from 0 to the 14th character
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	
	#since the format of the dest_mac and src_mac are not in human readable format, use function get_mac_addr to convert 
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]
	
#return properly formatted MAC Address(AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	
	return ':'.join(bytes_str).upper()
	
	
# Unpack IPv4 packet
def ipv4_packet(data):
	#version and header is the 1st byte
	#extract using bitwise
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
	
# returns properly formatted IPv4(e.g 127.0.0.1)
def ipv4(addr):
	return '.'.join(map(str, addr))
	
# Unpack ICMP Packet
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]
	
# unpack TCP segment
def tcp_segment(data):
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
	
# Unpacks UDP segment
def udp_segment(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]
	
# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
	

# detect malicious packets against config.txt
def detect(protocol, source, src_port, destination, dest_port):

	global database	
	
	f = open('config.txt', 'r')
	
	severityLevel = "None"

	for x in f:
		# ignore comments in config file
		if "#" not in x:
		
			data=x.split(' ')
			config_proto = data[0]
			config_source_addr = data[1]
			config_src_port = data[2]
			config_dest_addr = data[4]
			config_dest_port = data[5]
			severity = data[6]
		

			if(config_src_port != "any") or (config_dest_port != "any"):
				if(protocol == config_proto) and (source == config_source_addr) and (src_port == config_src_port) and (destination == config_dest_addr) and (dest_port == config_dest_port):
					severityLevel = severity.strip()
			else:
				if(protocol == config_proto) and (source == config_source_addr) and (destination == config_dest_addr):
					severityLevel = severity.strip()
	
	return severityLevel	
	

def dos():

	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
	
	global dict
	message = ""

	file_txt = open("attack_DoS.txt",'a')
	t1 = str(datetime.datetime.now())

	file_txt.writelines(t1)
	file_txt.writelines("\n")


	No_of_IPs = 5
	R_No_of_IPs = No_of_IPs +10
	pkt = s.recvfrom(2048)
	ipheader = pkt[0][14:34]
	ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
	IP = socket.inet_ntoa(ip_hdr[3])
	print ("The Source of the IP is:", IP)
	print(dict)

	if dict.__contains__(IP):
		dict[IP] = dict[IP]+1
	else:
		dict[IP] = 0


	if(dict[IP] >= No_of_IPs) and (dict[IP] <= R_No_of_IPs) :
		print("DDOS attack detected")
		line = "DDOS attack is Detected: "
		file_txt.writelines(line)
		file_txt.writelines(IP)
		file_txt.writelines("\n")
		message = "Possible DoS attack detected"
		
		
	print(message)
	return message

def send_to_telegram(message):

    apiToken = '5623414566:AAGKkS-1jP2mWgCSYVkSkMDs9QmvLnmaegU'
    chatID = '625857550' # change this
    apiURL = f'https://api.telegram.org/bot{apiToken}/sendMessage'

    try:
        response = requests.post(apiURL, json={'chat_id': chatID, 'text': message})
    except Exception as e:
        print(e)
	
@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
	global thread
	print('Client connected')
    
	#Start the random number generator thread only if the thread has not been started before.
	if not thread.is_alive():
		print("Starting Thread")
		thread = socketio.start_background_task(main)
        
@socketio.on('disconnect', namespace='/test')
def test_disconnect():
	print('Client disconnected')

#pass data to front end to display on webpage
def displayData(dataArray):
    print("Displaying Data")
    socketio.emit('newnumber', {'data': dataArray}, namespace='/test')
    socketio.sleep(0.5)
    
#receieve message from client
@socketio.on('message', namespace='/test')
def handle_message(message):
	print("************	Received message: " + message)
	
	if(message == 'export'):
		export()

	
def export():

	x = datetime.datetime.now()
	
	x = str(x) + ".txt"

	with open(x, 'w') as f:
		for i in dataArray:
			for j in dataArray:
				f.write(str(j))
				f.write(",")
				f.write('\n')
				


@app.route('/')
def index():
    #only by sending this page first will the client be connected to the socketio instance
    return render_template('index.html')
		

def main():
	conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	
	
	#while True:
	while not thread_stop_event.is_set():
		# Capture data in network
		raw_data, addr = conn.recvfrom(65536)
		date_time = str(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"))
		
		#format data
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		
		# Do not print localhost data
		if dest_mac != "00:00:00:00:00:00" and src_mac != "00:00:00:00:00:00":
			# 8 for ipv4
			if eth_proto == 8:
				(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
				
				'''
				print(TAB_1 + 'IPv4 Pakcet: ')
				print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
				print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
				'''
				
				
				# ICMP
				if proto == 1:
					icmp_type, code, checksum, data = icmp_packet(data)
					
					proto = 'icmp'
					
					'''
					print(TAB_1 + 'ICMP Packet: ')
					print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
					print(TAB_2 + 'Data:')'''
					print(format_multi_line(DATA_TAB_3, data))
					
					
					severity = detect(proto, src, src_port, target, dest_port)
					check_ddos = dos()
					#rowData = [date_time, src, src_port, target, dest_port, proto, severity, check_ddos, str(data)]
					
					#dataArray.append(rowData)
					#dataArray.insert(0, rowData)
					
					#displayData(rowData)
					if check_ddos == "Possible DoS attack detected":
						severity = 'medium'	
						
					
					rowData = [date_time, src, src_port, target, dest_port, proto, severity, check_ddos]
					dataArray.insert(0, rowData)	
					
					if severity == 'high' or severity == 'medium' or severity == 'low':
						send_to_telegram(rowData)
						database.updateDB(date_time, proto, src, src_port, target, dest_port , severity, check_ddos)
						
					rowData.append(str(hexdump(data)))
					displayData(rowData)
				
				# TCP
				elif proto == 6:
					(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
					
					proto = 'tcp'
					
					'''
					print(TAB_1 + 'TCP Segment:')
					print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
					print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
					print(TAB_2 + 'Flags:')
					print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
					print(TAB_2 + 'Data:')'''
					print(format_multi_line(DATA_TAB_3, data))
					
					# *****data*****??
					
					
					severity = detect(proto, src, src_port, target, dest_port)
					check_ddos = dos()
					#rowData = [date_time, src, src_port, target, dest_port, proto, severity, check_ddos, str(data)]
					
					#dataArray.append(rowData)
					#dataArray.insert(0, rowData)
					
					#displayData(rowData)
					if check_ddos == "Possible DoS attack detected":
						severity = 'medium'	
						
					
					rowData = [date_time, src, src_port, target, dest_port, proto, severity, check_ddos]
					dataArray.insert(0, rowData)	
					
					if severity == 'high' or severity == 'medium' or severity == 'low':
						send_to_telegram(rowData)
						database.updateDB(date_time, proto, src, src_port, target, dest_port , severity, check_ddos)
						
					rowData.append(str(hexdump(data)))
					displayData(rowData)
					
				#UDP
				elif proto == 17:
					src_port, dest_port, length, data = udp_segment(data)
					
					proto = 'udp'
					
					
					#print(TAB_1 + 'UDP Segment:')
					#print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
					
					severity = detect(proto, src, src_port, target, dest_port)
					check_ddos = dos()
					
					#displayData(rowData)
					if check_ddos == "Possible DoS attack detected":
						severity = 'medium'	
						
					
					rowData = [date_time, src, src_port, target, dest_port, proto, severity, check_ddos]
					dataArray.insert(0, rowData)	
					
					if severity == 'high' or severity == 'medium' or severity == 'low':
						send_to_telegram(rowData)
						database.updateDB(date_time, proto, src, src_port, target, dest_port , severity, check_ddos)
						
					rowData.append(str(hexdump(data)))
					displayData(rowData)

			#else:
				#pass
				#print('Data:')
				#print(format_multi_line(DATA_TAB_1, data))


if __name__ == '__main__':
	socketio.run(app)
