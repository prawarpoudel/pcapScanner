# packet parser written by Prawar Poudel
# this script scans through a 'pcap' file,
# and conunts the number of various packet types

# importing the library for reading
import sys
import os.path
import socket
import dpkt

# this flag is used to print and handle debug messages
debug = False

def packet_is_ip(eth):
	'''
	This funtion takes in the ethernet packet as argument
	Returns True if it is IP (TCP or UDP)
	'''
	if isinstance(eth.data, dpkt.ip.IP):
		return True
	return False

def parse_pcap(pcap_filename):

	# following are the counters for each kind of scan
	xmas_scan = 0
	udp_scan = 0
	null_scan = 0
	half_scan = 0
	connect_scan = 0
	udp_null_scan = 0
	# following is the set that identifies the uniqueness of the packets
	my_xmas_set = set()
	my_null_set = set()
	my_syn_set = set()
	my_ack_set = set()
	my_rst_set = set()
	my_synack_set = set()
	my_ackrst_set = set()

	# check if the pcap file exists
	if not os.path.isfile(pcap_filename):
		print('File {} doesnot exist. Please provide the proper file name'.format(pcap_filename))
		exit()

	# say if the file exists for debug
	if debug:
		print('File {} is found.'.format(pcap_filename))

	# open the file
	f = open(pcap_filename)
	if not f:
		print('Unable to open file: {}'.format(pcap_filename))
		exit()

	# read the file using the library
	pcap = dpkt.pcap.Reader(f)

	# iterate through all the packets of the pcap file read
	for ts,buf in pcap:
		# get the ethernet object from the buffer
		eth = dpkt.ethernet.Ethernet(buf)

		# we wont actually worry about packets other than TCP and UDP so
		if packet_is_ip(eth):
			# if IP, grab the IP from the ethernet packet
			ip = eth.data
			my_ip_data = ip.data

			if type(my_ip_data)==dpkt.tcp.TCP:			
				my_destination_port = my_ip_data.dport
				my_source_port = my_ip_data.sport
				my_source_ip = socket.inet_ntoa(ip.src)
				my_destination_ip = socket.inet_ntoa(ip.dst)

				my_source_id = str(my_source_ip)+str(my_source_port)
				my_destination_id = str(my_destination_ip)+str(my_destination_port)
				my_packet_id = str(my_source_id)+str(my_destination_id)
				# the packet is TCP, so work accordingly
				if debug:
					print('Packet found: TCP: Source {}:{} -> Destination {}:{}, Flags = {}'.format(my_source_ip,my_source_port,my_destination_ip,my_destination_port,my_ip_data.flags))
				
				# check for the flags set in the packet
				# .. if no flags, it is NULL scan
				if my_ip_data.flags==0:
					# packet id is changed since NULL scan directed to single port 
					# .. is only conted once
					my_packet_id = str(my_source_ip)+str(my_destination_id)
					if debug:
						print('\tPacket found: NULL')
					if my_packet_id in my_null_set:
						# we will not count multiple times
						if debug:
							print('\tIgnoring..')
						pass
					else:
						# if not already there, count NULL type and put in the set
						my_null_set.add(my_packet_id)
						null_scan+=1
				else:
					# scan through all the flag types
					fin_flag = (my_ip_data.flags&dpkt.tcp.TH_FIN)!=0
					syn_flag = (my_ip_data.flags&dpkt.tcp.TH_SYN)!=0
					rst_flag = (my_ip_data.flags&dpkt.tcp.TH_RST)!=0
					psh_flag = (my_ip_data.flags&dpkt.tcp.TH_PUSH)!=0
					ack_flag = (my_ip_data.flags&dpkt.tcp.TH_ACK)!=0
					urg_flag = (my_ip_data.flags&dpkt.tcp.TH_URG)!=0
					ece_flag = (my_ip_data.flags&dpkt.tcp.TH_ECE)!=0
					cwr_flag = (my_ip_data.flags&dpkt.tcp.TH_CWR)!=0

				# check the xmas scan
				if fin_flag and urg_flag and psh_flag:
					# if already there, we will not count it
					# packet id is changed since XMAS scan directed to single port 
					# .. is only conted once
					my_packet_id = str(my_source_ip)+str(my_destination_id)
					if debug:
						print('\tPacket found: XMAS')
					if my_packet_id in my_xmas_set:
						if debug:
							print('\tIgnoring')
						pass
					else:
						my_xmas_set.add(my_packet_id)
						xmas_scan += 1
				elif syn_flag and ack_flag:
					# if the packet has SYN and ACK flag both, this can mean only one thing
					# . this is a part of SYN, SYN+ACK and ACK protocol
					if my_packet_id in my_synack_set:
						# already in the set
						if debug:
							print('\tIgnoring: SYN+ACK')
						pass
					else:
						# we will add this to the set, but lets do a check here
						# .. to see if this SYN+ACK has a SYN packet before it 
						if debug:
							print('\tPacket found: SYN+ACK')
							if str(my_destination_id)+str(my_source_id) in my_syn_set:
								pass
							else:
								print('\t SYN+ACK has no SYN packet before this')
						my_synack_set.add(my_packet_id)
						# we will not do any counting here, because it is not an indication of any
						# .. thing complete
				elif syn_flag:
					# we are only concerned with Source-Destination syn flag, so we will just
					# .. put it in the set
					if my_packet_id in my_syn_set:
						if debug:
							print('\tIgnoring SYN')
						pass
					else:
						if debug:
							print('\tPacket found: SYN')
						my_syn_set.add(my_packet_id)
						# no counting is done here just for syn packet
				elif ack_flag and rst_flag:
					# ACK can be source to destination, or destination to source
					# we need to be careful here

					# since ACK is a result of SYN, or SYN+ACK, we need to check here
					# ..if none of SYN or SYN+ACK is detected prior to this, we will ignore this ACK
					if str(my_destination_id)+str(my_source_id) in my_syn_set:
						# means this is because of the protocol SYN,ACK protocol
						# .. this kind will be seen in SYN scan or connect scan
						if my_packet_id in my_ackrst_set:
							# repeated ACK packet, we will ignore this
							if debug:
								print('\tIgnoring ACK+RST')
							pass
						else:
							# we will increase the count of both the half scan and connect scan
							# .. as this can be anything
							if debug:
								print('\tPacket found: ACK+RST')
							my_ackrst_set.add(my_packet_id)
							connect_scan += 1
							half_scan += 1
				elif ack_flag:
					# ACK can be source to destination, or destination to source
					# we need to be careful here

					# since ACK is a result of SYN, or SYN+ACK, we need to check here
					# ..if none of SYN or SYN+ACK is detected prior to this, we will ignore this ACK
					if str(my_source_id)+str(my_destination_id) in my_syn_set:
						# means this was part of SYN,SYN+ACK, ACK protocol
						# .. this will be only particular to connect scan
						
						# let us also see if the corresponding SYN+ACK packet is already received
						if str(my_destination_id)+str(my_source_id) in my_synack_set:
							if my_packet_id in my_ack_set:
								# repeated packet, we will ignore this
								if debug:
									print('\tIgnoring ACK')
								pass
							else:
								if debug:
									print('\tPacket found: ACK')
								my_ack_set.add(my_packet_id)
								connect_scan += 1		
						else:
							# we will ignore this
							pass
					else:
						# being here does not make sense
						pass
				elif rst_flag:
					# RST flag can only mean one thing, half scan
					# for any open port, the protocol follows as SYN, SYN+ACK, RST
					if my_packet_id in my_rst_set:
						# doubled RST packet, we will ignore this
						if debug:
							print('\tIgnoring RST')
						pass
					else:
						if debug:
							print('\tPacket found: RST')
						# we will check if the corresponding SYN an SYN+ACK packet is already received
						if my_packet_id in my_syn_set:
							# means there is SYN packet
							if (my_destination_id)+str(my_source_id) in my_synack_set:
								# means there is SYN+ACK also
								my_rst_set.add(my_packet_id)
								half_scan += 1
							else:
								if debug:
									print('\t No SYN+ACK packet for this RST packet. Ignoring RST packet')
						else:
							if debug:
								print('\t No SYN packet for this RST packet. Ignoring RST packet')
				else:
					if debug:
						print('\tThis packet does not fall in any category')

			elif type(my_ip_data)==dpkt.udp.UDP:
				# the packet is UDP, so work accordingly
				my_destination_port = my_ip_data.dport
				my_source_port = my_ip_data.sport
				my_source_ip = socket.inet_ntoa(ip.src)
				my_destination_ip = socket.inet_ntoa(ip.dst)

				my_source_id = str(my_source_ip)+str(my_source_port)
				my_destination_id = str(my_destination_ip)+str(my_destination_port)
				my_packet_id = str(my_source_id)+str(my_destination_id)
				if debug:
					print('Packet found: UDP: Source {}:{} -> Destination {}:{}'.format(my_source_ip,my_source_port,my_destination_ip,my_destination_port))
				# we will only count the number of UDP packets that are
				# .. of 0 length
				if len(my_ip_data.data)==0:
					udp_null_scan += 1
				udp_scan += 1
		else:
			if debug:
				print('Packet is neither TCP nor UDP')

	if half_scan>connect_scan:
		connect_scan = 0
	else:
		half_scan = 0

	print('NULL:{}'.format(null_scan))
	print('XMAS:{}'.format(xmas_scan))
	print('UDP:{}'.format(udp_null_scan))
	print('Half-open:{}'.format(half_scan))
	print('Connect:{}'.format(connect_scan))

		

if __name__=='__main__':

	# grab the file name
	file_name = 'test.pcap'	#just a default name of file
	no_arguments = len(sys.argv)


	if debug:
		# print the python version information, just in case
		print(sys.version)
		print ("The number of arguments provided is {}".format(no_arguments));

	if no_arguments==1:
		# just go with the default file name
		if debug:
			print('Going with the default pcap file: {}'.format(file_name))
	else:
		# check for the flag
		if str(sys.argv[1]) == '-i' and no_arguments>2:
			# this is our flag
			file_name = str(sys.argv[2])
		else:
			print('Flag type is {} not supported. Please consult the developer'.format(sys.argv[1]))
			exit()
	parse_pcap(file_name)