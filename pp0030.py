# packet parser written by Prawar Poudel
# this script scans through a 'pcap' file,
# and conunts the number of various packet types

# importing the library for reading
import sys
import os.path
import dpkt

# this flag is used to print and handle debug messages
debug = False

def packet_is_ip(eth):
	if isinstance(eth.data, dpkt.ip.IP):
		return True
	return False

def parse_pcap(pcap_filename):

	xmas_scan = 0
	udp_scan = 0
	null_scan = 0
	half_scan = 0
	connect_scan = 0

	if not os.path.isfile(pcap_filename):
		print('File {} doesnot exist. Please provide the proper file name'.format(pcap_filename))
		exit()

	if debug:
		print('File {} is found.'.format(pcap_filename))

	f = open(pcap_filename)
	if not f:
		print('Unable to open file: {}'.format(pcap_filename))
		exit()

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
				# the packet is TCP, so work accordingly
				if debug:
					print('Packet found: TCP')
				# check for the flags set in the packet
				if my_ip_data.flags==0:
					if debug:
						print('Found NULL packet')
					null_scan+=1
				else:
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
					xmas_scan += 1

			elif type(my_ip_data)==dpkt.udp.UDP:
				# the packet is UDP, so work accordingly
				if debug:
					print('Packet found: UDP')
				udp_scan += 1
		else:
			if debug:
				print('Packet is neither TCP nor UDP')

	print('Number of NULL Scan = {}'.format(null_scan))
	print('Number of XMAS Scan = {}'.format(xmas_scan))
	print('Number of UDP Scan = {}'.format(udp_scan))
	print('Number of Half Scan = {}'.format(half_scan))
	print('Number of Connect Scan = {}'.format(connect_scan))

		

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