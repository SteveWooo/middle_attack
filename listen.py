import sys
import time as time
from scapy.all import (
	get_if_hwaddr,
	getmacbyip,
	ARP,
	Ether,
	sendp,
	sniff,
	wrpcap,
	Raw,
	TCP,
	IP
)
import scapy_http.http as HTTP
#
def callback(pkt):
	if HTTP.HTTPRequest in pkt:
		payload = pkt[TCP].payload
		if payload.Method == "GET":
			url = "http://{0}{1}".format(payload.Host, payload.Path)
			# if url.find(".jpg") > 0:
			print url
			print payload.Headers
			print "====="

result = sniff(filter="tcp and port 80", prn=callback, iface="en0")