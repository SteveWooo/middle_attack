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

argv = {
	"interface" : "wlan0"
}

def log(data):
	file = open("./logs/listen.html", 'a+');
	file.write(data);
	file.close();

#
def callback(pkt):
	if HTTP.HTTPRequest in pkt:
		payload = pkt[TCP].payload
		if payload.Method == "GET":
			url = "http://{0}{1}".format(payload.Host, payload.Path)
			# if url.find(".jpg") > 0:
			print(url)
			print(payload.Headers)
			print("=====")
			log_str = "url : <a src='"+url+"'>"+url+"</a>\n" + payload.Headers + "\n==================================";
			log(log_str)
		if payload.Method == "POST":
			url = "http://{0}{1}".format(payload.Host, payload.Path)
			# if url.find(".jpg") > 0:
			print(url)
			print(payload.Headers)
			print("=====")
			log_str = "url : <a src='"+url+"'>"+url+"</a>\n" + payload.Headers + "\n==================================";
			log(log_str)

result = sniff(filter="tcp and port 80", prn=callback, iface=argv["interface"])
print ("listening")