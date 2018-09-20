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

from http.server import HTTPServer, BaseHTTPRequestHandler
import os
class StaticServer(BaseHTTPRequestHandler):

    def do_GET(self):
        root = "./logs"
        print(self.path)
        if self.path == '/':
            filename = root + '/index.html'
        else:
            filename = root + self.path
 
        self.send_response(200)
        if filename[-4:] == '.css':
            self.send_header('Content-type', 'text/css')
        elif filename[-5:] == '.json':
            self.send_header('Content-type', 'application/javascript')
        elif filename[-3:] == '.js':
            self.send_header('Content-type', 'application/javascript')
        elif filename[-4:] == '.ico':
            self.send_header('Content-type', 'image/x-icon')
        else:
            self.send_header('Content-type', 'text/html')
        self.end_headers()
        with open(filename, 'rb') as fh:
            html = fh.read()
            #html = bytes(html, 'utf8')
            self.wfile.write(html)
 
def runServer(server_class=HTTPServer, handler_class=StaticServer, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Starting httpd on port {}'.format(port))
    httpd.serve_forever()

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
runServer()