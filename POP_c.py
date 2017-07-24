#!/bin/usr/python
# -*- coding:utf-8 -*-



import sys
import time 
#import pprint
import requests 
import censys.certificates 
import json
import os


"""cor1 = "\033[31m"


animation = "|/-\\"
for i in range(15):
    time.sleep(0.1)
    sys.stdout.write("\r" + "|" + animation[i % len(animation)] + "|" + cor1 + "meu texto aqui")
    sys.stdout.flush()
print('')


#sys.stdout.write(cor1+banner)
"""
cor1 = "\033[32m"

os.system("pip3 install --upgrade requests")
os.system("clear")
url_da_api = "https://www.censys.io/api/v1"
api_id = "0b0a437b-9b28-47de-89d5-2d168d0fc7cf"	
secret = "IpFLUkaxpJNtitqAkmxwQedDfcHEHN5Z"
page = 1
pages = float('inf')
#fields = ['location.country', 'location.country_code', 'location.city', 'ip', 'protocols', 'autonomous_system.name']

global corv
global corv1
global bann

corv = "\033[31m"
corv1 = "\033[32m"

bann = """
 ██▓███   ▒█████   ██▓███   ▄████▄   ▒█████   ██▀███   ███▄    █ 
▓██░  ██▒▒██▒  ██▒▓██░  ██▒▒██▀ ▀█  ▒██▒  ██▒▓██ ▒ ██▒ ██ ▀█   █ 
▓██░ ██▓▒▒██░  ██▒▓██░ ██▓▒▒▓█    ▄ ▒██░  ██▒▓██ ░▄█ ▒▓██  ▀█ ██▒
▒██▄█▓▒ ▒▒██   ██░▒██▄█▓▒ ▒▒▓▓▄ ▄██▒▒██   ██░▒██▀▀█▄  ▓██▒  ▐▌██▒
▒██▒ ░  ░░ ████▓▒░▒██▒ ░  ░▒ ▓███▀ ░░ ████▓▒░░██▓ ▒██▒▒██░   ▓██░
▒▓▒░ ░  ░░ ▒░▒░▒░ ▒▓▒░ ░  ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ 
░▒ ░       ░ ▒ ▒░ ░▒ ░       ░  ▒     ░ ▒ ▒░   ░▒ ░ ▒░░ ░░   ░ ▒░
░░       ░ ░ ░ ▒  ░░       ░        ░ ░ ░ ▒    ░░   ░    ░   ░ ░ 
             ░ ░           ░ ░          ░ ░     ░              ░ 
                           ░                                     
+===============================================================+
| [+] craking and crime heuaheuahuheuaheuheauhue                |
+---------------------------------------------------------------+                          
"""

while page <= pages:
	try:
		print(corv+bann)
		print("[+] simple writing ips censys: ")
		print("[dev] @desmondelite: ")
		print("[+] loop forever true: ")
		time.sleep(2)
		censys_key = input("[*] type a key censys: "+corv1)
		censys_txt = "popcorn_censys.txt"

		global ar_ip
		params = {'query' : censys_key, 'page' : page}
		ar_ip = open(censys_txt, "w")


		res = requests.post(url_da_api + "/search/ipv4", json = params, auth = (api_id, secret))

		pay = res.json()
		for i in pay["results"]:
			ip = i["ip"]
			proto = i["protocols"]
			print("IP: ", ip)
			print("proto : ", proto)
			#escrever ips censys 
			print("[+] writing ips censys in 'popcorn_censys.txt'.......")
			ar_ip.write(str(ip)+ "\n")




		pages = pay['metadata']['pages']
		ar_ip.close()

		page += 1
		print("")
		print("[*] loop is true [*]")
		print("[+] type Ctrl+c return....")
		print("")	

	except KeyboardInterrupt:
		time.sleep(2)
		os.system("python POP_corn.py")
