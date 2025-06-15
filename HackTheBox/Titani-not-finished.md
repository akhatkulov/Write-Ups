# Titanic

Room: https://app.hackthebox.com/machines/Titanic



## Ishni boshlashdan oldin.

```
echo "10.10.11.55 titanic.htb" > /etc/hosts
```



## Razvetka

Port Scanning:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.11.55 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
To scan or not to scan? That is the question.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.55:22
Open 10.10.11.55:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.11.55
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-15 16:51 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 16:51
Scanning 10.10.11.55 [2 ports]
Completed Ping Scan at 16:51, 0.09s elapsed (1 total hosts)
Initiating Connect Scan at 16:51
Scanning titanic.htb (10.10.11.55) [2 ports]
Discovered open port 22/tcp on 10.10.11.55
Discovered open port 80/tcp on 10.10.11.55
Completed Connect Scan at 16:51, 0.09s elapsed (2 total ports)
Initiating Service scan at 16:51
Scanning 2 services on titanic.htb (10.10.11.55)
Completed Service scan at 16:51, 6.19s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.55.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.42s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.37s elapsed
Nmap scan report for titanic.htb (10.10.11.55)
Host is up, received syn-ack (0.089s latency).
Scanned at 2025-06-15 16:51:14 +05 for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.52
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.31 seconds
```

Subdomenlar:

```

╭─mete   󰉖 ~
╰─ ❯❯ ffuf -u 'http://titanic.htb' -w /usr/share/payloads/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.titanic.htb' -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb
 :: Wordlist         : FUZZ: /usr/share/payloads/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 244ms
```



Routinglar:

```
mete@sec ~> gobuster dir -u http://titanic.htb/ -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://titanic.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 400) [Size: 41]
/book                 (Status: 405) [Size: 153]
```

```
mete@sec ~> gobuster dir -u http://dev.titanic.htb/ -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.titanic.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 303) [Size: 38] [--> /user/login]
/issues               (Status: 303) [Size: 38] [--> /user/login]
/test                 (Status: 200) [Size: 19844]
/developer            (Status: 200) [Size: 25150]
/v2                   (Status: 401) [Size: 50]
/explore              (Status: 303) [Size: 41] [--> /explore/repos]
/administrator        (Status: 200) [Size: 19996]
/milestones           (Status: 303) [Size: 38] [--> /user/login]
/Test                 (Status: 200) [Size: 19843]
```

/download routinggi ticket parametrini talab qiladi va shu bilan birgalikda bu routingda LFI zaifligi bor.

So'rov:

```
http://titanic.htb/download?ticket=/etc/passwd
```

Bu fayl orqali biz 3 foydaluvchi tizimda bor ekanini angladik.

- root
- www-data
- developer

