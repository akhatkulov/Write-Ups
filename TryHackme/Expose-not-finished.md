# Expose

Room: https://tryhackme.com/room/expose

## Razvetka

### Port scanning:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.255.224 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports like it's my full-time job. Wait, it is.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.255.224:21
Open 10.10.255.224:22
Open 10.10.255.224:53
Open 10.10.255.224:1337
Open 10.10.255.224:1883
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.255.224
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 21:07 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 21:07
Scanning 10.10.255.224 [2 ports]
Completed Ping Scan at 21:07, 0.11s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:07
Completed Parallel DNS resolution of 1 host. at 21:07, 0.08s elapsed
DNS resolution of 1 IPs took 0.08s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 21:07
Scanning 10.10.255.224 [5 ports]
Discovered open port 22/tcp on 10.10.255.224
Discovered open port 21/tcp on 10.10.255.224
Discovered open port 53/tcp on 10.10.255.224
Discovered open port 1337/tcp on 10.10.255.224
Discovered open port 1883/tcp on 10.10.255.224
Completed Connect Scan at 21:07, 0.11s elapsed (5 total ports)
Initiating Service scan at 21:07
Scanning 5 services on 10.10.255.224
Completed Service scan at 21:07, 11.38s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.255.224.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:07
Completed NSE at 21:07, 7.54s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:07
Completed NSE at 21:07, 0.47s elapsed
Nmap scan report for 10.10.255.224
Host is up, received conn-refused (0.11s latency).
Scanned at 2025-07-07 21:07:32 +05 for 19s

PORT     STATE SERVICE                 REASON  VERSION
21/tcp   open  ftp                     syn-ack vsftpd 2.0.8 or later
22/tcp   open  ssh                     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain                  syn-ack ISC BIND 9.16.1 (Ubuntu Linux)
1337/tcp open  http                    syn-ack Apache httpd 2.4.41 ((Ubuntu))
1883/tcp open  mosquitto version 1.6.9 syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.82 seconds
```

