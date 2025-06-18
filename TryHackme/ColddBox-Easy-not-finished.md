# ColddBox: Easy

Room: https://tryhackme.com/room/colddboxeasy

## Razvetka

```

╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.177.241 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
With RustScan, I scan ports so fast, even my firewall gets whiplash 💨

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.177.241:80
Open 10.10.177.241:4512
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.177.241
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-16 01:30 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 01:30
Scanning 10.10.177.241 [2 ports]
Completed Ping Scan at 01:30, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:30
Completed Parallel DNS resolution of 1 host. at 01:30, 4.00s elapsed
DNS resolution of 1 IPs took 4.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 2, CN: 0]
Initiating Connect Scan at 01:30
Scanning 10.10.177.241 [2 ports]
Discovered open port 80/tcp on 10.10.177.241
Discovered open port 4512/tcp on 10.10.177.241
Completed Connect Scan at 01:30, 0.20s elapsed (2 total ports)
Initiating Service scan at 01:30
Scanning 2 services on 10.10.177.241
Completed Service scan at 01:30, 6.67s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.177.241.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 01:30
Completed NSE at 01:30, 0.93s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 01:30
Completed NSE at 01:30, 0.85s elapsed
Nmap scan report for 10.10.177.241
Host is up, received syn-ack (0.22s latency).
Scanned at 2025-06-16 01:30:24 +05 for 8s

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
4512/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.98 seconds
```

80 portda nima ishlayapti?

```
╭─mete   󰉖 ~
╰─ ❯❯ whatweb http://10.10.177.241/
http://10.10.177.241/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.177.241], JQuery[1.11.1], MetaGenerator[WordPress 4.1.31], PoweredBy[WordPress,WordPress,], Script[text/javascript], Title[ColddBox | One more machine], WordPress[4.1.31], x-pingback[/xmlrpc.php]
```

Routinglar:

