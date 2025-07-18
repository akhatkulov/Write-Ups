# Binex

Room: https://tryhackme.com/room/binex

## Razvetka

### PortScanning

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.229.78 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.229.78:22
Open 10.10.229.78:139
Open 10.10.229.78:445
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.229.78
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-25 18:33 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 18:33
Scanning 10.10.229.78 [2 ports]
Completed Ping Scan at 18:33, 0.32s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:33
Completed Parallel DNS resolution of 1 host. at 18:33, 0.08s elapsed
DNS resolution of 1 IPs took 0.08s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:33
Scanning 10.10.229.78 [3 ports]
Discovered open port 22/tcp on 10.10.229.78
Discovered open port 445/tcp on 10.10.229.78
Discovered open port 139/tcp on 10.10.229.78
Completed Connect Scan at 18:33, 0.28s elapsed (3 total ports)
Initiating Service scan at 18:33
Scanning 3 services on 10.10.229.78
Completed Service scan at 18:33, 11.62s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.229.78.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:33
Completed NSE at 18:33, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:33
Completed NSE at 18:33, 0.00s elapsed
Nmap scan report for 10.10.229.78
Host is up, received conn-refused (0.30s latency).
Scanned at 2025-06-25 18:33:36 +05 for 12s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: THM_EXPLOIT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
```

Samba:

```

╭─mete   󰉖 ~
╰─ ❯❯ smbclient -L //10.10.229.78 -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (THM_exploit server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Enum4linux

```

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\kel (Local User)
S-1-22-1-1001 Unix User\des (Local User)
S-1-22-1-1002 Unix User\tryhackme (Local User)
S-1-22-1-1003 Unix User\noentry (Local User)
```

